#![feature(once_cell)]

use std::{
    convert::Infallible,
    env::{set_var, var},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use async_session::{chrono::Utc, Session, SessionStore};
use async_sqlx_session::SqliteSessionStore;
use auth::{MaybeUserIdFromSession, UserIdFromSession};
use axum::{
    body::Empty,
    error_handling::HandleErrorExt,
    extract::{Extension, Query, TypedHeader},
    http::{header, Response, StatusCode},
    response::IntoResponse,
    routing::{get, post, service_method_router as service},
    AddExtensionLayer, Json, Router,
};
use config::PUBLIC_KEY;
use dashmap::DashMap;
use headers::Cookie;
use jsonwebtoken::{encode, Algorithm, Header};
use log::LevelFilter;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Deserialize;
use serde_json::json;
use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, SqlitePool,
};
use tokio::{spawn, sync::mpsc::unbounded_channel};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{
    ao_bot::{CharacterQuery, Verifications},
    auth::{clean_up_intermittently, hash, verify, User},
    characters::Character,
    config::{CONFIG, PRIVATE_KEY},
    templates::{
        ChooseTemplate, HtmlTemplate, IndexTemplate, LoginTemplate, ManageTemplate, SignupTemplate,
    },
};

mod ao_bot;
mod auth;
mod characters;
mod config;
mod templates;

const SESSION_DURATION_SECONDS: i64 = 60 * 60 * 24 * 30;

#[tokio::main]
async fn main() {
    if var("RUST_LOG").is_err() {
        set_var("RUST_LOG", "INFO");
    }

    tracing_subscriber::fmt::init();

    // Initialize Sqlite DB
    let m = Migrator::new(Path::new("./migrations")).await.unwrap();

    let mut options = SqliteConnectOptions::new()
        .filename(&var("DATABASE_FILE").unwrap_or_else(|_| String::from("aoauth.db")));
    options.log_statements(LevelFilter::Debug);
    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .expect("Could not connect to sqlite db");

    m.run(&pool).await.expect("Migration failed");

    // Initialize session storage
    let store = SqliteSessionStore::from_client(pool.clone());
    store.migrate().await.unwrap();
    clean_up_intermittently(store.clone(), Duration::from_secs(60 * 60));

    // Initialize pending verifications
    let verifications: Verifications = Arc::new(DashMap::new());

    // Start the AO bot

    let (sender, receiver) = unbounded_channel();
    let queries = Arc::new(DashMap::new());
    spawn(ao_bot::run(
        receiver,
        verifications.clone(),
        pool.clone(),
        queries.clone(),
    ));
    let lookup = CharacterQuery {
        sender,
        pending: queries,
    };

    let app = Router::new()
        .layer(TraceLayer::new_for_http())
        .nest(
            "/assets",
            service::get(ServeDir::new("assets")).handle_error(|error: std::io::Error| {
                Ok::<_, Infallible>((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Unhandled internal error: {}", error),
                ))
            }),
        )
        .route("/", get(root))
        .route("/key", get(show_key))
        .route("/logout", get(logout))
        .route("/login", get(login_show).post(login))
        .route("/signup", get(create_account_show).post(create_account))
        .route("/delete-account", post(delete_account))
        .route("/manage", get(manage_account))
        .route("/auth", get(authorize_application))
        .route("/confirm-auth", get(finish_authorization))
        .route("/add-character", post(add_character))
        .route("/delete-character", post(delete_character))
        .layer(AddExtensionLayer::new(pool))
        .layer(AddExtensionLayer::new(store))
        .layer(AddExtensionLayer::new(verifications))
        .layer(AddExtensionLayer::new(lookup));

    let addr = SocketAddr::from(([0, 0, 0, 0], 4114));

    tracing::info!("Listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root(maybe_user_id: MaybeUserIdFromSession) -> impl IntoResponse {
    let template = IndexTemplate {
        logged_in: maybe_user_id.0.is_some(),
        public_key: PUBLIC_KEY.to_string(),
    };
    HtmlTemplate(template)
}

async fn show_key() -> impl IntoResponse {
    PUBLIC_KEY.to_string()
}

async fn manage_account(
    Extension(pool): Extension<SqlitePool>,
    user_id: UserIdFromSession,
) -> impl IntoResponse {
    let characters = sqlx::query_as!(
        Character,
        r#"SELECT * FROM characters WHERE "user_id"=?;"#,
        user_id.0
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let template = ManageTemplate {
        logged_in: true,
        bot_character: CONFIG.bot_character.to_string(),
        characters,
    };
    HtmlTemplate(template)
}

#[derive(Deserialize)]
struct AuthorizeParameters {
    redirect_uri: String,
    application_name: String,
}

async fn authorize_application(
    Extension(pool): Extension<SqlitePool>,
    user_id: UserIdFromSession,
    Query(parameters): Query<AuthorizeParameters>,
) -> impl IntoResponse {
    let characters = sqlx::query_as!(
        Character,
        r#"SELECT * FROM characters WHERE "user_id"=?;"#,
        user_id.0
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let template = ChooseTemplate {
        logged_in: true,
        characters,
        application_name: parameters.application_name,
        redirect_uri: parameters.redirect_uri,
    };
    HtmlTemplate(template)
}

#[derive(Deserialize)]
struct FinishAuthorizeParameters {
    redirect_uri: String,
    character: String,
}

async fn finish_authorization(
    Extension(pool): Extension<SqlitePool>,
    Extension(query): Extension<CharacterQuery>,
    user_id: UserIdFromSession,
    Query(parameters): Query<FinishAuthorizeParameters>,
) -> impl IntoResponse {
    let character_id = query.lookup(parameters.character.clone()).await;

    if let Some(character_id) = character_id {
        let character = sqlx::query_as!(
            Character,
            r#"SELECT * FROM characters WHERE "user_id"=? AND "name"=?;"#,
            user_id.0,
            parameters.character,
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        if let Some(character) = character {
            if character.id == i64::from(character_id) {
                let expiry = Utc::now().timestamp() + SESSION_DURATION_SECONDS; // 30 days
                let claims =
                    json!({"sub": {"name": character.name, "id": character.id}, "exp": expiry});
                let encrypted =
                    encode(&Header::new(Algorithm::ES256), &claims, &PRIVATE_KEY).unwrap();
                Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header(
                        "Location",
                        format!("{}?_aoauth_token={}", parameters.redirect_uri, encrypted),
                    )
                    .body(Empty::new())
                    .unwrap()
            } else {
                sqlx::query!(
                    r#"DELETE FROM characters WHERE "user_id"=? AND "name"=?;"#,
                    user_id.0,
                    parameters.character,
                )
                .execute(&pool)
                .await
                .unwrap();

                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Empty::new())
                    .unwrap()
            }
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Empty::new())
                .unwrap()
        }
    } else {
        sqlx::query!(
            r#"DELETE FROM characters WHERE "user_id"=? AND "name"=?;"#,
            user_id.0,
            parameters.character,
        )
        .execute(&pool)
        .await
        .unwrap();

        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Empty::new())
            .unwrap()
    }
}

async fn add_character(
    Extension(verifications): Extension<Verifications>,
    user_id: UserIdFromSession,
) -> impl IntoResponse {
    let mut rng = thread_rng();
    let verification_prompt: String = std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(10)
        .collect();
    verifications.insert(verification_prompt.clone(), user_id.0);

    let verification_prompt_copy = verification_prompt.clone();
    tokio::task::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60 * 10)).await;
        verifications.remove(&verification_prompt_copy);
    });

    verification_prompt
}

#[derive(Deserialize, Debug)]
struct DeleteCharacterJson {
    id: u32,
}

async fn delete_character(
    user_id: UserIdFromSession,
    Extension(pool): Extension<SqlitePool>,
    Json(character): Json<DeleteCharacterJson>,
) -> impl IntoResponse {
    sqlx::query!(
        r#"DELETE FROM characters WHERE "user_id"=? AND "id"=?;"#,
        user_id.0,
        character.id
    )
    .execute(&pool)
    .await
    .unwrap();
}

#[derive(Deserialize)]
struct LoginParameters {
    #[serde(default)]
    redirect_uri: Option<String>,
}

async fn login_show(
    maybe_user_id: MaybeUserIdFromSession,
    Query(parameters): Query<LoginParameters>,
) -> impl IntoResponse {
    let template = LoginTemplate {
        logged_in: maybe_user_id.0.is_some(),
        redirect_uri: parameters.redirect_uri.unwrap_or_else(|| String::from("/")),
    };
    HtmlTemplate(template)
}

async fn create_account_show(maybe_user_id: MaybeUserIdFromSession) -> impl IntoResponse {
    let template = SignupTemplate {
        logged_in: maybe_user_id.0.is_some(),
    };
    HtmlTemplate(template)
}

#[derive(Deserialize, Debug)]
struct LoginCredentials {
    username: String,
    password: String,
}

async fn delete_account(
    user_id: UserIdFromSession,
    Extension(store): Extension<SqliteSessionStore>,
    Extension(pool): Extension<SqlitePool>,
    TypedHeader(cookies): TypedHeader<Cookie>,
) -> impl IntoResponse {
    sqlx::query!(r#"DELETE FROM users WHERE "id"=?;"#, user_id.0,)
        .execute(&pool)
        .await
        .unwrap();

    if let Some(cookie) = cookies.get("session") {
        if let Some(session) = store.load_session(cookie.to_string()).await.unwrap() {
            store.destroy_session(session).await.unwrap();
        }
    }
}

async fn create_account(
    Extension(store): Extension<SqliteSessionStore>,
    Extension(pool): Extension<SqlitePool>,
    Json(input): Json<LoginCredentials>,
) -> impl IntoResponse {
    let hash = hash(&input.password);

    if sqlx::query!(
        r#"INSERT INTO users("name", "password") VALUES (?, ?);"#,
        input.username,
        hash
    )
    .execute(&pool)
    .await
    .is_err()
    {
        return Response::builder()
            .status(StatusCode::CONFLICT)
            .body(Empty::new())
            .unwrap();
    };

    let user = sqlx::query_as!(
        User,
        r#"SELECT * FROM users WHERE "name"=?;"#,
        input.username,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let mut session = Session::new();
    session.insert("user_id", user.id).unwrap();
    let cookie = store.store_session(session).await.unwrap().unwrap();
    let cookie_string = format!("session={}; Max-Age=900; Secure", cookie,);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie_string)
        .body(Empty::new())
        .unwrap()
}

async fn logout(
    Extension(store): Extension<SqliteSessionStore>,
    TypedHeader(cookies): TypedHeader<Cookie>,
) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("session") {
        if let Some(session) = store.load_session(cookie.to_string()).await.unwrap() {
            store.destroy_session(session).await.unwrap();
        }
    }

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/")
        .body(Empty::new())
        .unwrap()
}

async fn login(
    Extension(pool): Extension<SqlitePool>,
    Extension(store): Extension<SqliteSessionStore>,
    Json(input): Json<LoginCredentials>,
) -> impl IntoResponse {
    let user = sqlx::query_as!(
        User,
        r#"SELECT * FROM users WHERE "name"=?;"#,
        input.username,
    )
    .fetch_optional(&pool)
    .await
    .unwrap();

    if let Some(user) = user {
        let is_valid = verify(&user.password, &input.password);

        if is_valid {
            let mut session = Session::new();
            session.insert("user_id", user.id).unwrap();
            let cookie = store.store_session(session).await.unwrap().unwrap();
            let cookie_string =
                format!("session={}; Max-Age={};", cookie, SESSION_DURATION_SECONDS);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::SET_COOKIE, cookie_string)
                .body(Empty::new())
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Empty::new())
                .unwrap()
        }
    } else {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Empty::new())
            .unwrap()
    }
}
