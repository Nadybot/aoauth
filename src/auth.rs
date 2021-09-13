use std::time::Duration;

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_session::SessionStore;
use async_sqlx_session::SqliteSessionStore;
use axum::{
    async_trait,
    body::{Bytes, Empty},
    extract::{Extension, FromRequest, RequestParts, TypedHeader},
    http::{Response, StatusCode},
};
use rand_core::OsRng;
use serde_urlencoded::to_string;

pub fn hash(password: &str) -> String {
    let hasher = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    hasher
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn verify(hash: &str, password: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();
    let hasher = Argon2::default();
    hasher
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn clean_up_intermittently(store: SqliteSessionStore, period: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            if let Err(error) = store.cleanup().await {
                tracing::error!("Cleanup error: {}", error);
            }
        }
    });
}

#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub password: String,
}

pub struct UserIdFromSession(pub i64);

pub struct MaybeUserIdFromSession(pub Option<i64>);

#[async_trait]
impl<B> FromRequest<B> for UserIdFromSession
where
    B: Send,
{
    type Rejection = Response<Empty<Bytes>>;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<SqliteSessionStore>::from_request(req)
            .await
            .unwrap();

        let cookies: TypedHeader<headers::Cookie> =
            if let Ok(cookies) = TypedHeader::from_request(req).await {
                cookies
            } else {
                return Err(Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header(
                        "Location",
                        format!(
                            "/login?{}",
                            to_string(&[("redirect_uri", req.uri().to_string())]).unwrap()
                        ),
                    )
                    .body(Empty::new())
                    .unwrap());
            };

        let cookie = if let Some(cookie) = cookies.get("session") {
            cookie.to_string()
        } else {
            return Err(Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(
                    "Location",
                    format!(
                        "/login?{}",
                        to_string(&[("redirect_uri", req.uri().to_string())]).unwrap()
                    ),
                )
                .body(Empty::new())
                .unwrap());
        };

        let user_id = if let Some(session) = store.load_session(cookie).await.unwrap() {
            if let Some(user_id) = session.get::<i64>("user_id") {
                user_id
            } else {
                return Err(Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header(
                        "Location",
                        format!(
                            "/login?{}",
                            to_string(&[("redirect_uri", req.uri().to_string())]).unwrap()
                        ),
                    )
                    .body(Empty::new())
                    .unwrap());
            }
        } else {
            return Err(Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(
                    "Location",
                    format!(
                        "/login?{}",
                        to_string(&[("redirect_uri", req.uri().to_string())]).unwrap()
                    ),
                )
                .body(Empty::new())
                .unwrap());
        };

        Ok(Self(user_id))
    }
}

#[async_trait]
impl<B> FromRequest<B> for MaybeUserIdFromSession
where
    B: Send,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<SqliteSessionStore>::from_request(req)
            .await
            .unwrap();

        let cookies: TypedHeader<headers::Cookie> =
            if let Ok(cookies) = TypedHeader::from_request(req).await {
                cookies
            } else {
                return Ok(Self(None));
            };

        let cookie = if let Some(cookie) = cookies.get("session") {
            cookie.to_string()
        } else {
            return Ok(Self(None));
        };

        let user_id = if let Some(session) = store.load_session(cookie).await.unwrap() {
            if let Some(user_id) = session.get::<i64>("user_id") {
                user_id
            } else {
                return Ok(Self(None));
            }
        } else {
            return Ok(Self(None));
        };

        Ok(Self(Some(user_id)))
    }
}
