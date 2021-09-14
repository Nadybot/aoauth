use std::convert::Infallible;

use askama::Template;
use axum::{
    body::{Bytes, Full},
    http::{Response, StatusCode},
    response::{Html, IntoResponse},
};

use crate::characters::Character;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub logged_in: bool,
    pub public_key: String,
}

#[derive(Template)]
#[template(path = "login.html", escape = "none")]
pub struct LoginTemplate {
    pub logged_in: bool,
    pub redirect_uri: String,
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupTemplate {
    pub logged_in: bool,
}

#[derive(Template)]
#[template(path = "manage.html")]
pub struct ManageTemplate {
    pub logged_in: bool,
    pub bot_character: String,
    pub characters: Vec<Character>,
}

#[derive(Template)]
#[template(path = "choose.html", escape = "none")]
pub struct ChooseTemplate {
    pub logged_in: bool,
    pub application_name: String,
    pub redirect_uri: String,
    pub characters: Vec<Character>,
}

pub struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    type Body = Full<Bytes>;
    type BodyError = Infallible;

    fn into_response(self) -> Response<Self::Body> {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from(format!(
                    "Failed to render template. Error: {}",
                    err
                )))
                .unwrap(),
        }
    }
}
