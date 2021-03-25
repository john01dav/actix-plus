use actix_web::dev::HttpResponseBuilder;
use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use std::any::Any;
use std::error::Error;
use std::fmt::{Display, Formatter};

pub trait DowncastableError: Error + Any {}
impl<T: ?Sized + Error + Any> DowncastableError for T {}

pub type ResponseResult<T> = Result<T, ResponseError>;
pub type Response = ResponseResult<HttpResponse>;

#[derive(Debug)]
pub enum ResponseError {
    InternalServerError(Box<dyn DowncastableError>),
    StatusCodeError { code: StatusCode, message: String },
}

impl Display for ResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseError::InternalServerError(err) => write!(f, "InternalServerError: {}", err)?,
            ResponseError::StatusCodeError { code, message } => {
                write!(f, "HTTP {} {} ({})", code.as_u16(), code.as_str(), message)?
            }
        }
        Ok(())
    }
}

impl actix_web::ResponseError for ResponseError {
    fn status_code(&self) -> StatusCode {
        match self {
            ResponseError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ResponseError::StatusCodeError { code, .. } => *code,
        }
    }

    fn error_response(&self) -> HttpResponse {
        match self {
            ResponseError::InternalServerError(_) => {
                HttpResponse::InternalServerError().body("Internal Server Error")
            }
            ResponseError::StatusCodeError { code, message } => {
                HttpResponseBuilder::new(*code).body(message)
            }
        }
    }
}

impl<T: DowncastableError + 'static> From<T> for ResponseError {
    fn from(err: T) -> Self {
        Self::InternalServerError(Box::new(err))
    }
}

#[cfg(test)]
mod tests;
