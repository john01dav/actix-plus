use actix_web::dev::HttpResponseBuilder;
use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use std::any::Any;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// This trait is automatically implemented for any type that implements both Error and Any, thus allowing that type to be propagated through ResponseError and ResponseResult as an internal server error.
pub trait DowncastableError: Error + Any {}
impl<T: ?Sized + Error + Any> DowncastableError for T {}

impl<T: DowncastableError + 'static> From<T> for ResponseError {
    fn from(err: T) -> Self {
        Self::InternalServerError(Box::new(err))
    }
}

/// Type alias of `Result<T, ResponseError>`, use this type to return from functions that are part of request handling but are not themselves requests (e.g. database functions)
pub type ResponseResult<T> = Result<T, ResponseError>;

/// Type alias of ResponseResult<HttpResponse> = Result<HttpResponse, ResponseError>, use this type to return from routes.
pub type Response = ResponseResult<HttpResponse>;

/// This type facilitates propagation of both internal server errors and status code errors. The former take place when something goes wrong in the backend that isn't due to user error but nonetheless prevents a normal response (e.g. error contacting the database, a file on the backend server was not found). The latter is when an error takes place in a function that corresponds to a particular response to the user, for example if a function is called to get a row from a database that does not exist a StatusCodeError variant may be emitted with a 404 Not Found, thus allowing the caller to simply propogate this error via ? to the route and thus to the user.
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

#[cfg(test)]
mod tests;
