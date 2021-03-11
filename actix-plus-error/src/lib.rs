use std::error::Error;
use std::fmt::{Display, Formatter};
use actix_web::HttpResponse;
use actix_web::web::BytesMut;
use actix_web::http::StatusCode;
use actix_web::body::Body;
use actix_web::dev::HttpResponseBuilder;

pub type ResponseResult<T> = Result<T, ResponseError>;
pub type Response = ResponseResult<HttpResponse>;

#[derive(Debug)]
pub enum ResponseError {
    InternalServerError(Box<dyn Error>),
    StatusCodeError{code: StatusCode, message: String}
}

impl Display for ResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), ()> {
        match self{
            ResponseError::InternalServerError(err) => {
                write!(f, "InternalServerError: {}", err)
            },
            ResponseError::StatusCodeError {code, message} => {
                write!("HTTP {} {}", code, message)
            }
        }
        Ok(())
    }
}

impl Error for ResponseError {}

impl actix_web::ResponseError for ResponseError {

    fn status_code(&self) -> StatusCode {
        match self{
            ResponseError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ResponseError::StatusCodeError {code, ..} => code
        }
    }

    fn error_response(&self) -> HttpResponse {
        match self{
            ResponseError::InternalServerError(_) => HttpResponse::InternalServerError().body("Internal Server Error"),
            ResponseError::StatusCodeError {code, message} => HttpResponseBuilder::new(*code).body(message)
        }
    }

}

impl<T: Error + 'static> From<T> for ResponseError {
    fn from(err: T) -> Self {
        Self::InternalServerError(Box::new(err))
    }
}

