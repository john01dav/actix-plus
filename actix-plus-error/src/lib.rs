//! # Overview
//! This crate provides an ergonomic, convenient, and universal way to handle errors in an actix-web application. All errors can be divided into three categories: internal server errors, errors that result in some HTTP error being given to the user (e.g. sending an invalid string as one's email), and errors that aren't really errors at all (e.g. sending an incorrect password with the email when logging in — nothing has really gone wrong as this is an expected course of events). The first and second categories are represented in a custom error type defined roughly as follows (modified from the actual library code to more clearly make the point):
//! ```rust,ignore
//! pub enum ResponseError{
//!     InternalServerError(Box<dyn Error + Any>),
//!     StatusCodeError { code: actix_web::http::StatusCode, message: String },
//! }
//! ```
//! This error type is able to propagate any Error-implementing type via the ? operator, thus allowing one to conveniently and cleanly handle internal server errors, and is able to use the same operator to propagate StatusCodeError variant instances between functions, thus allowing such errors to be cleanly propagated. For example, if a route to view a forum thread calls another function to fetch that thread from the database, but a thread that does not exist is requested, that database function can simply return a ResponseError that encodes a 404 Not Found Request, which is then propagated back to Actix via the ? operator, potentially through a long chain of calls. This allows the user to only need to write code that directly deals with the standard case, and other cases are implicitly, cleanly, and clearly handled thus reducing development time.
//!
//! The third category is recommended to be handled by a 200 OK response with JSON (or similar) that specifies the result.
//!
//! # What about when I need to handle errors directly?
//! Of course, this opinionated way of handling errors isn't always going to work — sometimes one wants to do something special when, for example, a database function can't find the requested item (e.g. call another database function). With actix-plus-error, this is still feasible as one can match on the error (and even the status code) like any other:
//! ```rust,ignore
//! async fn fetch_something(uuid: Uuid) -> ResponseResult<Something>{
//!     match fetch_something_from_db(uuid).await {
//!         Ok(something) => Ok(something),
//!         Err(ResponseError::StatusCodeError { code: StatusCode::NOT_FOUND, .. }) => { // a 403 forbidden status code, for example, is propagated
//!             //return a default Something
//!             Ok(Something::default())
//!         },
//!         Err(other_error) => Err(other_error) //propagate other errors (e.g. internal server errors, other status codes)
//!     }
//! }
//! ```
//! It is also possible to use the `Any` trait to downcast errors wrapped in the InternalServerError variant.
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
