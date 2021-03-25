use crate::Response;
use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
struct TestError;
impl Display for TestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestError")?;
        Ok(())
    }
}
impl Error for TestError {}

#[test]
fn test_wrap_error() {
    fn test_error(should_error: bool) -> Response {
        if should_error {
            Err(TestError)?;
        }
        Ok(HttpResponse::new(StatusCode::OK))
    }

    match test_error(false) {
        Ok(_) => {}
        Err(_err) => panic!("Found error type in response where none should exist."),
    }

    match test_error(true) {
        Ok(_) => panic!("Found Ok type when Err was expected."),
        Err(_) => {}
    }
}
