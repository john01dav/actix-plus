# Overview
This crate provides an ergonomic, convenient, and universal way to handle errors in an actix-web application. All errors can be divided into three categories: internal server errors, errors that result in some HTTP error being given to the user (e.g. sending an invalid string as one's email), and errors that aren't really errors at all (e.g. sending an incorrect password with the email when logging in — nothing has really gone wrong as this is an expected course of events). The first and second categories are represented in a custom error type defined roughly as follows (modified from the actual library code to more clearly make the point):
```rust
pub enum ResponseError{
    InternalServerError(Box<dyn Error + Any>),
    StatusCodeError { code: actix_web::http::StatusCode, message: String },
}
```
This error type is able to propagate any Error-implementing type via the ? operator, thus allowing one to conveniently and cleanly handle internal server errors, and is able to use the same operator to propagate StatusCodeError variant instances between functions, thus allowing such errors to be cleanly propagated. For example, if a route to view a forum thread calls another function to fetch that thread from the database, but a thread that does not exist is requested, that database function can simply return a ResponseError that encodes a 404 Not Found Request, which is then propagated back to Actix via the ? operator, potentially through a long chain of calls. This allows the user to only need to write code that directly deals with the standard case, and other cases are implicitly, cleanly, and clearly handled thus reducing development time.

The third category is recommended to be handled by a 200 OK response with JSON (or similar) that specifies the result.

# What about when I need to handle errors directly?
Of course, this opinionated way of handling errors isn't always going to work — sometimes one wants to do something special when, for example, a database function can't find the requested item (e.g. call another database function). With actix-plus-error, this is still feasible as one can match on the error (and even the status code) like any other:
```rust
async fn fetch_something(uuid: Uuid) -> ResponseResult<Something>{
    match fetch_something_from_db(uuid).await {
        Ok(something) => Ok(something),
        Err(ResponseError::StatusCodeError { code: StatusCode::NOT_FOUND, .. }) => { // a 403 forbidden status code, for example, is propagated
            //return a default Something
            Ok(Something::default())
        },
        Err(other_error) => Err(other_error) //propagate other errors (e.g. internal server errors, other status codes)
    }
}
```
It is also possible to use the `Any` trait to downcast errors wrapped in the InternalServerError variant.