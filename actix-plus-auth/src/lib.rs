//! Overview
//! ========
//! One way to design a web backend is to split it into three parts: the API layer (for reusable actions used in the presentation layer), data layer (for interacting with the database), and presentation layer (for handling requests). This crate aims to provide the API layer for authentication. Example routes are provided in the examples folder, so you can get the presentation layer as well, although you are almost certainly going to want to make some changes so it is not included in the crate by default.
//!
//! Features
//! ========
//!  - Easy: Makes it easy to add authentication to your web application by providing structure and doing the hard parts for you
//!  - Flexible: not opinionated on what your URL structure, UI, or database looks like
//!  - Fast: fully async, and does not require a database query unless logging in or registering (e.g. normal authenticated requests verify without a database query)
//!  - Stateless: no need for server pinning with this library, only cryptography is used to verify sessions, so it's fine if a user sporadically switches backend servers
//!
//! Usage
//! =====
//! Roughly speaking, there are three steps in using this library: create the data layer, integrate with Actix-Web, make the routes, and make the frontend. You can view a complete example [here](https://github.com/john01dav/actix-plus/blob/master/actix-plus-auth/examples/basic_use_in_memory_db.rs).
//!
//! Create the Data Layer
//! ---------------------
//! To create a data layer, you must create a Rust struct to hold the information that you want to associate with each user, except the password hash which is stored separately. You must store the email in this struct. An example struct follows:
//! ```rust,ignore
//! // !!!!!WARNING: anything in your account type is visible to users as it is encoded as a JWT!!!!!
//! #[derive(Serialize, Deserialize, Debug)]
//! pub struct ExampleAccount {
//!     pub username: String, //example of custom data to include with one's account type
//!     pub email: String,
//! }
//!
//! impl Account for ExampleAccount {
//!     fn email(&self) -> &str {
//!         &self.email
//!     }
//! }
//! ```
//! As you can see, after the struct is created, the `Account` trait is implemented to allow actix-plus-auth to access the email, and to signal that this struct represents an account. The `Account` trait, due to [JWT](https://jwt.io/) (Json Web Token) serialization and deserialization, requires that the serde `Serialize` and `DeserializeOwned` traits are implemented. To implement `DeserializeOwned` simply have a struct that owns all of its types (e.g. no reference members) and then derive `Deserialize`. Additionally, the `Account` trait requires the `Debug` trait. Of course, you can implement other traits as you see fit.
//!
//! **Note that anything in your account type is visible to users as it is encoded as a JWT for session storage. DO NOT PUT PRIVATE INFORMATION IN THE ACCOUNT TYPE.**
//!
//! Once the account struct is created, a data provider struct is needed. A data provider struct implements the operations that fetch and store this account type from a database. To create a data provider struct, simply implement the `DataProvider` trait:
//! ```rust,ignore
//! #[async_trait]
//! pub trait DataProvider: Clone {
//!     type AccountType: Account;
//!
//!     ///Adds a new account to the database, then returns that account back. You may need to clone the account when implementing this function. If another account exists with this email, then the function should return some sort of error.
//!     async fn insert_account(
//!         &self,
//!         account: Self::AccountType,
//!         password_hash: String,
//!     ) -> ResponseResult<Self::AccountType>;
//!
//!     /// Fetches the account with the given email from the database, case-insensitively. Note that a lowercase email should be passed to this function, but the matching email as stored in the database may be in any case.
//!     async fn fetch_account(
//!         &self,
//!         email: &str,
//!     ) -> ResponseResult<Option<(Self::AccountType, String)>>;
//! }
//! ```
//! Note that the [async_trait](https://crates.io/crates/async-trait) crate is used to facilitate async functions in this trait, and you must use it when implementing this trait as well. Also, note that the `insert_account` and `fetch_account` functions take `&self` and not `&mut self`, and that `DataProvider` requires `Clone`. The model in this library is that a single data store is shared across many instances of your data provider, and references to those instances, like a normal database connection pool (e.g. as in [sqlx](https://crates.io/crates/sqlx)). When your data provider is cloned, make sure to internally reference the same data such that if a change is made on the clone it can be read back from the original (or other clones) and visa-versa. The best way to implement this is to use a database library (such as [sqlx](https://crates.io/crates/sqlx)) that already works in this way.
//!
//! Congratulations! You have now created the data layer, which is 95% of the work to use this library.
//!
//! An example data provider is not shown here as it will vary wildly between different database backends.
//!
//! Integrate with Actix-Web
//! ------------------------
//! Once your data layer is created, you can move on to integrating with Actix Web. To do this, create an instance of `actix_plus_auth::AuthenticationProvider<T: DataProvider>` via the `new` function. To do this, you'll need a secret and an instance of your data provider:
//! ```rust,ignore
//! let auth = AuthenticationProvider::new(
//!     MyDataProvider::new(),
//!     "some secret, you should use a real one"
//!         .as_bytes()
//!         .iter()
//!         .map(|u| *u)
//!         .collect(),
//! );
//! ```
//! The secret is used to verify JWTs, so it should be both secret (if it is leaked then users can forge a JWT for any account on your service) and unchanging (if it changes, existing sessions will be invalidated). If it is leaked, you should change it, and review your logs for any possible abuse. `AuthenticationProvider` is generic over a provided `DataProvider`-implementing struct, and it will infer the account type from your `DataProvider` implementation, also generically.
//!
//! Once you have an `AuthenticationProvider`, you simply need to make it available to each route. This is done via [Actix Web's state system](https://actix.rs/docs/application/#state):
//! ```rust,ignore
//! HttpServer::new(move || { //move your auth variable into the closure
//!     App::new()
//!         .data(auth.clone()) //clone the closure's copy for each Actix Web worker, this is why clones of a data provider must refer to the same data even when cloned
//! })
//! ```
//!
//! Lastly, as this system relies on cookies with the secure flag set, you must enable TLS/HTTPS for it to work. A simple self-signed certificate is sufficient for development. Refer to [Actix Web documentation](https://actix.rs/docs/http2/) for details on enabling TLS.
//!
//! Make the Routes
//! ---------------
//! Once an `AuthenticationProvider` is registered with Actix Web, routes for login, registration, and logout must be created. `AuthenticationProvider` provides functions that facilitate most of the heavy lifting for these operations, except for logout which is to be implemented entirely by the user.
//!
//! ### Register
//! ```rust,ignore
//! pub async fn register(
//!     &self,
//!     account: DataProviderImpl::AccountType,
//!     password: &str,
//! ) -> ResponseResult<RegistrationOutcome<DataProviderImpl::AccountType>>
//! ```
//! Above is the signature of the registration function. To put it simply, it accepts a reference to the authentication provider, the password to register with, and an instance of your account type. It then returns a `ResponseResult` (from the actix-plus-error crate, used to propagate internal server errors such as those from the user-provided data layer) with a `RegistrationOutcome` instance which has three variants:
//! ```rust,ignore
//! ///The non-error outcomes of registration. Error outcomes are used when a genuine error takes place — e.g. the database is not reachable (represented by the functions on your DataProvider implementation returning an error).
//! pub enum RegistrationOutcome<AccountType: Account> {
//!     ///The account is now in the database, and is given here.
//!     Successful(AccountType),
//!     ///The provided email is not a valid email
//!     InvalidEmail,
//!     //The provided email is already taken
//!     EmailTaken,
//! }
//! ```
//!
//! ### Login
//! ```rust,ignore
//! pub async fn login(
//!     &self,
//!     email: &str,
//!     password: &str,
//! ) -> ResponseResult<LoginOutcome<DataProviderImpl::AccountType>>
//! ```
//! Above is the signature of the login function. To put it simply, it accepts a reference to to the authentication provider, an email, and a username (as provided by the user) and returns a `ResponseResult` (from the actix-plus-error crate, used to propagate internal server errors such as those from the user-provided data layer) with a `LoginOutcome` instance which has two variants:
//! ```rust,ignore
//! ///The non-error outcomes of logging in. Error outcomes are used when a genuine error takes place — e.g. the database is not reachable (represented by the functions on your DataProvider implementation returning an error).
//! pub enum LoginOutcome<AccountType> {
//!     ///The credentials were correct, so the account  and a cookie that should be set in the response to the login route are provided.
//!     Successful(AccountType, Cookie<'static>),
//!     //The provided credentials do not correspond to a valid account.
//!     InvalidEmailOrPassword,
//! }
//! ```
//! If `InvalidEmailOrPassword` is returned then this information should be passed in your response in whatever way you see fit. If `Successful` is returned, then the provided cookie should be set on your HTTP response. Additionally, in the successful scenario, you may set additional cookies to share data with your frontend. Note that, following best practices for cookie-based token storage, the token cookie is HTTP only, so Javascript code can't access it. See [here](https://github.com/john01dav/actix-plus/blob/master/actix-plus-auth/examples/basic_use_in_memory_db.rs) for an example.
//!
//! ### Logout
//! To logout, simply delete the `actix-plus-auth-token` cookie, along with any other cookies that you may have set in your login. You do not need to call into the library to delete a session or anything, as the library is stateless:
//! ```rust,ignore
//! #[post("/logout")]
//! async fn logout(request: HttpRequest) -> Response {
//!     let mut response = HttpResponse::Ok();
//!     if let Some(mut session_cookie) = request.cookie("actix-plus-auth-token") { //you must delete this cookie
//!         session_cookie.set_path("/"); //this is needed to ensure that the cookie deletion goes through
//!         session_cookie.set_secure(true); //this is needed to ensure that the cookie deletion goes through
//!         response.del_cookie(&session_cookie);
//!     }
//!     if let Some(mut username_cookie) = request.cookie("username") { //delete optional user-added cookie
//!         username_cookie.set_path("/");
//!         username_cookie.set_secure(true);
//!         response.del_cookie(&username_cookie);
//!     }
//!     Ok(response.await?)
//! }
//! ```
//!
//! ### Authenticating in Other Routes
//! In another route, you can simply call `current_user(req: &HttpRequest)` on `AuthenticationProvider` to get the current user. This function returns `Err(ResponseError)` that encodes a 401 Not Authorized (via the actix-plus-error crate), so if you use the same crate you can simply propagate with `?` to keep code concise:
//! ```rust,ignore
//! #[get("/private_page")]
//! async fn private_page(request: HttpRequest, auth: Data<ExampleAuthProvider>) -> Response {
//!     let account = auth.current_user(&request)?;
//!     Ok(HttpResponse::Ok() //you can do anything here, including more traditional JSON/REST/etc. routes
//!         .body(format!("Hello {}", account.username))
//!         .await?)
//! }
//! ```
//!
//! Make the Frontend
//! -----------------
//! When making the frontend, there are some considerations to ensure that cookies are included with HTTP requests. Specifically, credentials should be set to 'same-origin' (both for requests to login, logout, and registration; and for general authenticated requests):
//! ```javascript
//! let response = await fetch('/login', {
//!     method: 'POST',
//!     credentials: 'same-origin',
//!     headers: {
//!        'Content-Type': 'application/json'
//!     },
//!     body: JSON.stringify({
//!         email: document.getElementById('email').value,
//!         password: document.getElementById('password').value,
//!     })
//! });
//! ```
//!
//! Todo
//! ====
//! - Email Verification
//! - SQLx example
use actix_plus_error::{ResponseError, ResponseResult};
use actix_plus_utils::current_unix_time_secs;
use actix_web::cookie::{Cookie, CookieBuilder, SameSite};
use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
pub use async_trait::async_trait;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

///A struct that implements this trait represents the data that is stored with each account in the authentication system. The only mandatory data to st ore in an account is the email that the account is associated with. The password should not be stored here. Your account object's data and the password, taken together, are usually one row in a SQL database (although other database types can be used as this library does not interact with the database), where the email is the primary key.
///**Note that this data is viewable to the user as it is stored in an unencrypted (but signed) json web token!**
pub trait Account: Serialize + DeserializeOwned + Debug + 'static {
    ///Gets the email associated with this account.
    fn email(&self) -> &str;
}

///A struct that implements this trait provides the functions that Actix+Auth needs to interact with your database (or flatfile, volatile storage in ram, whatever you want) to implement authentication. Although it is not strictly required to work at small scale, it is **strongly** recommended that the email of each account be able to be looked up quickly in a case-insensitive manner. With a SQL database, this can be accomplished by adding an index on the lowercase of the email. The email is also the primary key.
///**Note that when this struct is cloned it should refer to the same datastore. This struct is cloned like a database pool is in normal Actix.**
#[async_trait]
pub trait DataProvider: Clone {
    type AccountType: Account;

    ///Adds a new account to the database, then returns that account back. You may need to clone the account when implementing this function. If another account exists with this email, then the function should return some sort of error.
    async fn insert_account(
        &self,
        account: Self::AccountType,
        password_hash: String,
    ) -> ResponseResult<Self::AccountType>;

    /// Fetches the account with the given email from the database, case-insensitively. Note that a lowercase email should be passed to this function, but the matching email as stored in the database may be in any case.
    async fn fetch_account(
        &self,
        email: &str,
    ) -> ResponseResult<Option<(Self::AccountType, String)>>;
}

///The non-error outcomes of registration. Error outcomes are used when a genuine error takes place — e.g. the database is not reachable (represented by the functions on your DataProvider implementation returning an error).
pub enum RegistrationOutcome<AccountType: Account> {
    ///The account is now in the database, and is given here.
    Successful(AccountType),
    ///The provided email is not a valid email
    InvalidEmail,
    //The provided email is already taken
    EmailTaken,
}

///The non-error outcomes of logging in. Error outcomes are used when a genuine error takes place — e.g. the database is not reachable (represented by the functions on your DataProvider implementation returning an error).
pub enum LoginOutcome<AccountType> {
    ///The credentials were correct, so the account  and a cookie that should be set in the response to the login route are provided.
    Successful(AccountType, Cookie<'static>),
    //The provided credentials do not correspond to a valid account.
    InvalidEmailOrPassword,
}

//from https://emailregex.com/
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r###"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"###,
    ).expect("Failed to parse email regex")
});

#[derive(Debug, Serialize, Deserialize)]
struct JsonWebTokenClaims<T> {
    exp: usize,
    account: T,
}

///A clone of this struct is provided to each App instance in Actix as Data, thus providing access to the authentication system in each route.
#[derive(Clone)]
pub struct AuthenticationProvider<DataProviderImpl: DataProvider> {
    provider: DataProviderImpl,
    jwt_encoding_key: EncodingKey,
    jwt_secret: Vec<u8>,
}

impl<DataProviderImpl: DataProvider> AuthenticationProvider<DataProviderImpl> {
    ///Creates a new AuthenticationProvider with the provided jwt_secret and data provider. The jwt secret is used to sign and verify the json web tokens, so it should be secret, long enough to be secure, and persistent over a period of days. Changing this token will invalidate all current sessions, but they may not be cleanly logged out if you set your own cookies in addition to the token.
    pub fn new(provider: DataProviderImpl, jwt_secret: Vec<u8>) -> Self {
        Self {
            provider,
            jwt_encoding_key: EncodingKey::from_secret(&jwt_secret),
            jwt_secret,
        }
    }

    ///Registers the provided account with the provided password. See the documentation on RegistrationOutcome for details on what to do next.
    /// ```rust,ignore
    /// #[post("/register")]
    /// async fn register(auth: Data<ExampleAuthProvider>, dto: Json<RegistrationDto>) -> Response {
    ///     let dto = dto.into_inner();
    ///     Ok(
    ///         match auth.register(
    ///             ExampleAccount {
    ///                 username: dto.username,
    ///                 email: dto.email,
    ///             },
    ///             &dto.password,
    ///         )? {
    ///             RegistrationOutcome::Successful(_account) => {
    ///                 HttpResponse::Ok()
    ///                     .json(RegistrationResponseDto {
    ///                         succeeded: true,
    ///                         message: None,
    ///                     })
    ///                     .await?
    ///             }
    ///             RegistrationOutcome::InvalidEmail => {
    ///                 HttpResponse::Ok()
    ///                     .json(RegistrationResponseDto {
    ///                         succeeded: false,
    ///                         message: Some("Invalid Email".into()),
    ///                     })
    ///                     .await?
    ///             }
    ///             RegistrationOutcome::EmailTaken => {
    ///                 HttpResponse::Ok()
    ///                     .json(RegistrationResponseDto {
    ///                         succeeded: false,
    ///                         message: Some("Email is already taken".into()),
    ///                     })
    ///                     .await?
    ///             }
    ///         },
    ///     )
    /// }
    /// ```
    pub async fn register(
        &self,
        account: DataProviderImpl::AccountType,
        password: &str,
    ) -> ResponseResult<RegistrationOutcome<DataProviderImpl::AccountType>> {
        let lowercase_email = account.email().to_ascii_lowercase();

        //verify that email is a valid email
        if !EMAIL_REGEX.is_match(&lowercase_email) {
            return Ok(RegistrationOutcome::InvalidEmail);
        }

        //check for existing account with same username
        if let Some(_) = self.provider.fetch_account(&lowercase_email).await? {
            return Ok(RegistrationOutcome::EmailTaken);
        }

        //hash password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password_simple(password.as_bytes(), salt.as_ref())?
            .to_string();

        //insert new account
        let account = self.provider.insert_account(account, hash).await?;

        return Ok(RegistrationOutcome::Successful(account));
    }

    ///Attempts to login to the specified account. See the documentation on LoginOutcome for details on what to do next.
    /// ```rust,ignore
    /// #[post("/login")]
    /// async fn login(auth: Data<ExampleAuthProvider>, dto: Json<LoginDto>) -> Response {
    ///     Ok(match auth.login(&dto.email, &dto.password)? {
    ///         LoginOutcome::Successful(account, cookie) => {
    ///             HttpResponse::Ok()
    ///                 .cookie(CookieBuilder::new("username", account.username).finish()) //this is how you make information available to your frontend, note that anything in your account type is visible to users as it is encoded as a JWT!!!!!
    ///                 .cookie(cookie)
    ///                 .json(LoginResponseDto {
    ///                     succeeded: true,
    ///                     message: None,
    ///                 })
    ///                 .await?
    ///         }
    ///         LoginOutcome::InvalidEmailOrPassword => {
    ///             HttpResponse::Ok()
    ///                 .json(LoginResponseDto {
    ///                     succeeded: false,
    ///                     message: Some("Invalid username or password".into()),
    ///                 })
    ///                 .await?
    ///         }
    ///     })
    /// }
    /// ```
    pub async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> ResponseResult<LoginOutcome<DataProviderImpl::AccountType>> {
        //get account & verify exists
        let (account, hash_string) = match self
            .provider
            .fetch_account(&email.to_ascii_lowercase())
            .await?
        {
            Some(account) => account,
            None => return Ok(LoginOutcome::InvalidEmailOrPassword),
        };

        //check password
        let argon2 = Argon2::default();
        let password_hash = PasswordHash::new(&hash_string)?;
        if !argon2
            .verify_password(password.as_bytes(), &password_hash)
            .is_ok()
        {
            return Ok(LoginOutcome::InvalidEmailOrPassword);
        }

        //issue token
        let claims = JsonWebTokenClaims {
            account,
            exp: current_unix_time_secs() as usize + 24 * 3600, //expire 24 hours after issue
        };
        let token = encode(&Header::default(), &claims, &self.jwt_encoding_key)?;

        //create cookie
        let cookie = CookieBuilder::new("actix-plus-auth-token", token)
            .secure(true)
            .http_only(true)
            .path("/")
            .same_site(SameSite::Strict)
            .finish();

        Ok(LoginOutcome::Successful(claims.account, cookie))
    }

    ///Gets the current user if a valid session is present on the provided HTTP request, otherwise returns a ResponseResult that when propagated with the actix-plus-error crate causes Actix web to return 401 Not Authorized.
    /// ```rust,ignore
    /// #[get("/private_page")]
    /// async fn private_page(request: HttpRequest, auth: Data<ExampleAuthProvider>) -> Response {
    ///     let account = auth.current_user(&request)?;
    ///     Ok(HttpResponse::Ok()
    ///         .body(format!("Hello {}", account.username))
    ///         .await?)
    /// }
    /// ```
    pub fn current_user(
        &self,
        request: &HttpRequest,
    ) -> ResponseResult<DataProviderImpl::AccountType> {
        //check for cookie
        let cookie: Cookie<'static> = match request.cookie("actix-plus-auth-token") {
            Some(cookie) => cookie,
            None => {
                return Err(ResponseError::StatusCodeError {
                    message: "Unauthorized".into(),
                    code: StatusCode::UNAUTHORIZED,
                })
            }
        };

        //check token
        let token = match decode::<JsonWebTokenClaims<DataProviderImpl::AccountType>>(
            &cookie.value(),
            &DecodingKey::from_secret(&self.jwt_secret),
            &Validation::default(),
        ) {
            Ok(token) => token,
            Err(_) => {
                return Err(ResponseError::StatusCodeError {
                    message: "Unauthorized".into(),
                    code: StatusCode::UNAUTHORIZED,
                })
            }
        };

        //return user if token is valid
        Ok(token.claims.account)
    }
}
