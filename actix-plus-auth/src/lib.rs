use actix_plus_error::{ResponseError, ResponseResult};
use actix_plus_utils::current_unix_time_secs;
use actix_web::cookie::{Cookie, CookieBuilder, SameSite};
use actix_web::http::StatusCode;
use actix_web::{HttpMessage, HttpRequest};
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
