use actix_plus_error::{ResponseError, ResponseResult};
use actix_plus_utils::current_unix_time_secs;
use actix_web::cookie::{Cookie, CookieBuilder, SameSite};
use actix_web::http::StatusCode;
use actix_web::{HttpMessage, HttpRequest};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub trait Account: Serialize + DeserializeOwned + Debug + 'static {
    fn email(&self) -> &str;
}

pub trait DataProvider: Clone {
    type AccountType: Account;

    fn insert_account(
        &self,
        account: Self::AccountType,
        password_hash: String,
    ) -> ResponseResult<Self::AccountType>;
    fn fetch_account(&self, email: &str) -> ResponseResult<Option<(Self::AccountType, String)>>;
}

pub enum RegistrationOutcome<AccountType: Account> {
    Successful(AccountType),
    InvalidEmail,
    EmailTaken,
}

pub enum LoginOutcome<AccountType> {
    Successful(AccountType, Cookie<'static>),
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

#[derive(Clone)]
pub struct AuthenticationProvider<DataProviderImpl: DataProvider> {
    provider: DataProviderImpl,
    jwt_encoding_key: EncodingKey,
    jwt_secret: Vec<u8>,
}

impl<DataProviderImpl: DataProvider> AuthenticationProvider<DataProviderImpl> {
    pub fn new(provider: DataProviderImpl, jwt_secret: Vec<u8>) -> Self {
        Self {
            provider,
            jwt_encoding_key: EncodingKey::from_secret(&jwt_secret),
            jwt_secret,
        }
    }

    pub fn register(
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
        if let Some(_) = self.provider.fetch_account(&lowercase_email)? {
            return Ok(RegistrationOutcome::EmailTaken);
        }

        //hash password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password_simple(password.as_bytes(), salt.as_ref())?
            .to_string();

        //insert new account
        let account = self.provider.insert_account(account, hash)?;

        return Ok(RegistrationOutcome::Successful(account));
    }

    pub fn login(
        &self,
        email: &str,
        password: &str,
    ) -> ResponseResult<LoginOutcome<DataProviderImpl::AccountType>> {
        //get account & verify exists
        let (account, hash_string) =
            match self.provider.fetch_account(&email.to_ascii_lowercase())? {
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
