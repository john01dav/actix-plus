use crate::auth::{ExampleAccount, ExampleAuthProvider, InMemoryDataProvider};
use actix_plus_auth::{AuthenticationProvider, LoginOutcome, RegistrationOutcome};
use actix_plus_error::Response;
use actix_plus_static_files::{build_hashmap_from_included_dir, include_dir, Dir, ResourceFiles};
use actix_web::cookie::CookieBuilder;
use actix_web::web::{Data, Json};
use actix_web::{get, post, App, HttpRequest, HttpResponse, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct LoginDto {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponseDto {
    succeeded: bool,
    message: Option<String>,
}

#[post("/login")]
async fn login(auth: Data<ExampleAuthProvider>, dto: Json<LoginDto>) -> Response {
    Ok(match auth.login(&dto.email, &dto.password).await? {
        LoginOutcome::Successful(account, cookie) => {
            HttpResponse::Ok()
                .cookie(CookieBuilder::new("username", account.username).finish()) //this is how you make information available to your frontend, note that anything in your account type is visible to users as it is encoded as a JWT!!!!!
                .cookie(cookie)
                .json(LoginResponseDto {
                    succeeded: true,
                    message: None,
                })
        }
        LoginOutcome::InvalidEmailOrPassword => {
            HttpResponse::Ok()
                .json(LoginResponseDto {
                    succeeded: false,
                    message: Some("Invalid username or password".into()),
                })
        }
    })
}

#[post("/logout")]
async fn logout(request: HttpRequest) -> Response {
    let mut response = HttpResponse::Ok().await?;
    if let Some(mut session_cookie) = request.cookie("actix-plus-auth-token") {
        //TODO: no magic strings
        session_cookie.set_path("/");
        session_cookie.set_secure(true);
        response.add_removal_cookie(&session_cookie)?;
    }
    if let Some(mut username_cookie) = request.cookie("username") {
        //TODO: no magic strings
        username_cookie.set_path("/");
        username_cookie.set_secure(true);
        response.add_removal_cookie(&username_cookie)?;
    }
    Ok(response)
}

#[derive(Deserialize)]
struct RegistrationDto {
    email: String,
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegistrationResponseDto {
    succeeded: bool,
    message: Option<String>,
}

#[post("/register")]
async fn register(auth: Data<ExampleAuthProvider>, dto: Json<RegistrationDto>) -> Response {
    let dto = dto.into_inner();
    Ok(
        match auth
            .register(
                ExampleAccount {
                    username: dto.username,
                    email: dto.email,
                },
                &dto.password,
            )
            .await?
        {
            RegistrationOutcome::Successful(_account) => {
                HttpResponse::Ok()
                    .json(RegistrationResponseDto {
                        succeeded: true,
                        message: None,
                    })
            }
            RegistrationOutcome::InvalidEmail => {
                HttpResponse::Ok()
                    .json(RegistrationResponseDto {
                        succeeded: false,
                        message: Some("Invalid Email".into()),
                    })
            }
            RegistrationOutcome::EmailTaken => {
                HttpResponse::Ok()
                    .json(RegistrationResponseDto {
                        succeeded: false,
                        message: Some("Email is already taken".into()),
                    })
            }
        },
    )
}

#[get("/private_page")]
async fn private_page(request: HttpRequest, auth: Data<ExampleAuthProvider>) -> Response {
    let account = auth.current_user(&request)?;
    Ok(HttpResponse::Ok()
        .body(format!("Hello {}", account.username)))
}

const FRONTEND: Dir = include_dir!("examples/frontend");

#[actix_web::main]
async fn main() {
    let auth = AuthenticationProvider::new(
        InMemoryDataProvider::new(),
        "some secret, you should use a real one"
            .as_bytes()
            .iter()
            .map(|u| *u)
            .collect(),
    );

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("actix-plus-auth/examples/key.pem", SslFiletype::PEM)
        .unwrap();
    builder
        .set_certificate_chain_file("actix-plus-auth/examples/cert.pem")
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(auth.clone()))
            .service(login)
            .service(logout)
            .service(register)
            .service(private_page)
            .service(ResourceFiles::new(
                "/",
                build_hashmap_from_included_dir(&FRONTEND),
            ))
    })
    .bind_openssl("127.0.0.1:8192", builder)
    .expect("Failed to bind to port.")
    .run()
    .await
    .expect("Failed to run Actix Web.");
}

//in a real project you would probably want this module to be its own file
mod auth {
    use actix_plus_auth::{async_trait, Account, AuthenticationProvider, DataProvider};
    use actix_plus_error::ResponseResult;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    pub type ExampleAuthProvider = AuthenticationProvider<InMemoryDataProvider>;

    // !!!!!WARNING: anything in your account type is visible to users as it is encoded as a JWT!!!!!
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct ExampleAccount {
        pub username: String, //example of custom data to include with one's account type
        pub email: String,
    }

    impl Account for ExampleAccount {
        fn email(&self) -> &str {
            &self.email
        }
    }

    #[derive(Clone)]
    pub struct InMemoryDataProvider {
        //a real database should be used here instead of a simple in-memory store
        accounts: Arc<Mutex<HashMap<String, (ExampleAccount, String)>>>, //in a real program you probably don't want locks on your account system, to make it more scalable, although it's fine for a simple example
    }

    impl InMemoryDataProvider {
        pub fn new() -> Self {
            Self {
                accounts: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl DataProvider for InMemoryDataProvider {
        type AccountType = ExampleAccount; //this is where you tell the library about your account type

        async fn insert_account(
            &self,
            account: Self::AccountType,
            password_hash: String,
        ) -> ResponseResult<Self::AccountType> {
            let mut datastore = self.accounts.lock().expect("Mutex Poisoning");
            let cloned_account = account.clone();
            datastore.insert(account.email.to_ascii_lowercase(), (account, password_hash));
            Ok(cloned_account)
        }

        async fn fetch_account(
            &self,
            email: &str,
        ) -> ResponseResult<Option<(Self::AccountType, String)>> {
            let datastore = self.accounts.lock().expect("Mutex Poisoning");
            let (account, password_hash) = match datastore.get(email) {
                Some(record) => record,
                None => return Ok(None),
            };
            Ok(Some((account.clone(), password_hash.clone())))
        }
    }
}
