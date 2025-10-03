use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
use actix_web::{body::BoxBody, cookie::{time::Duration, Key}, dev::{ServiceRequest, ServiceResponse}, get, middleware::{from_fn, Next}, post, web::{self, Data}, App, Error, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use argon2::{password_hash::{rand_core::OsRng, SaltString}, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, Executor, SqlitePool};

#[actix_web::main]
async fn main() {
    let pool = db().await;
    let key = Key::generate();
    let session_store = RedisSessionStore::new("redis://127.0.0.1:6379").await.unwrap();

    HttpServer::new(move || {
        App::new()
        .app_data(Data::new(pool.clone()))
        .wrap(IdentityMiddleware::builder().build())
        .wrap(SessionMiddleware::builder(session_store.clone(), key.clone()).session_lifecycle(PersistentSession::default().session_ttl(Duration::hours(24))).build())
        .service(index)
        .service(register)
        .service(login)
        .service(logout)
        .service(
            web::scope("/api")
            .wrap(from_fn(auth))
            .service(protected)
        )

    })
    .bind("0.0.0.0:3000")
    .unwrap()
    .run()
    .await
    .unwrap()
}

async fn db() -> SqlitePool {
    let pool = sqlx::sqlite::SqlitePool::connect("sqlite://db.sqlite").await.unwrap();
    pool.execute("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ").await.unwrap();

    pool
}

fn hash_password(password: String) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_password = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();

    hashed_password
}

fn verify_password(password: String, hashed_password: String) -> Result<(), argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let hashed_password = PasswordHash::new(&hashed_password).unwrap();
    argon2.verify_password(password.as_bytes(), &hashed_password)
}

#[post("/register")]
async fn register(pool: web::Data<SqlitePool>, user_request: web::Json<UserRequest>) -> impl Responder {
    if user_request.username.trim() == "" || user_request.password == "" {
        HttpResponse::BadRequest().body("Username or password must be not empty")
    } else {
        let rows: Vec<UserSql> = sqlx::query_as("SELECT * FROM users WHERE username = ?1").bind(&user_request.username).fetch_all(pool.get_ref()).await.unwrap();

        if rows.len() == 0 {
            let hashed_password = hash_password(user_request.password.clone());
            sqlx::query("INSERT INTO users (username, password) VALUES (?1, ?2)").bind(&user_request.username).bind(&hashed_password).execute(pool.get_ref()).await.unwrap();

            HttpResponse::Ok().body("Register Successful!")
        } else {
            HttpResponse::BadRequest().body("Username is already taken!")
        }
    }
}

#[post("/login")]
async fn login(pool: web::Data<SqlitePool>, user_request: web::Json<UserRequest>, req: HttpRequest) -> impl Responder {
    if user_request.username.trim() == "" || user_request.password == "" {
        HttpResponse::BadRequest().body("Username or password must be not empty")
    } else {
        let rows : Vec<UserSql> = sqlx::query_as("SELECT * FROM users WHERE username = ?1").bind(&user_request.username).fetch_all(pool.get_ref()).await.unwrap();

        if rows.len() == 0 {
            HttpResponse::NotFound().body("username is not registered!")
        } else {
            match verify_password(user_request.password.clone(), rows[0].password.clone()) {
                Ok(_) => {
                    Identity::login(&req.extensions(), user_request.username.clone().into()).unwrap();
                    HttpResponse::Ok().body("Login Successful!")
                },
                Err(_) => HttpResponse::Unauthorized().body("Password is incorrect")
            }
        }
    }
}

#[get("/logout")]
async fn logout(id: Option<Identity>) -> impl Responder {
    if let Some(id) = id {
        id.logout();
        HttpResponse::Ok().body("Logout Successful")
    }else {
        HttpResponse::BadRequest().body("Logout Failed")
    }
}
#[get("/")]
async fn index() -> impl Responder {
    "Hello World"
}

#[get("/protected")]
async fn protected(req: HttpRequest) -> impl Responder {
    match req.extensions().get::<String>().cloned() {
        Some(user) => {
            let msg = format!("Hello {}, welcome", user);
            HttpResponse::Ok().body(msg)
        },
        None => HttpResponse::NotFound().body("No user")
    }
}

async fn auth(id: Option<Identity>, req: ServiceRequest, next: Next<BoxBody>) -> Result<ServiceResponse<BoxBody>, Error> {
    if let Some(id) = id {
        let user = id.id().unwrap();
        req.extensions_mut().insert(user);
        next.call(req).await
    } else {
        Ok(req.into_response(HttpResponse::Unauthorized().body("You are unauthorized")))
    }
}


#[derive(Deserialize)]
struct UserRequest {
    username: String,
    password: String
}

#[derive(FromRow, Serialize)]
struct UserSql {
    id: i32,
    username: String,
    password: String
}