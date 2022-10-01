use actix_session::storage::CookieSessionStore;
use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

pub mod challenge_34;
pub mod timing_attack;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key = {
        let mut bytes = [0; 16];
        openssl::rand::rand_bytes(&mut bytes).expect("random key generation failed");
        bytes
    };

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .app_data(web::Data::new(key))
            .service(hello)
            .service(echo)
            .service(timing_attack::receive_secure_thing)
            .service(timing_attack::slightly_better_receive_secure_thing)
            .service(challenge_34::exchange_keys)
            .service(challenge_34::exchange_message)
            .service(challenge_34::exchange_keys_mitm)
            .service(challenge_34::exchange_message_mitm)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}
