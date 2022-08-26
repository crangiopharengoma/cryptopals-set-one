use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use actix_web::web::{Data, Query};
use actix_web::{error, get, post, web, App, Error, HttpResponse, HttpServer, Responder};
use serde::Deserialize;

use cryptopals::encoding::hex::Hex;
use cryptopals::encoding::Digest;
use cryptopals::mac::sha_1::validate_hmac_insecure;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key = {
        let mut bytes = [0; 16];
        openssl::rand::rand_bytes(&mut bytes).expect("random key generation failed");
        bytes
    };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(key))
            .service(hello)
            .service(echo)
            .service(receive_secure_thing)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[derive(Deserialize)]
struct Message {
    file: String,
    signature: String,
}

#[derive(Debug)]
struct HmacError {
    message: &'static str,
}

impl StdError for HmacError {}

impl Display for HmacError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}", self.message)
    }
}

impl error::ResponseError for HmacError {}

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

#[get("/challenge31")]
async fn receive_secure_thing(
    message: Query<Message>,
    key: Data<[u8; 16]>, // key: Data<[u8; 20]>,
) -> Result<HttpResponse, Error> {
    let hmac_hex = Hex::from_str(&message.signature).expect("hmac invalid hex");
    let hmac = hmac_hex.bytes().try_into().expect("invalid hmac length");
    let key = key.get_ref();

    if validate_hmac_insecure(key, message.file.as_bytes(), hmac) {
        Ok(HttpResponse::Ok().body("Valid HMAC!"))
    } else {
        Err(HmacError {
            message: "Invalid message",
        }
        .into())
    }
}
