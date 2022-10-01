use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use actix_web::web::{Data, Query};
use actix_web::{error, get, Error, HttpResponse};
use serde::Deserialize;

use cryptopals::encoding::hex::Hex;
use cryptopals::encoding::Digest;
use cryptopals::mac::sha_1::Sha1Hmac;
use cryptopals::mac::Hmac;

#[derive(Deserialize)]
pub(crate) struct Message {
    file: String,
    signature: String,
}

#[derive(Debug)]
pub(crate) struct HmacError {
    message: &'static str,
}

impl StdError for HmacError {}

impl Display for HmacError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}", self.message)
    }
}

impl error::ResponseError for HmacError {}

#[get("/challenge31")]
pub(crate) async fn receive_secure_thing(
    message: Query<Message>,
    key: Data<[u8; 16]>, // key: Data<[u8; 20]>,
) -> Result<HttpResponse, Error> {
    validate_hmac(&message, key, 50)
}

#[get("/challenge32")]
pub(crate) async fn slightly_better_receive_secure_thing(
    message: Query<Message>,
    key: Data<[u8; 16]>, // key: Data<[u8; 20]>,
) -> Result<HttpResponse, Error> {
    validate_hmac(&message, key, 5)
}

fn validate_hmac(
    message: &Query<Message>,
    key: Data<[u8; 16]>,
    pause: u64,
) -> Result<HttpResponse, Error> {
    let hmac_hex = Hex::from_str(&message.signature).expect("hmac invalid hex");
    let hmac: Sha1Hmac = hmac_hex.bytes().try_into().expect("invalid hmac length");
    let key = key.get_ref();

    if hmac.validate_hmac_insecure(key, message.file.as_bytes(), pause) {
        // if validate_hmac_insecure(key, message.file.as_bytes(), hmac, pause) {
        Ok(HttpResponse::Ok().body("Valid HMAC!"))
    } else {
        Err(HmacError {
            message: "Invalid message",
        }
        .into())
    }
}
