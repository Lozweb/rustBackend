use crate::user::model::Keys;
use std::env::var;

#[derive(Clone)]
pub struct Config {
    pub brevo_api_key: String,
    pub auth_keys: Keys,
}

impl Config {
    pub fn load() -> Config {
        Config {
            brevo_api_key: var("BREVO_API_KEY").expect("Missing BREVO_API_KEY"),
            auth_keys: Keys::new(var("JWT_SECRET").expect("Missing JWT_SECRET").as_bytes()),
        }
    }
}