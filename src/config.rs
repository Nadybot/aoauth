use std::{fs::read_to_string, lazy::SyncLazy, process::exit};

use jsonwebtoken::EncodingKey;
use serde::Deserialize;
use serde_json::{from_reader, from_str};
use std::{fs::File, io::BufReader};

pub static CONFIG: SyncLazy<Config> = SyncLazy::new(|| {
    let file = File::open("config.json");

    if let Ok(file) = file {
        let reader = BufReader::new(file);

        if let Ok(config) = from_reader(reader) {
            config
        } else {
            tracing::error!("Failed to parse config.json");
            exit(1)
        }
    } else {
        from_str("{}").unwrap()
    }
});

pub static PRIVATE_KEY: SyncLazy<EncodingKey> = SyncLazy::new(|| {
    let contents = read_to_string("keys/private.pem");

    if let Ok(contents) = contents {
        match EncodingKey::from_ec_pem(contents.as_bytes()) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!("Private key is misformatted: {}", e);
                exit(1)
            }
        }
    } else {
        tracing::error!("Failed to open keys/private.pem");
        exit(1)
    }
});

pub static PUBLIC_KEY: SyncLazy<String> = SyncLazy::new(|| {
    let contents = read_to_string("keys/public.pem");

    if let Ok(contents) = contents {
        contents
    } else {
        tracing::error!("Failed to open keys/public.pem");
        exit(1)
    }
});

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_bot_username")]
    pub bot_username: String,
    #[serde(default = "default_bot_password")]
    pub bot_password: String,
    #[serde(default = "default_bot_character")]
    pub bot_character: String,
}

fn default_bot_username() -> String {
    if let Ok(val) = std::env::var("BOT_USERNAME") {
        val
    } else {
        tracing::error!("Config does not contain bot_username and BOT_USERNAME env var is not set");
        exit(1);
    }
}

fn default_bot_password() -> String {
    if let Ok(val) = std::env::var("BOT_PASSWORD") {
        val
    } else {
        tracing::error!("Config does not contain bot_password and BOT_PASSWORD env var is not set");
        exit(1);
    }
}

fn default_bot_character() -> String {
    if let Ok(val) = std::env::var("BOT_CHARACTER") {
        val
    } else {
        tracing::error!(
            "Config does not contain bot_character and BOT_CHARACTER env var is not set"
        );
        exit(1);
    }
}
