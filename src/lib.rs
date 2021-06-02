extern crate serde;

use serde::{Serialize, Deserialize};

extern crate chrono;
extern crate jsonwebtoken;

#[derive(Deserialize)]
pub struct LoginData {
    pub login: String,
    pub pwd: String
}

#[derive(Serialize)]
pub struct AuthenticationToken {
    pub token: String
}

#[derive(Debug, Serialize, Deserialize)] 
pub struct Claims {
    sub: String,
    exp: usize,
}

pub trait Authenticator {
    type Err;

    fn check(data: LoginData) -> Result<AuthenticationToken, Self::Err>;
}

use chrono::{Duration};

#[derive(Clone)]
pub struct TokenSource {
    secret: Box<[u8]>,
    expiration_period: chrono::Duration
}

const DEFAULT_EXPIRATION_PERIOD: Duration = Duration::minutes(30);

impl TokenSource {
    pub fn deafult() -> Self {
        let default = b"Some very cool secret";

        Self::from_secret(default)
    }

    #[inline(always)]
    pub fn from_secret(secret: &[u8]) -> Self {
        let secret = {
            let mut buff = Vec::with_capacity(secret.len());
            buff.extend_from_slice(secret);
            buff
        };

        Self {
            secret: secret.into_boxed_slice(),
            expiration_period: DEFAULT_EXPIRATION_PERIOD
        }
    }

    pub fn create_token(&self, data: LoginData) -> Result<AuthenticationToken, Error> {
        use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};

        let exp = calc_expiration_timestamp(self.expiration_period);
        let claims = Claims {
            sub: data.login,
            exp: exp as usize
        };

        let header = Header::new(Algorithm::HS256);

        let token = encode(&header, &claims, &EncodingKey::from_secret(&self.secret))
            .map_err(|_| Error::JWTCreationError)?;

        Ok(AuthenticationToken { token })
    }
}

fn calc_expiration_timestamp(expiration_period: Duration) -> i64 {
    chrono::Utc::now()
        .checked_add_signed(expiration_period)
        .expect("Invalid timestamp")
        .timestamp()
}

unsafe impl Send for TokenSource { }

enum Error {
    JWTCreationError
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
