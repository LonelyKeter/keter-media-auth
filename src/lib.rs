extern crate serde;

use serde::{Serialize, Deserialize, de::DeserializeOwned};

extern crate chrono;
extern crate jsonwebtoken;
#[macro_use] extern crate lazy_static;

pub trait LoginData {
    type Claim: Serialize + Clone;
    fn to_claim(&self) -> Self::Claim;
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Payload<T: Clone> {
    claim: T,
    exp: usize
}

impl<T: Serialize + Clone + DeserializeOwned> Payload<T> {
    pub fn get_claim(&self) -> T {
        self.claim.clone()
    }

    pub fn into_claim(self) -> T {
        self.claim
    }
}

#[derive(Serialize)]
pub struct AuthenticationToken {
    pub token: String
}

pub trait Authenticator {
    type Data: LoginData;
    type Output;
    type Err;

    fn check(data: Self::Data) -> Result<Self::Output, Self::Err>;
}

use chrono::{Duration};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct TokenSource<TClaim: Clone + Serialize + DeserializeOwned> {
    secret: Box<[u8]>,
    expiration_period: Duration,
    _claim_type: PhantomData<TClaim>
}

lazy_static! {
    pub static ref DEFAULT_EXPIRATION_PERIOD: Duration = Duration::minutes(30);
}

impl<TClaim: Clone + Serialize + DeserializeOwned> TokenSource<TClaim> {
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
            expiration_period: *DEFAULT_EXPIRATION_PERIOD,
            _claim_type: PhantomData
        }
    }

    pub fn create_token<T: LoginData<Claim = TClaim>>(&self, data: T) -> Result<AuthenticationToken, Error> {
        use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};

        let exp = calc_expiration_timestamp(self.expiration_period);
        let payload = Payload::<T::Claim> {
            claim: data.to_claim(),
            exp: exp as usize
        };

        let header = Header::new(Algorithm::HS256);

        let token = encode(&header, &payload, &EncodingKey::from_secret(&self.secret))
            .map_err(|_| Error::JWTCreationError)?;

        Ok(AuthenticationToken { token })
    }

    pub fn verify_token(&self, token: String) -> Result<TClaim, Error> {
        use jsonwebtoken::{decode, DecodingKey, Algorithm, Validation};

        let decoded = decode::<Payload<TClaim>>(
            &token, 
            &DecodingKey::from_secret(&self.secret), 
            &Validation::new(Algorithm::HS256))
            .map_err(|_| Error::JWTDecodingError)?;

        Ok(decoded.claims.claim)
    }
}

fn calc_expiration_timestamp(expiration_period: Duration) -> i64 {
    chrono::Utc::now()
        .checked_add_signed(expiration_period)
        .expect("Invalid timestamp")
        .timestamp()
}

unsafe impl<TClaim: Clone + Serialize + DeserializeOwned> Send for TokenSource<TClaim> { }

pub enum Error {
    JWTCreationError,
    JWTDecodingError
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
