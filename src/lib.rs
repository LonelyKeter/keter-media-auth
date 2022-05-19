use async_trait::*;
use lazy_static::lazy_static;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

pub trait LoginData {
    type Claim: Serialize + Clone;
    type Context;
    type Err;

    fn to_claim(self, context: &Self::Context) -> Result<Self::Claim, Self::Err>;
}

#[async_trait]
pub trait LoginDataAsync {
    type Claim: Serialize + Clone;
    type Context;
    type Err;

    async fn to_claim(self, context: &Self::Context) -> Result<Self::Claim, Self::Err>;
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Payload<T: Clone> {
    claim: T,
    exp: usize,
}

impl<T: Serialize + Clone + DeserializeOwned> Payload<T> {
    pub fn get_claim(&self) -> T {
        self.claim.clone()
    }

    pub fn into_claim(self) -> T {
        self.claim
    }
}

pub trait Authenticator {
    type Data: LoginData;
    type Output;
    type Err;

    fn check(data: Self::Data) -> Result<Self::Output, Self::Err>;
}

use chrono::Duration;
use std::{default, marker::PhantomData};

#[derive(Clone)]
pub struct TokenSource<TClaim: Clone + Serialize + DeserializeOwned> {
    secret: Box<[u8]>,
    expiration_period: Duration,
    _claim_type: PhantomData<TClaim>,
}

lazy_static! {
    pub static ref DEFAULT_EXPIRATION_PERIOD: Duration = Duration::days(1);
}

pub static DEFAULT_SECRET: &[u8] = b"Some very cool secret";

impl<TClaim: Clone + Serialize + DeserializeOwned> Default for TokenSource<TClaim> {
    fn default() -> Self {
        Self::new(DEFAULT_SECRET, *DEFAULT_EXPIRATION_PERIOD)
    }
}

impl<TClaim: Clone + Serialize + DeserializeOwned> TokenSource<TClaim> {
    pub fn new(secret: &[u8], expiration_period: Duration) -> Self {
        let secret = {
            let mut buff = Vec::with_capacity(secret.len());
            buff.extend_from_slice(secret);
            buff
        }
        .into_boxed_slice();

        Self {
            secret,
            expiration_period,
            _claim_type: PhantomData,
        }
    }

    #[inline(always)]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self::new(secret, *DEFAULT_EXPIRATION_PERIOD)
    }

    #[inline(always)]
    pub fn from_expiration_period(expiration_period: Duration) -> Self {
        Self::new(DEFAULT_SECRET, expiration_period)
    }

    pub fn create_token<T: LoginData<Claim = TClaim>>(
        &self,
        data: T,
        context: &T::Context,
    ) -> Result<String, T::Err> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let exp = calc_expiration_timestamp(self.expiration_period);
        let payload = Payload::<T::Claim> {
            claim: data.to_claim(context)?,
            exp: exp as usize,
        };

        let header = Header::new(Algorithm::HS256);

        //Unmatching algorythm families in header and key will lead to panic
        let token = encode(&header, &payload, &EncodingKey::from_secret(&self.secret)).unwrap();

        Ok(token)
    }

    
    pub async fn create_token_async<T: LoginDataAsync<Claim = TClaim>>(
        &self,
        data: T,
        context: &T::Context,
    ) -> Result<String, T::Err> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let exp = calc_expiration_timestamp(self.expiration_period);
        let payload = Payload::<T::Claim> {
            claim: data.to_claim(context).await?,
            exp: exp as usize,
        };

        let header = Header::new(Algorithm::HS256);

        //Unmatching algorythm families in header and key will lead to panic
        let token = encode(&header, &payload, &EncodingKey::from_secret(&self.secret)).unwrap();

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<TClaim, ValidationError> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let decoded = decode::<Payload<TClaim>>(
            token,
            &DecodingKey::from_secret(&self.secret),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(ValidationError::on_verify)?;

        Ok(decoded.claims.claim)
    }
}

fn calc_expiration_timestamp(expiration_period: Duration) -> i64 {
    chrono::Utc::now()
        .checked_add_signed(expiration_period)
        .expect("Invalid timestamp")
        .timestamp()
}

unsafe impl<TClaim: Clone + Serialize + DeserializeOwned> Send for TokenSource<TClaim> {}

#[derive(Debug)]
pub enum ValidationError {
    InvalidAlgorithm,    
    InvalidToken,
    InvalidSignature,
    FailedVerification
}

impl ValidationError {
    fn on_verify(err: jsonwebtoken::errors::Error) -> Self {
        match err.into_kind() {
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => Self::InvalidAlgorithm,
            jsonwebtoken::errors::ErrorKind::InvalidToken => Self::InvalidToken,
            jsonwebtoken::errors::ErrorKind::InvalidSignature |  
            jsonwebtoken::errors::ErrorKind::ExpiredSignature |
            jsonwebtoken::errors::ErrorKind::ImmatureSignature => Self::InvalidSignature,
            _ => Self::FailedVerification
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
