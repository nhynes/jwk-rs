#![allow(incomplete_features)]
#![feature(box_syntax, const_generics, fixed_size_array)]

mod byte_array;
mod byte_vec;
mod key_ops;
#[cfg(test)]
mod tests;
mod utils;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub use byte_array::ByteArray;
pub use byte_vec::ByteVec;
pub use key_ops::KeyOps;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKey {
    #[serde(flatten)]
    pub key_type: Box<KeyType>,

    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,

    #[serde(default, skip_serializing_if = "KeyOps::is_empty")]
    pub key_ops: KeyOps,

    #[serde(default, rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(default, rename = "alg", skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<JsonWebAlgorithm>,
}

impl JsonWebKey {
    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(serde_json::from_slice(bytes.as_ref())?)
    }
}

impl std::str::FromStr for JsonWebKey {
    type Err = Error;
    fn from_str(json: &str) -> Result<Self, Self::Err> {
        let jwk = Self::from_slice(json.as_bytes())?;

        // Validate alg.
        use JsonWebAlgorithm::*;
        use KeyType::*;
        let alg = match &jwk.algorithm {
            Some(alg) => alg,
            None => return Ok(jwk),
        };
        match (alg, &*jwk.key_type) {
            (
                ES256,
                EC {
                    params: Curve::P256 { .. },
                },
            )
            | (RS256, RSA { .. })
            | (HS256, Symmetric { .. }) => Ok(jwk),
            _ => Err(Error::MismatchedAlgorithm),
        }
    }
}

impl std::fmt::Display for JsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
        } else {
            write!(f, "{}", serde_json::to_string(self).unwrap())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum KeyType {
    EC {
        #[serde(flatten)]
        params: Curve,
    },
    RSA {
        #[serde(flatten)]
        public: RsaPublic,
        #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
        private: Option<RsaPrivate>,
    },
    #[serde(rename = "oct")]
    Symmetric {
        #[serde(rename = "k")]
        key: ByteVec,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "crv")]
pub enum Curve {
    /// prime256v1
    #[serde(rename = "P-256")]
    P256 {
        /// Private point.
        #[serde(skip_serializing_if = "Option::is_none")]
        d: Option<ByteArray<32>>,
        x: ByteArray<32>,
        y: ByteArray<32>,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPublic {
    /// Public exponent. Must be 65537.
    pub e: PublicExponent,
    /// Modulus, p*q.
    pub n: ByteVec,
}

const PUBLIC_EXPONENT: u32 = 65537;
const PUBLIC_EXPONENT_B64: &str = "AQAB"; // little-endian, strip zeros
const PUBLIC_EXPONENT_B64_PADDED: &str = "AQABAA==";
#[derive(Debug, PartialEq, Eq)]
pub struct PublicExponent;

impl Serialize for PublicExponent {
    fn serialize<S: serde::ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        PUBLIC_EXPONENT_B64.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PublicExponent {
    fn deserialize<D: serde::de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let e = String::deserialize(d)?;
        if e == PUBLIC_EXPONENT_B64 || e == PUBLIC_EXPONENT_B64_PADDED {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(&format!(
                "public exponent must be {}",
                PUBLIC_EXPONENT
            )))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPrivate {
    /// Private exponent.
    pub d: ByteVec,
    /// First prime factor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<ByteVec>,
    /// Second prime factor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<ByteVec>,
    /// First factor Chinese Remainder Theorem (CRT) exponent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<ByteVec>,
    /// Second factor Chinese Remainder Theorem (CRT) exponent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<ByteVec>,
    /// First CRT coefficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qi: Option<ByteVec>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Signing,
    #[serde(rename = "enc")]
    Encryption,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum JsonWebAlgorithm {
    HS256,
    RS256,
    ES256,
}

#[derive(thiserror::Error)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Error {
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),

    #[error("mismatched algorithm for key type")]
    MismatchedAlgorithm,
}
