#![deny(rust_2018_idioms, unreachable_pub)]
#![forbid(unsafe_code)]

//! *[JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517#section-4.3) (de)serialization, generation, and conversion.*
//!
//! **Note**: this crate requires Rust nightly >= 1.45 because it uses
//! `feature(const_generics, fixed_size_array)` to enable statically-checked key lengths.
//!
//! ## Examples
//!
//! ### Deserializing from JSON
//!
//! ```
//! extern crate jsonwebkey as jwk;
//! // Generated using https://mkjwk.org/.
//! let jwt_str = r#"{
//!    "kty": "oct",
//!    "use": "sig",
//!    "kid": "my signing key",
//!    "k": "Wpj30SfkzM_m0Sa_B2NqNw",
//!    "alg": "HS256"
//! }"#;
//! let the_jwk: jwk::JsonWebKey = jwt_str.parse().unwrap();
//! println!("{:#?}", the_jwk); // looks like `jwt_str` but with reordered fields.
//! ```
//!
//! ### Using with other crates
//!
//! ```
//! #[cfg(all(feature = "generate", feature = "jwt-convert"))] {
//! extern crate jsonwebtoken as jwt;
//! extern crate jsonwebkey as jwk;
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct TokenClaims {
//!     exp: usize,
//! }
//!
//! let mut my_jwk = jwk::JsonWebKey::new(jwk::Key::generate_p256());
//! my_jwk.set_algorithm(jwk::Algorithm::ES256);
//!
//! let alg: jwt::Algorithm = my_jwk.algorithm.unwrap().into();
//! let token = jwt::encode(
//!     &jwt::Header::new(alg),
//!     &TokenClaims {
//!         exp: 0,
//!     },
//!     &my_jwk.key.to_encoding_key(),
//! ).unwrap();
//!
//! let mut validation = jwt::Validation::new(alg);
//! validation.validate_exp = false;
//! jwt::decode::<TokenClaims>(&token, &my_jwk.key.to_decoding_key(), &validation).unwrap();
//! }
//! ```
//!
//! ## Features
//!
//! * `convert` - enables `Key::{to_der, to_pem}`.
//!               This pulls in the [yasna](https://crates.io/crates/yasna) crate.
//! * `generate` - enables `Key::{generate_p256, generate_symmetric}`.
//!                This pulls in the [p256](https://crates.io/crates/p256) and [rand](https://crates.io/crates/rand) crates.
//! * `jsonwebtoken` - enables conversions to types in the [jsonwebtoken](https://crates.io/crates/jsonwebtoken) crate.

mod byte_array;
mod byte_vec;
mod key_ops;
#[cfg(test)]
mod tests;
mod utils;

use std::{borrow::Cow, fmt};

use generic_array::typenum::U32;
use serde::{Deserialize, Serialize};

pub use byte_array::ByteArray;
pub use byte_vec::ByteVec;
pub use key_ops::KeyOps;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKey {
    #[serde(flatten)]
    pub key: Box<Key>,

    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,

    #[serde(default, skip_serializing_if = "KeyOps::is_empty")]
    pub key_ops: KeyOps,

    #[serde(default, rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(default, rename = "alg", skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<Algorithm>,

    #[serde(default, flatten, skip_serializing_if = "X509Params::is_empty")]
    pub x5: X509Params,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Params {
    /// x5u: The URL of the X.509 cert corresponding to this key.
    #[serde(default, rename = "x5u", skip_serializing_if = "Option::is_none")]
    url: Option<String>,

    /// x5c: The certificate chain used to verify this key.
    #[serde(default, rename = "x5c", skip_serializing_if = "Option::is_none")]
    cert_chain: Option<Vec<String>>,

    /// x5t: The SHA-1 thumbprint of the DER-encoded X.509 version of the public key.
    #[serde(default, rename = "x5t", skip_serializing_if = "Option::is_none")]
    thumbprint: Option<String>,

    /// x5t#S256: The same data as the thumbprint, but digested using SHA-256
    #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    thumbprint_sha256: Option<String>,
}

impl X509Params {
    fn is_empty(&self) -> bool {
        matches!(
            self,
            X509Params {
                url: None,
                cert_chain: None,
                thumbprint: None,
                thumbprint_sha256: None,
            }
        )
    }
}

impl JsonWebKey {
    pub fn new(key: Key) -> Self {
        Self {
            key: Box::new(key),
            key_use: None,
            key_ops: KeyOps::empty(),
            key_id: None,
            algorithm: None,
            x5: Default::default(),
        }
    }

    pub fn set_algorithm(&mut self, alg: Algorithm) -> Result<(), Error> {
        Self::validate_algorithm(alg, &*self.key)?;
        self.algorithm = Some(alg);
        Ok(())
    }

    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(serde_json::from_slice(bytes.as_ref())?)
    }

    fn validate_algorithm(alg: Algorithm, key: &Key) -> Result<(), Error> {
        use Algorithm::*;
        use Key::*;
        match (alg, key) {
            (
                ES256,
                EC {
                    curve: Curve::P256 { .. },
                },
            )
            | (RS256, RSA { .. })
            | (HS256, Symmetric { .. }) => Ok(()),
            _ => Err(Error::MismatchedAlgorithm),
        }
    }
}

impl std::str::FromStr for JsonWebKey {
    type Err = Error;
    fn from_str(json: &str) -> Result<Self, Self::Err> {
        let jwk = Self::from_slice(json.as_bytes())?;

        let alg = match jwk.algorithm {
            Some(alg) => alg,
            None => return Ok(jwk),
        };
        Self::validate_algorithm(alg, &*jwk.key).map(|_| jwk)
    }
}

impl std::fmt::Display for JsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
        } else {
            write!(f, "{}", serde_json::to_string(self).unwrap())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
#[allow(clippy::upper_case_acronyms)]
pub enum Key {
    /// An elliptic curve, as per [RFC 7518 §6.2](https://tools.ietf.org/html/rfc7518#section-6.2).
    EC {
        #[serde(flatten)]
        curve: Curve,
    },
    /// An elliptic curve, as per [RFC 7518 §6.3](https://tools.ietf.org/html/rfc7518#section-6.3).
    /// See also: [RFC 3447](https://tools.ietf.org/html/rfc3447).
    RSA {
        #[serde(flatten)]
        public: RsaPublic,
        #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
        private: Option<RsaPrivate>,
    },
    /// A symmetric key, as per [RFC 7518 §6.4](https://tools.ietf.org/html/rfc7518#section-6.4).
    #[serde(rename = "oct")]
    Symmetric {
        #[serde(rename = "k")]
        key: ByteVec,
    },
}

impl Key {
    /// Returns true iff this key only contains private components (i.e. a private asymmetric
    /// key or a symmetric key).
    pub fn is_private(&self) -> bool {
        matches!(
            self,
            Self::Symmetric { .. }
                | Self::EC {
                    curve: Curve::P256 { d: Some(_), .. },
                    ..
                }
                | Self::RSA {
                    private: Some(_),
                    ..
                }
        )
    }

    /// Returns the public part of this key (symmetric keys have no public parts).
    pub fn to_public(&self) -> Option<Cow<'_, Self>> {
        if !self.is_private() {
            return Some(Cow::Borrowed(self));
        }
        Some(Cow::Owned(match self {
            Self::Symmetric { .. } => return None,
            Self::EC {
                curve: Curve::P256 { x, y, .. },
            } => Self::EC {
                curve: Curve::P256 {
                    x: x.clone(),
                    y: y.clone(),
                    d: None,
                },
            },
            Self::RSA { public, .. } => Self::RSA {
                public: public.clone(),
                private: None,
            },
        }))
    }

    /// If this key is asymmetric, encodes it as PKCS#8.
    #[cfg(feature = "pkcs-convert")]
    pub fn try_to_der(&self) -> Result<Vec<u8>, ConversionError> {
        use num_bigint::BigUint;
        use yasna::{models::ObjectIdentifier, DERWriter, DERWriterSeq, Tag};

        use crate::utils::pkcs8;

        if let Self::Symmetric { .. } = self {
            return Err(ConversionError::NotAsymmetric);
        }

        Ok(match self {
            Self::EC {
                curve: Curve::P256 { d, x, y },
            } => {
                let ec_public_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]);
                let prime256v1_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]);
                let oids = &[Some(&ec_public_oid), Some(&prime256v1_oid)];

                let write_public = |writer: DERWriter<'_>| {
                    let public_bytes: Vec<u8> = [0x04 /* uncompressed */]
                        .iter()
                        .chain(x.iter())
                        .chain(y.iter())
                        .copied()
                        .collect();
                    writer.write_bitvec_bytes(&public_bytes, 8 * (32 * 2 + 1));
                };

                match d {
                    Some(private_point) => {
                        pkcs8::write_private(oids, |writer: &mut DERWriterSeq<'_>| {
                            writer.next().write_i8(1); // version
                            writer.next().write_bytes(&**private_point);
                            // The following tagged value is optional. OpenSSL produces it,
                            // but many tools, including jwt.io and `jsonwebtoken`, don't like it,
                            // so we don't include it.
                            // writer.next().write_tagged(Tag::context(0), |writer| {
                            //     writer.write_oid(&prime256v1_oid)
                            // });
                            writer.next().write_tagged(Tag::context(1), write_public);
                        })
                    }
                    None => pkcs8::write_public(oids, write_public),
                }
            }
            Self::RSA { public, private } => {
                let rsa_encryption_oid = ObjectIdentifier::from_slice(&[
                    1, 2, 840, 113549, 1, 1, 1, // rsaEncryption
                ]);
                let oids = &[Some(&rsa_encryption_oid), None];
                let write_bytevec = |writer: DERWriter<'_>, vec: &ByteVec| {
                    let bigint = BigUint::from_bytes_be(vec);
                    writer.write_biguint(&bigint);
                };

                let write_public = |writer: &mut DERWriterSeq<'_>| {
                    write_bytevec(writer.next(), &public.n);
                    writer.next().write_u32(PUBLIC_EXPONENT);
                };

                let write_private = |writer: &mut DERWriterSeq<'_>, private: &RsaPrivate| {
                    // https://tools.ietf.org/html/rfc3447#appendix-A.1.2
                    writer.next().write_i8(0); // version (two-prime)
                    write_public(writer);
                    write_bytevec(writer.next(), &private.d);
                    macro_rules! write_opt_bytevecs {
                            ($($param:ident),+) => {{
                                $(write_bytevec(writer.next(), private.$param.as_ref().unwrap());)+
                            }};
                        }
                    write_opt_bytevecs!(p, q, dp, dq, qi);
                };

                match private {
                    Some(
                        private @ RsaPrivate {
                            d: _,
                            p: Some(_),
                            q: Some(_),
                            dp: Some(_),
                            dq: Some(_),
                            qi: Some(_),
                        },
                    ) => pkcs8::write_private(oids, |writer| write_private(writer, private)),
                    Some(_) => return Err(ConversionError::MissingRsaParams),
                    None => pkcs8::write_public(oids, |writer| {
                        let body =
                            yasna::construct_der(|writer| writer.write_sequence(write_public));
                        writer.write_bitvec_bytes(&body, body.len() * 8);
                    }),
                }
            }
            Self::Symmetric { .. } => unreachable!("checked above"),
        })
    }

    /// Unwrapping `try_to_der`.
    /// Panics if the key is not asymmetric or there are missing RSA components.
    #[cfg(feature = "pkcs-convert")]
    pub fn to_der(&self) -> Vec<u8> {
        self.try_to_der().unwrap()
    }

    /// If this key is asymmetric, encodes it as PKCS#8 with PEM armoring.
    #[cfg(feature = "pkcs-convert")]
    pub fn try_to_pem(&self) -> Result<String, ConversionError> {
        use std::fmt::Write;
        let der_b64 = base64::encode(self.try_to_der()?);
        let key_ty = if self.is_private() {
            "PRIVATE"
        } else {
            "PUBLIC"
        };
        let mut pem = String::new();
        writeln!(&mut pem, "-----BEGIN {} KEY-----", key_ty).unwrap();
        //^ re: `unwrap`, if writing to a string fails, we've got bigger issues.
        const MAX_LINE_LEN: usize = 64;
        for i in (0..der_b64.len()).step_by(MAX_LINE_LEN) {
            writeln!(
                &mut pem,
                "{}",
                &der_b64[i..std::cmp::min(i + MAX_LINE_LEN, der_b64.len())]
            )
            .unwrap();
        }
        writeln!(&mut pem, "-----END {} KEY-----", key_ty).unwrap();
        Ok(pem)
    }

    /// Unwrapping `try_to_pem`.
    /// Panics if the key is not asymmetric or there are missing RSA components.
    #[cfg(feature = "pkcs-convert")]
    pub fn to_pem(&self) -> String {
        self.try_to_pem().unwrap()
    }

    /// Generates a new symmetric key with the specified number of bits.
    /// Best used with one of the HS algorithms (e.g., HS256).
    #[cfg(feature = "generate")]
    pub fn generate_symmetric(num_bits: usize) -> Self {
        use rand::RngCore;
        let mut bytes = vec![0; num_bits / 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self::Symmetric { key: bytes.into() }
    }

    /// Generates a new EC keypair using the prime256 curve.
    /// Used with the ES256 algorithm.
    #[cfg(feature = "generate")]
    pub fn generate_p256() -> Self {
        use p256::elliptic_curve::{self as elliptic_curve, sec1::ToEncodedPoint};

        let sk = elliptic_curve::SecretKey::random(&mut rand::thread_rng());
        let sk_scalar = p256::Scalar::from(&sk);

        let pk = p256::ProjectivePoint::generator() * sk_scalar;
        let pk_bytes = &pk
            .to_affine()
            .to_encoded_point(false /* compress */)
            .to_bytes()[1..];
        let (x_bytes, y_bytes) = pk_bytes.split_at(32);

        Self::EC {
            curve: Curve::P256 {
                d: Some(sk_scalar.to_bytes().into()),
                x: ByteArray::from_slice(x_bytes),
                y: ByteArray::from_slice(y_bytes),
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "crv")]
pub enum Curve {
    /// Parameters of the prime256v1 (P256) curve.
    #[serde(rename = "P-256")]
    P256 {
        /// The private scalar.
        #[serde(skip_serializing_if = "Option::is_none")]
        d: Option<ByteArray<U32>>,
        /// The curve point x coordinate.
        x: ByteArray<U32>,
        /// The curve point y coordinate.
        y: ByteArray<U32>,
    },
}

impl fmt::Debug for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P256 { x, y, .. } => f
                .debug_struct("Curve:P256")
                .field("x", x)
                .field("y", y)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPublic {
    /// The standard public exponent, 65537.
    pub e: PublicExponent,
    /// The modulus, p*q.
    pub n: ByteVec,
}

const PUBLIC_EXPONENT: u32 = 65537;
const PUBLIC_EXPONENT_B64: &str = "AQAB"; // little-endian, strip zeros
const PUBLIC_EXPONENT_B64_PADDED: &str = "AQABAA==";

/// The standard RSA public exponent, 65537.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Second factor CRT exponent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<ByteVec>,
    /// First CRT coefficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qi: Option<ByteVec>,
}

impl fmt::Debug for RsaPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RsaPrivate")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Signing,
    #[serde(rename = "enc")]
    Encryption,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum Algorithm {
    HS256,
    RS256,
    ES256,
}

#[cfg(feature = "jwt-convert")]
const _IMPL_JWT_CONVERSIONS: () = {
    use jsonwebtoken as jwt;

    impl From<Algorithm> for jwt::Algorithm {
        fn from(alg: Algorithm) -> Self {
            match alg {
                Algorithm::HS256 => Self::HS256,
                Algorithm::ES256 => Self::ES256,
                Algorithm::RS256 => Self::RS256,
            }
        }
    }

    impl Key {
        /// Returns an `EncodingKey` if the key is private.
        pub fn try_to_encoding_key(&self) -> Result<jwt::EncodingKey, ConversionError> {
            if !self.is_private() {
                return Err(ConversionError::NotPrivate);
            }
            Ok(match self {
                Self::Symmetric { key } => jwt::EncodingKey::from_secret(key),
                // The following two conversion will not panic, as we've ensured that the keys
                // are private and tested that the successful output of `try_to_pem` is valid.
                Self::EC { .. } => {
                    jwt::EncodingKey::from_ec_pem(self.try_to_pem()?.as_bytes()).unwrap()
                }
                Self::RSA { .. } => {
                    jwt::EncodingKey::from_rsa_pem(self.try_to_pem()?.as_bytes()).unwrap()
                }
            })
        }

        /// Unwrapping `try_to_encoding_key`. Panics if the key is public.
        pub fn to_encoding_key(&self) -> jwt::EncodingKey {
            self.try_to_encoding_key().unwrap()
        }

        pub fn to_decoding_key(&self) -> jwt::DecodingKey {
            match self {
                Self::Symmetric { key } => jwt::DecodingKey::from_secret(key),
                Self::EC { .. } => {
                    // The following will not panic: all EC JWKs have public components due to
                    // typing. PEM conversion will always succeed, for the same reason.
                    // Hence, jwt::DecodingKey shall have no issue with de-converting.
                    jwt::DecodingKey::from_ec_pem(self.to_public().unwrap().to_pem().as_bytes())
                        .unwrap()
                }
                Self::RSA { .. } => {
                    jwt::DecodingKey::from_rsa_pem(self.to_pem().as_bytes()).unwrap()
                }
            }
        }
    }
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),

    #[error("mismatched algorithm for key type")]
    MismatchedAlgorithm,
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("encoding RSA JWK as PKCS#8 requires specifing all of p, q, dp, dq, qi")]
    MissingRsaParams,

    #[error("a symmetric key can not be encoded using PKCS#8")]
    NotAsymmetric,

    #[cfg(feature = "jwt-convert")]
    #[error("a public key cannot be converted to a `jsonwebtoken::EncodingKey`")]
    NotPrivate,
}
