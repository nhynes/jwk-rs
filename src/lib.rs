#![allow(incomplete_features)]
#![feature(box_syntax, const_generics, fixed_size_array)]

mod byte_array;
mod byte_vec;
mod key_ops;
#[cfg(test)]
mod tests;
mod utils;

use std::array::FixedSizeArray;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub use byte_array::ByteArray;
pub use byte_vec::ByteVec;
pub use key_ops::KeyOps;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub algorithm: Option<JsonWebAlgorithm>,
}

impl JsonWebKey {
    pub fn new(key: Key) -> Self {
        Self {
            key: box key,
            key_use: None,
            key_ops: KeyOps::empty(),
            key_id: None,
            algorithm: None,
        }
    }

    pub fn set_algorithm(&mut self, alg: JsonWebAlgorithm) -> Result<(), Error> {
        Self::validate_algorithm(alg, &*self.key)?;
        self.algorithm = Some(alg);
        Ok(())
    }

    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(serde_json::from_slice(bytes.as_ref())?)
    }

    fn validate_algorithm(alg: JsonWebAlgorithm, key: &Key) -> Result<(), Error> {
        use JsonWebAlgorithm::*;
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
        } else {
            write!(f, "{}", serde_json::to_string(self).unwrap())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
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
    fn is_private(&self) -> bool {
        match self {
            Self::Symmetric { .. }
            | Self::EC {
                curve: Curve::P256 { d: Some(_), .. },
                ..
            }
            | Self::RSA {
                private: Some(_), ..
            } => true,
            _ => false,
        }
    }

    /// Returns true iff this key only contains non-private components.
    pub fn is_public(&self) -> bool {
        !self.is_private()
    }

    /// Returns the public part of this key, if it's symmetric.
    pub fn to_public(&self) -> Option<Self> {
        if self.is_public() {
            return Some(self.clone());
        }
        Some(match self {
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
        })
    }

    /// If this key is asymmetric, encodes it as PKCS#8.
    #[cfg(feature = "convert")]
    pub fn to_der(&self) -> Result<Vec<u8>, PkcsConvertError> {
        use num_bigint::BigUint;
        use yasna::{models::ObjectIdentifier, DERWriter, DERWriterSeq, Tag};

        use crate::utils::pkcs8;

        if let Self::Symmetric { .. } = self {
            return Err(PkcsConvertError::NotAsymmetric);
        }

        Ok(match self {
            Self::EC {
                curve: Curve::P256 { d, x, y },
            } => {
                let ec_public_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]);
                let prime256v1_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]);
                let oids = &[Some(&ec_public_oid), Some(&prime256v1_oid)];

                let write_public = |writer: DERWriter| {
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
                        pkcs8::write_private(oids, |writer: &mut DERWriterSeq| {
                            writer.next().write_i8(1); // version
                            writer.next().write_bytes(private_point.as_slice());
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
                let write_bytevec = |writer: DERWriter, vec: &ByteVec| {
                    let bigint = BigUint::from_bytes_be(vec.as_slice());
                    writer.write_biguint(&bigint);
                };

                let write_public = |writer: &mut DERWriterSeq| {
                    write_bytevec(writer.next(), &public.n);
                    writer.next().write_u32(PUBLIC_EXPONENT);
                };

                let write_private = |writer: &mut DERWriterSeq, private: &RsaPrivate| {
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
                        private
                        @
                        RsaPrivate {
                            d: _,
                            p: Some(_),
                            q: Some(_),
                            dp: Some(_),
                            dq: Some(_),
                            qi: Some(_),
                        },
                    ) => pkcs8::write_private(oids, |writer| write_private(writer, private)),
                    Some(_) => return Err(PkcsConvertError::MissingRsaParams),
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

    /// If this key is asymmetric, encodes it as PKCS#8 with PEM armoring.
    #[cfg(feature = "convert")]
    pub fn to_pem(&self) -> Result<String, PkcsConvertError> {
        use std::fmt::Write;
        let der_b64 = base64::encode(self.to_der()?);
        let key_ty = if self.is_private() {
            "PRIVATE"
        } else {
            "PUBLIC"
        };
        let mut pem = String::new();
        writeln!(&mut pem, "-----BEGIN {} KEY-----", key_ty).unwrap();
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

    /// Generates a new symmetric key with the specified number of bits.
    /// Best used with one of the HS algorithms (e.g., HS256).
    #[cfg(feature = "generate")]
    pub fn generate_symmetric(num_bits: usize) -> Self {
        use rand::RngCore;
        let mut bytes = Vec::with_capacity(num_bits / 8);
        rand::thread_rng().fill_bytes(&mut bytes);
        Self::Symmetric { key: bytes.into() }
    }

    /// Generates a new EC keypair using the prime256 curve.
    /// Used with the ES256 algorithm.
    #[cfg(feature = "generate")]
    pub fn generate_p256() -> Self {
        use p256::elliptic_curve::generic_array::GenericArray;
        use rand::RngCore;

        let mut sk_bytes = GenericArray::default();
        rand::thread_rng().fill_bytes(&mut sk_bytes);
        let sk = p256::SecretKey::new(sk_bytes);
        let sk_scalar = p256::arithmetic::Scalar::from_secret(sk).unwrap();

        let pk = p256::arithmetic::ProjectivePoint::generator() * &sk_scalar;
        let pk_bytes = &pk
            .to_affine()
            .unwrap()
            .to_uncompressed_pubkey()
            .into_bytes()[1..];
        let (x_bytes, y_bytes) = pk_bytes.split_at(32);

        Self::EC {
            curve: Curve::P256 {
                d: Some(sk_scalar.to_bytes().into()),
                x: ByteArray::try_from_slice(x_bytes).unwrap(),
                y: ByteArray::try_from_slice(y_bytes).unwrap(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPublic {
    /// Public exponent. Must be 65537.
    pub e: PublicExponent,
    /// Modulus, p*q.
    pub n: ByteVec,
}

const PUBLIC_EXPONENT: u32 = 65537;
const PUBLIC_EXPONENT_B64: &str = "AQAB"; // little-endian, strip zeros
const PUBLIC_EXPONENT_B64_PADDED: &str = "AQABAA==";
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum JsonWebAlgorithm {
    HS256,
    RS256,
    ES256,
}

#[cfg(any(test, feature = "jsonwebtoken"))]
impl Into<jsonwebtoken::Algorithm> for JsonWebAlgorithm {
    fn into(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::HS256 => jsonwebtoken::Algorithm::HS256,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
        }
    }
}

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
pub enum PkcsConvertError {
    #[error("encoding RSA JWK as PKCS#8 requires specifing all of p, q, dp, dq, qi")]
    MissingRsaParams,

    #[error("a symmetric key can not be encoded using PKCS#8")]
    NotAsymmetric,
}
