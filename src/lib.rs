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
        use Key::*;
        let alg = match &jwk.algorithm {
            Some(alg) => alg,
            None => return Ok(jwk),
        };
        match (alg, &*jwk.key) {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Key {
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

impl Key {
    /// Returns true iff this key only contains private components (i.e. a private asymmetric
    /// key or a symmetric key).
    fn is_private(&self) -> bool {
        match self {
            Self::Symmetric { .. }
            | Self::EC {
                params: Curve::P256 { d: Some(_), .. },
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
                params: Curve::P256 { x, y, .. },
            } => Self::EC {
                params: Curve::P256 {
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
    #[cfg(feature = "conversion")]
    pub fn to_der(&self) -> Option<Vec<u8>> {
        use yasna::{models::ObjectIdentifier, DERWriter, DERWriterSeq, Tag};

        if let Self::Symmetric { .. } = self {
            return None;
        }
        Some(yasna::construct_der(|writer| match self {
            Self::EC {
                params: Curve::P256 { d, x, y },
            } => {
                let write_curve_oid = |writer: DERWriter| {
                    writer.write_oid(&ObjectIdentifier::from_slice(&[
                        1, 2, 840, 10045, 3, 1, 7, // prime256v1
                    ]));
                };
                let write_public = |writer: DERWriter| {
                    let public_bytes: Vec<u8> = [0x04 /* uncompressed */]
                        .iter()
                        .chain(x.iter())
                        .chain(y.iter())
                        .copied()
                        .collect();
                    writer.write_bitvec_bytes(&public_bytes, 8 * (32 * 2 + 1));
                };
                writer.write_sequence(|writer| {
                    match d {
                        Some(private_point) => {
                            writer.next().write_i8(1); // version
                            writer.next().write_bytes(private_point.as_ref());
                            writer.next().write_tagged(Tag::context(0), |writer| {
                                write_curve_oid(writer);
                            });
                            writer.next().write_tagged(Tag::context(1), |writer| {
                                write_public(writer);
                            });
                        }
                        None => {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                                    1, 2, 840, 10045, 2, 1, // ecPublicKey
                                ]));
                                write_curve_oid(writer.next());
                            });
                            write_public(writer.next());
                        }
                    };
                });
            }
            Self::RSA { public, private } => {
                let write_alg_id = |writer: &mut DERWriterSeq| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                        1, 2, 840, 113549, 1, 1, 1, // rsaEncryption
                    ]));
                    writer.next().write_null(); // parameters
                };
                let write_public = |writer: &mut DERWriterSeq| {
                    writer.next().write_bytes(&*public.n);
                    writer.next().write_u32(PUBLIC_EXPONENT);
                };
                writer.write_sequence(|writer| {
                    match private {
                        Some(private) => {
                            writer.next().write_i8(0); // version
                            writer.next().write_sequence(|writer| {
                                write_alg_id(writer);
                            });
                            writer
                                .next()
                                .write_tagged(yasna::tags::TAG_OCTETSTRING, |writer| {
                                    writer.write_sequence(|writer| {
                                        writer.next().write_i8(0); // version
                                        write_public(writer);
                                        writer.next().write_bytes(&private.d);
                                        if let Some(p) = &private.p {
                                            writer.next().write_bytes(p);
                                        }
                                        if let Some(q) = &private.q {
                                            writer.next().write_bytes(q);
                                        }
                                        if let Some(dp) = &private.dp {
                                            writer.next().write_bytes(dp);
                                        }
                                        if let Some(dq) = &private.dq {
                                            writer.next().write_bytes(dq);
                                        }
                                        if let Some(qi) = &private.qi {
                                            writer.next().write_bytes(qi);
                                        }
                                    });
                                });
                        }
                        None => {
                            write_alg_id(writer);
                            writer
                                .next()
                                .write_tagged(yasna::tags::TAG_BITSTRING, |writer| {
                                    writer.write_sequence(|writer| {
                                        write_public(writer);
                                    })
                                });
                        }
                    }
                });
            }
            Self::Symmetric { .. } => unreachable!("checked above"),
        }))
    }

    /// If this key is asymmetric, encodes it as PKCS#8 with PEM armoring.
    #[cfg(feature = "conversion")]
    pub fn to_pem(&self) -> Option<String> {
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
        Some(pem)
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
