use super::*;

use std::str::FromStr;

use crate::byte_array::ByteArray;

// Generated using https://mkjwk.org
static P256_JWK_FIXTURE: &str = r#"{
        "kty": "EC",
        "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
        "use": "enc",
        "crv": "P-256",
        "kid": "a key",
        "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
        "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k",
        "alg": "ES256"
    }"#;

static RSA_JWK_FIXTURE: &str = r#"{
        "p": "6AQ4yHef17an_i5LQPHNIxzpH65xWOSf_qCB7q-lXyM",
        "kty": "RSA",
        "q": "tSVfpefCsf1iWmAs1zYvxdEsUiv0VMEuQBtbTijj_OE",
        "d": "Qdp8a8Df5TlMaaloXApNF_3eu8sLHNWbXdg70e5YVTAs0WUfaIf5c3n96RrDDAzmMEwgKnJ7A1NJ9Nlzz4Z0AQ",
        "e": "AQAB",
        "use": "enc",
        "qi": "adhQHH8IGXFfLEMnZ5t_TeCp5zgSwQktJ2lmylxUG0M",
        "dp": "qVnLiKeoSG_Olz17OGBGd4a2sqVFnrjh_51wuaQDdTk",
        "dq": "GL_Ec6xYg2z1FRfyyGyU1lgf0BJFTZcfNI8ISIN5ssE",
        "key_ops": ["wrapKey"],
        "n": "pCzbcd9kjvg5rfGHdEMWnXo49zbB6FLQ-m0B0BvVp0aojVWYa0xujC-ZP7ZhxByPxyc2PazwFJJi9ivZ_ggRww"
    }"#;

#[cfg(feature = "pkcs-convert")]
static OCT_FIXTURE: &str = r#"{
        "kty": "oct",
        "k": "TdSBZdXL5n39JXlQc7QL3w"
    }"#;

#[test]
fn deserialize_es256() {
    let jwk = JsonWebKey::from_str(P256_JWK_FIXTURE).unwrap();
    assert_eq!(
        jwk,
        JsonWebKey {
            key: Box::new(Key::EC {
                // The parameters were decoded using a 10-liner Rust script.
                curve: Curve::P256 {
                    d: Some(ByteArray::from_slice(&[
                        102, 130, 144, 246, 62, 29, 132, 128, 101, 49, 21, 107, 191, 228, 6, 240,
                        255, 211, 246, 203, 173, 191, 127, 253, 229, 232, 168, 244, 203, 105, 128,
                        168
                    ])),
                    x: ByteArray::from_slice(&[
                        64, 227, 7, 154, 255, 122, 181, 89, 73, 191, 235, 141, 170, 154, 231, 13,
                        34, 136, 143, 144, 34, 45, 53, 202, 70, 137, 151, 98, 118, 175, 208, 221
                    ]),
                    y: ByteArray::from_slice(&[
                        78, 54, 25, 160, 121, 220, 181, 171, 68, 19, 163, 66, 172, 169, 151, 65,
                        210, 73, 62, 115, 115, 100, 69, 252, 156, 25, 153, 117, 237, 192, 99, 137
                    ])
                },
            }),
            algorithm: Some(Algorithm::ES256),
            key_id: Some("a key".into()),
            key_ops: KeyOps::empty(),
            key_use: Some(KeyUse::Encryption),
            x5: Default::default(),
        }
    );
}

#[test]
fn serialize_es256() {
    let jwk = JsonWebKey {
        key: Box::new(Key::EC {
            curve: Curve::P256 {
                d: None,
                x: ByteArray::from_slice(&[1u8; 32]),
                y: ByteArray::from_slice(&[2u8; 32]),
            },
        }),
        key_id: None,
        algorithm: None,
        key_ops: KeyOps::empty(),
        key_use: None,
        x5: Default::default(),
    };
    assert_eq!(
        jwk.to_string(),
        r#"{"kty":"EC","crv":"P-256","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","y":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}"#
    );
}

#[cfg(all(feature = "jwt-convert", feature = "generate"))]
#[test]
fn generate_p256() {
    extern crate jsonwebtoken as jwt;

    #[derive(Serialize, Deserialize)]
    struct TokenClaims {
        exp: usize,
    }

    let mut the_jwk = JsonWebKey::new(Key::generate_p256());
    the_jwk.set_algorithm(Algorithm::ES256).unwrap();

    let encoding_key = jwt::EncodingKey::from_ec_der(&the_jwk.key.to_der());
    let token = jwt::encode(
        &jwt::Header::new(the_jwk.algorithm.unwrap().into()),
        &TokenClaims { exp: 0 },
        &encoding_key,
    )
    .unwrap();

    let mut validation = jwt::Validation::new(the_jwk.algorithm.unwrap().into());
    validation.validate_exp = false;
    let public_pem = the_jwk.key.to_public().unwrap().to_pem();
    let decoding_key = jwt::DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap();
    jwt::decode::<TokenClaims>(&token, &decoding_key, &validation).unwrap();
}

#[test]
fn deserialize_hs256() {
    let jwk_str = r#"{
        "kty": "oct",
        "k": "tAON6Q",
        "alg": "HS256",
        "key_ops": ["verify", "sign"]
    }"#;
    let jwk = JsonWebKey::from_str(jwk_str).unwrap();
    assert_eq!(
        jwk,
        JsonWebKey {
            key: Box::new(Key::Symmetric {
                // The parameters were decoded using a 10-liner Rust script.
                key: vec![180, 3, 141, 233].into(),
            }),
            algorithm: Some(Algorithm::HS256),
            key_id: None,
            key_ops: KeyOps::SIGN | KeyOps::VERIFY,
            key_use: None,
            x5: Default::default(),
        }
    );
}

#[test]
fn serialize_hs256() {
    let jwk = JsonWebKey {
        key: Box::new(Key::Symmetric {
            key: vec![42; 16].into(),
        }),
        key_id: None,
        algorithm: None,
        key_ops: KeyOps::empty(),
        key_use: None,
        x5: Default::default(),
    };
    assert_eq!(
        jwk.to_string(),
        r#"{"kty":"oct","k":"KioqKioqKioqKioqKioqKg"}"#
    );
}

#[test]
fn deserialize_rs256() {
    let jwk = JsonWebKey::from_str(RSA_JWK_FIXTURE).unwrap();
    assert_eq!(
        jwk,
        JsonWebKey {
            key: Box::new(Key::RSA {
                public: RsaPublic {
                    e: PublicExponent,
                    n: vec![
                        164, 44, 219, 113, 223, 100, 142, 248, 57, 173, 241, 135, 116, 67, 22, 157,
                        122, 56, 247, 54, 193, 232, 82, 208, 250, 109, 1, 208, 27, 213, 167, 70,
                        168, 141, 85, 152, 107, 76, 110, 140, 47, 153, 63, 182, 97, 196, 28, 143,
                        199, 39, 54, 61, 172, 240, 20, 146, 98, 246, 43, 217, 254, 8, 17, 195
                    ]
                    .into()
                },
                private: Some(RsaPrivate {
                    d: vec![
                        65, 218, 124, 107, 192, 223, 229, 57, 76, 105, 169, 104, 92, 10, 77, 23,
                        253, 222, 187, 203, 11, 28, 213, 155, 93, 216, 59, 209, 238, 88, 85, 48,
                        44, 209, 101, 31, 104, 135, 249, 115, 121, 253, 233, 26, 195, 12, 12, 230,
                        48, 76, 32, 42, 114, 123, 3, 83, 73, 244, 217, 115, 207, 134, 116, 1
                    ]
                    .into(),
                    p: Some(
                        vec![
                            232, 4, 56, 200, 119, 159, 215, 182, 167, 254, 46, 75, 64, 241, 205,
                            35, 28, 233, 31, 174, 113, 88, 228, 159, 254, 160, 129, 238, 175, 165,
                            95, 35
                        ]
                        .into()
                    ),
                    q: Some(
                        vec![
                            181, 37, 95, 165, 231, 194, 177, 253, 98, 90, 96, 44, 215, 54, 47, 197,
                            209, 44, 82, 43, 244, 84, 193, 46, 64, 27, 91, 78, 40, 227, 252, 225
                        ]
                        .into()
                    ),
                    dp: Some(
                        vec![
                            169, 89, 203, 136, 167, 168, 72, 111, 206, 151, 61, 123, 56, 96, 70,
                            119, 134, 182, 178, 165, 69, 158, 184, 225, 255, 157, 112, 185, 164, 3,
                            117, 57
                        ]
                        .into()
                    ),
                    dq: Some(
                        vec![
                            24, 191, 196, 115, 172, 88, 131, 108, 245, 21, 23, 242, 200, 108, 148,
                            214, 88, 31, 208, 18, 69, 77, 151, 31, 52, 143, 8, 72, 131, 121, 178,
                            193
                        ]
                        .into()
                    ),
                    qi: Some(
                        vec![
                            105, 216, 80, 28, 127, 8, 25, 113, 95, 44, 67, 39, 103, 155, 127, 77,
                            224, 169, 231, 56, 18, 193, 9, 45, 39, 105, 102, 202, 92, 84, 27, 67
                        ]
                        .into()
                    )
                })
            }),
            algorithm: None,
            key_id: None,
            key_ops: KeyOps::WRAP_KEY,
            key_use: Some(KeyUse::Encryption),
            x5: Default::default(),
        }
    );
}

#[test]
fn serialize_rs256() {
    let jwk = JsonWebKey {
        key: Box::new(Key::RSA {
            public: RsaPublic {
                e: PublicExponent,
                n: vec![105, 183, 62].into(),
            },
            private: Some(RsaPrivate {
                d: vec![105, 183, 63].into(),
                p: None,
                q: None,
                dp: None,
                dq: None,
                qi: None,
            }),
        }),
        key_id: None,
        algorithm: None,
        key_ops: KeyOps::empty(),
        key_use: None,
        x5: Default::default(),
    };
    assert_eq!(
        jwk.to_string(),
        r#"{"kty":"RSA","e":"AQAB","n":"abc-","d":"abc_"}"#
    );
}

#[test]
fn mismatched_algorithm() {
    macro_rules! assert_mismatched_alg {
        ($jwk_str:literal) => {
            match JsonWebKey::from_str($jwk_str) {
                Err(Error::MismatchedAlgorithm) => {}
                v => panic!("expected MismatchedAlgorithm, got {:?}", v),
            }
        };
    }

    assert_mismatched_alg!(r#"{ "kty": "oct", "k": "tAON6Q", "alg": "ES256" }"#);
    assert_mismatched_alg!(r#"{ "kty": "oct", "k": "tAON6Q", "alg": "RS256" }"#);

    assert_mismatched_alg!(
        r#"{
            "kty": "EC",
            "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
            "crv": "P-256",
            "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
            "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k",
            "alg": "RS256"
        }"#
    );
    assert_mismatched_alg!(
        r#"{
            "kty": "EC",
            "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
            "crv": "P-256",
            "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
            "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k",
            "alg": "HS256"
        }"#
    );
}

#[cfg(feature = "pkcs-convert")]
#[test]
fn p256_private_to_pem() {
    // generated using mkjwk, converted using node-jwk-to-pem, verified using openssl
    let jwk = JsonWebKey::from_str(P256_JWK_FIXTURE).unwrap();
    #[rustfmt::skip]
    assert_eq!(
        jwk.key.to_pem(),
"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZoKQ9j4dhIBlMRVr
v+QG8P/T9sutv3/95eio9MtpgKihRANCAARA4wea/3q1WUm/642qmucNIoiPkCIt
NcpGiZdidq/Q3U42GaB53LWrRBOjQqypl0HSST5zc2RF/JwZmXXtwGOJ
-----END PRIVATE KEY-----
"
    );
}

#[cfg(feature = "pkcs-convert")]
#[test]
fn p256_public_to_pem() {
    let jwk = JsonWebKey::from_str(P256_JWK_FIXTURE).unwrap();
    #[rustfmt::skip]
    assert_eq!(
        jwk.key.to_public().unwrap().to_pem(),
"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQOMHmv96tVlJv+uNqprnDSKIj5Ai
LTXKRomXYnav0N1ONhmgedy1q0QTo0KsqZdB0kk+c3NkRfycGZl17cBjiQ==
-----END PUBLIC KEY-----
"
    );
}

#[cfg(feature = "pkcs-convert")]
#[test]
fn rsa_private_to_pem() {
    let jwk = JsonWebKey::from_str(RSA_JWK_FIXTURE).unwrap();
    #[rustfmt::skip]
    assert_eq!(
        jwk.key.to_pem(),
"-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEApCzbcd9kjvg5rfGH
dEMWnXo49zbB6FLQ+m0B0BvVp0aojVWYa0xujC+ZP7ZhxByPxyc2PazwFJJi9ivZ
/ggRwwIDAQABAkBB2nxrwN/lOUxpqWhcCk0X/d67ywsc1Ztd2DvR7lhVMCzRZR9o
h/lzef3pGsMMDOYwTCAqcnsDU0n02XPPhnQBAiEA6AQ4yHef17an/i5LQPHNIxzp
H65xWOSf/qCB7q+lXyMCIQC1JV+l58Kx/WJaYCzXNi/F0SxSK/RUwS5AG1tOKOP8
4QIhAKlZy4inqEhvzpc9ezhgRneGtrKlRZ644f+dcLmkA3U5AiAYv8RzrFiDbPUV
F/LIbJTWWB/QEkVNlx80jwhIg3mywQIgadhQHH8IGXFfLEMnZ5t/TeCp5zgSwQkt
J2lmylxUG0M=
-----END PRIVATE KEY-----
"
    );
}

#[cfg(feature = "pkcs-convert")]
#[test]
fn rsa_public_to_pem() {
    let jwk = JsonWebKey::from_str(RSA_JWK_FIXTURE).unwrap();
    assert_eq!(
        jwk.key.to_public().unwrap().to_pem(),
        "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKQs23HfZI74Oa3xh3RDFp16OPc2wehS
0PptAdAb1adGqI1VmGtMbowvmT+2YcQcj8cnNj2s8BSSYvYr2f4IEcMCAwEAAQ==
-----END PUBLIC KEY-----
"
    );
}

#[cfg(feature = "pkcs-convert")]
#[test]
fn oct_to_pem() {
    let jwk = JsonWebKey::from_str(OCT_FIXTURE).unwrap();
    assert!(jwk.key.try_to_pem().is_err());
}

#[cfg(feature = "pkcs-convert")]
#[test]
fn oct_to_public() {
    let jwk = JsonWebKey::from_str(OCT_FIXTURE).unwrap();
    assert!(jwk.key.to_public().is_none());
}

#[cfg(feature = "generate")]
#[test]
fn generate_oct() {
    let bits = 56;
    match Key::generate_symmetric(bits) {
        Key::Symmetric { key } if key.len() == 56 / 8 => {}
        k => panic!("`generate_symmetric` generated {:?}", k),
    }
}

#[test]
fn ec_is_private() {
    let private_jwk = JsonWebKey::from_str(P256_JWK_FIXTURE).unwrap();
    assert!(private_jwk.key.is_private());
    assert!(!private_jwk.key.to_public().unwrap().is_private());
    let mut k: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(P256_JWK_FIXTURE).unwrap();
    k.remove("d");
    let public_jwk = JsonWebKey::from_str(&serde_json::to_string(&k).unwrap()).unwrap();
    assert!(!public_jwk.key.is_private());
    assert!(!public_jwk.key.to_public().unwrap().is_private());
}

#[test]
fn rsa_is_private() {
    let private_jwk = JsonWebKey::from_str(RSA_JWK_FIXTURE).unwrap();
    assert!(private_jwk.key.is_private());
    assert!(!private_jwk.key.to_public().unwrap().is_private());

    static PUBLIC_RSA_JWK_FIXTURE: &str = r#"{
        "kty": "RSA",
        "e": "AQAB",
        "n": "pCzbcd9kjvg5rfGHdEMWnXo49zbB6FLQ-m0B0BvVp0aojVWYa0xujC-ZP7ZhxByPxyc2PazwFJJi9ivZ_ggRww"
    }"#;

    let public_jwk = JsonWebKey::from_str(PUBLIC_RSA_JWK_FIXTURE).unwrap();
    assert!(!public_jwk.key.is_private());
    assert!(!public_jwk.key.to_public().unwrap().is_private());
}

#[test]
fn x509_params() {
    let private_jwk = JsonWebKey::from_str(RSA_JWK_FIXTURE).unwrap();
    assert!(private_jwk.key.is_private());
    assert!(!private_jwk.key.to_public().unwrap().is_private());

    static X509_JWK_FIXTURE: &str = r#"{
        "kty": "oct",
        "k": "TdSBZdXL5n39JXlQc7QL3w",
        "x5u": "https://example.com/testing.crt",
        "x5c": ["---BEGIN CERTIFICATE---..."],
        "x5t": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "x5t#S256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }"#;

    let jwk = JsonWebKey::from_str(X509_JWK_FIXTURE).unwrap();
    assert_eq!(jwk.x5.url.unwrap(), "https://example.com/testing.crt");
    assert_eq!(
        jwk.x5.cert_chain.unwrap(),
        vec!["---BEGIN CERTIFICATE---..."]
    );
    assert_eq!(
        jwk.x5.thumbprint.unwrap(),
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    );
    assert_eq!(
        jwk.x5.thumbprint_sha256.unwrap(),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}
