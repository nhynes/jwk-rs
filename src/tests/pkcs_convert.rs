use super::*;

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

#[test]
fn oct_to_pem() {
    let jwk = JsonWebKey::from_str(OCT_JWK_FIXTURE).unwrap();
    assert!(jwk.key.try_to_pem().is_err());
}

#[test]
fn oct_to_public() {
    let jwk = JsonWebKey::from_str(OCT_JWK_FIXTURE).unwrap();
    assert!(jwk.key.to_public().is_none());
}
