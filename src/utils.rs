use serde::{
    de::{self, Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use zeroize::Zeroizing;

fn base64_config() -> base64::Config {
    base64::Config::new(base64::CharacterSet::UrlSafe, true /* pad */)
}

fn base64_encode(bytes: impl AsRef<[u8]>) -> String {
    base64::encode_config(bytes, base64_config())
}

fn base64_decode(b64: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(b64, base64_config())
}

pub fn serialize_base64<S: Serializer>(bytes: impl AsRef<[u8]>, s: S) -> Result<S::Ok, S::Error> {
    base64_encode(bytes).serialize(s)
}

pub fn deserialize_base64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let base64_str = Zeroizing::new(String::deserialize(d)?);
    base64_decode(&*base64_str).map_err(|e| {
        #[cfg(debug_assertions)]
        let err_msg = e.to_string().to_lowercase();
        #[cfg(not(debug_assertions))]
        let err_msg = "invalid base64";
        de::Error::custom(err_msg.strip_suffix(".").unwrap_or(&err_msg))
    })
}
