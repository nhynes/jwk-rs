use generic_array::{ArrayLength, GenericArray};
use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize,
};
use zeroize::{Zeroize, Zeroizing};

/// A zeroizing-on-drop container for a `[u8; N]` that deserializes from base64.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ByteArray<N: ArrayLength<u8>>(
    #[serde(serialize_with = "crate::utils::serde_base64::serialize")] GenericArray<u8, N>,
);

impl<N: ArrayLength<u8>> std::fmt::Debug for ByteArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::utils::base64_encode(&self.0))
    }
}

impl<N: ArrayLength<u8>, T: Into<GenericArray<u8, N>>> From<T> for ByteArray<N> {
    fn from(arr: T) -> Self {
        Self(arr.into())
    }
}

impl<N: ArrayLength<u8>> Drop for ByteArray<N> {
    fn drop(&mut self) {
        Zeroize::zeroize(self.0.as_mut_slice())
    }
}

impl<N: ArrayLength<u8>> AsRef<[u8]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<N: ArrayLength<u8>> std::ops::Deref for ByteArray<N> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: ArrayLength<u8>> ByteArray<N> {
    /// An unwrapping version of `try_from_slice`.
    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Self {
        Self::try_from_slice(bytes).unwrap()
    }

    pub fn try_from_slice(bytes: impl AsRef<[u8]>) -> Result<Self, String> {
        let bytes = bytes.as_ref();
        if bytes.len() != N::USIZE {
            Err(format!(
                "expected {} bytes but got {}",
                N::USIZE,
                bytes.len()
            ))
        } else {
            Ok(Self(GenericArray::clone_from_slice(bytes)))
        }
    }
}

impl<'de, N: ArrayLength<u8>> Deserialize<'de> for ByteArray<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Zeroizing::new(crate::utils::serde_base64::deserialize(d)?);
        Self::try_from_slice(&*bytes).map_err(|_| {
            de::Error::invalid_length(
                bytes.len(),
                &format!("{} base64-encoded bytes", N::USIZE).as_str(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::*;

    static BYTES: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
    static BASE64_JSON: &str = "\"AQIDBAUGBw\"";

    fn get_de() -> serde_json::Deserializer<serde_json::de::StrRead<'static>> {
        serde_json::Deserializer::from_str(BASE64_JSON)
    }

    #[test]
    fn test_serde_byte_array_good() {
        let arr = ByteArray::<U7>::try_from_slice(BYTES).unwrap();
        let b64 = serde_json::to_string(&arr).unwrap();
        assert_eq!(b64, BASE64_JSON);
        let bytes: ByteArray<U7> = serde_json::from_str(&b64).unwrap();
        assert_eq!(bytes.as_ref(), BYTES);
    }

    #[test]
    fn test_serde_deserialize_byte_array_invalid() {
        let mut de = serde_json::Deserializer::from_str("\"Z\"");
        ByteArray::<U0>::deserialize(&mut de).unwrap_err();
    }

    #[test]
    fn test_serde_base64_deserialize_array_long() {
        ByteArray::<U6>::deserialize(&mut get_de()).unwrap_err();
    }

    #[test]
    fn test_serde_base64_deserialize_array_short() {
        ByteArray::<U8>::deserialize(&mut get_de()).unwrap_err();
    }
}
