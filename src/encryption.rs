use aes::cipher::InvalidLength;

use rand::Rng;

use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod argon2id_aes;
#[cfg(feature = "keyring")]
mod keyring;
mod legacy;

pub use argon2id_aes::*;
pub use legacy::*;

#[cfg(feature = "keyring")]
pub use crate::encryption::keyring::*;

#[deprecated = "Salt length needs to be provided by the scheme"]
const SALT_LENGTH: usize = 8;
#[deprecated = "IV length needs to be provided by the scheme"]
const IV_LENGTH: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryEncryptionParams {
	pub iv: String,
	pub salt: String,
	pub scheme: EncryptionScheme,
}

impl EntryEncryptionParams {
	pub fn generate() -> EntryEncryptionParams {
		let rng = ring::rand::SystemRandom::new();
		let mut salt = [0u8; SALT_LENGTH];
		let mut iv = [0u8; IV_LENGTH];
		rng.fill(&mut salt).expect("Unable to generate salt.");
		rng.fill(&mut iv).expect("Unable to generate IV.");
		EntryEncryptionParams {
			salt: base64::encode(salt),
			iv: base64::encode(iv),
			scheme: Default::default(),
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionScheme {
	Argon2idAes256,
	/// Encryption scheme that is compatible with SteamDesktopAuthenticator.
	LegacySdaCompatible,
}

impl Default for EncryptionScheme {
	fn default() -> Self {
		Self::LegacySdaCompatible
	}
}

pub trait EntryEncryptor {
	fn encrypt(
		passkey: &str,
		params: &EntryEncryptionParams,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError>;
	fn decrypt(
		passkey: &str,
		params: &EntryEncryptionParams,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError>;
}

#[derive(Debug, Error)]
pub enum EntryEncryptionError {
	#[error("Invalid ciphertext length. The ciphertext must be a multiple of 16 bytes.")]
	InvalidCipherTextLength,
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

/// For some reason, these errors do not get converted to `ManifestAccountLoadError`s, even though they get converted into `anyhow::Error` just fine. I am too lazy to figure out why right now.
impl From<InvalidLength> for EntryEncryptionError {
	fn from(error: InvalidLength) -> Self {
		Self::Unknown(anyhow::Error::from(error))
	}
}

impl From<inout::NotEqualError> for EntryEncryptionError {
	fn from(error: inout::NotEqualError) -> Self {
		Self::Unknown(anyhow::Error::from(error))
	}
}

impl From<inout::PadError> for EntryEncryptionError {
	fn from(error: inout::PadError) -> Self {
		Self::Unknown(anyhow::Error::from(error))
	}
}

impl From<inout::block_padding::UnpadError> for EntryEncryptionError {
	fn from(error: inout::block_padding::UnpadError) -> Self {
		Self::Unknown(anyhow::Error::from(error))
	}
}

impl From<base64::DecodeError> for EntryEncryptionError {
	fn from(error: base64::DecodeError) -> Self {
		Self::Unknown(anyhow::Error::from(error))
	}
}
impl From<std::io::Error> for EntryEncryptionError {
	fn from(error: std::io::Error) -> Self {
		Self::Unknown(anyhow::Error::from(error))
	}
}

pub fn generate_keyring_id() -> String {
	let rng = rand::thread_rng();
	rng.sample_iter(rand::distributions::Alphanumeric)
		.take(32)
		.map(char::from)
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	prop_compose! {
		/// An insecure but reproducible strategy for generating encryption params.
		fn encryption_params()(salt in any::<[u8; SALT_LENGTH]>(), iv in any::<[u8; IV_LENGTH]>()) -> EntryEncryptionParams {
			EntryEncryptionParams {
				salt: base64::encode(salt),
				iv: base64::encode(iv),
				scheme: EncryptionScheme::LegacySdaCompatible,
			}
		}
	}

	// proptest! {
	// 	#[test]
	// 	fn ensure_encryption_symmetric(
	// 		passkey in ".{1,}",
	// 		params in encryption_params(),
	// 		data in any::<Vec<u8>>(),
	// 	) {
	// 		prop_assume!(data.len() >= 2);
	// 		let mut orig = data;
	// 		orig[0] = '{' as u8;
	// 		let n = orig.len() - 1;
	// 		orig[n] = '}' as u8;
	// 		let encrypted = LegacySdaCompatible::encrypt(&passkey.clone().into(), &params, orig.clone()).unwrap();
	// 		let result = LegacySdaCompatible::decrypt(&passkey.into(), &params, encrypted).unwrap();
	// 		prop_assert_eq!(orig, result.to_vec());
	// 	}
	// }
}
