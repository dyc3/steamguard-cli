use aes::cipher::InvalidLength;

use rand::Rng;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "scheme")]
pub enum EncryptionScheme {
	Argon2idAes256(Argon2idAes256),
	LegacySdaCompatible(LegacySdaCompatible),
}

pub trait EntryEncryptor {
	fn generate() -> Self;
	fn encrypt(
		&self,
		passkey: &str,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError>;
	fn decrypt(
		&self,
		passkey: &str,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError>;
}

impl EntryEncryptor for EncryptionScheme {
	fn generate() -> Self {
		EncryptionScheme::Argon2idAes256(Argon2idAes256::generate())
	}

	fn encrypt(
		&self,
		passkey: &str,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		match self {
			EncryptionScheme::Argon2idAes256(scheme) => scheme.encrypt(passkey, plaintext),
			EncryptionScheme::LegacySdaCompatible(scheme) => scheme.encrypt(passkey, plaintext),
		}
	}

	fn decrypt(
		&self,
		passkey: &str,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		match self {
			EncryptionScheme::Argon2idAes256(scheme) => scheme.decrypt(passkey, ciphertext),
			EncryptionScheme::LegacySdaCompatible(scheme) => scheme.decrypt(passkey, ciphertext),
		}
	}
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
