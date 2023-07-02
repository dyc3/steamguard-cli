use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, InvalidLength, KeyIvInit};
use aes::Aes256;
use ring::pbkdf2;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "keyring")]
mod keyring;

#[cfg(feature = "keyring")]
pub use crate::encryption::keyring::*;

const SALT_LENGTH: usize = 8;
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
	/// Encryption scheme that is compatible with SteamDesktopAuthenticator.
	LegacySdaCompatible = -1,
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

/// Encryption scheme that is compatible with SteamDesktopAuthenticator.
pub struct LegacySdaCompatible;

impl LegacySdaCompatible {
	const PBKDF2_ITERATIONS: u32 = 50000; // This is necessary to maintain compatibility with SteamDesktopAuthenticator.
	const KEY_SIZE_BYTES: usize = 32;

	fn get_encryption_key(passkey: &str, salt: &str) -> anyhow::Result<[u8; Self::KEY_SIZE_BYTES]> {
		let password_bytes = passkey.as_bytes();
		let salt_bytes = base64::decode(salt)?;
		let mut full_key: [u8; Self::KEY_SIZE_BYTES] = [0u8; Self::KEY_SIZE_BYTES];
		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA1,
			std::num::NonZeroU32::new(Self::PBKDF2_ITERATIONS).unwrap(),
			&salt_bytes,
			password_bytes,
			&mut full_key,
		);
		Ok(full_key)
	}
}

impl EntryEncryptor for LegacySdaCompatible {
	fn encrypt(
		passkey: &str,
		params: &EntryEncryptionParams,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let key = Self::get_encryption_key(passkey, &params.salt)?;
		let mut iv = [0u8; IV_LENGTH];
		base64::decode_config_slice(&params.iv, base64::STANDARD, &mut iv)?;

		let cipher = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)?;

		let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&plaintext);

		let encoded = base64::encode(ciphertext);
		Ok(encoded.as_bytes().to_vec())
	}

	fn decrypt(
		passkey: &str,
		params: &EntryEncryptionParams,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let key = Self::get_encryption_key(passkey, &params.salt)?;
		let mut iv = [0u8; IV_LENGTH];
		base64::decode_config_slice(&params.iv, base64::STANDARD, &mut iv)?;
		let cipher = cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv)?;
		let decoded = base64::decode(ciphertext)?;
		let size: usize = decoded.len() / 16 + (if decoded.len() % 16 == 0 { 0 } else { 1 });
		let mut buffer = vec![0xffu8; 16 * size];
		buffer[..decoded.len()].copy_from_slice(&decoded);
		let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)?;
		Ok(decrypted.to_vec())
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

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	/// This test ensures compatibility with SteamDesktopAuthenticator and with previous versions of steamguard-cli
	#[test]
	fn test_encryption_key() {
		assert_eq!(
			LegacySdaCompatible::get_encryption_key("password", "GMhL0N2hqXg=")
				.unwrap()
				.as_slice(),
			base64::decode("KtiRa4/OxW83MlB6URf+Z8rAGj7CBY+pDlwD/NuVo6Y=")
				.unwrap()
				.as_slice()
		);

		assert_eq!(
			LegacySdaCompatible::get_encryption_key("password", "wTzTE9A6aN8=")
				.unwrap()
				.as_slice(),
			base64::decode("Dqpej/3DqEat0roJaHmu3luYgDzRCUmzX94n4fqvWj8=")
				.unwrap()
				.as_slice()
		);
	}

	#[test]
	fn test_ensure_encryption_symmetric() -> anyhow::Result<()> {
		let cases = [
			"foo",
			"tactical glizzy",
			"glizzy gladiator",
			"shadow wizard money gang",
			"shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells, shadow wizard money gang, we love casting spells",
		];
		let passkey = "password";
		let params = EntryEncryptionParams::generate();
		for case in cases {
			eprintln!("testing case: {} (len {})", case, case.len());
			let orig = case.as_bytes().to_vec();
			let encrypted = LegacySdaCompatible::encrypt(passkey, &params, orig.clone()).unwrap();
			let result = LegacySdaCompatible::decrypt(passkey, &params, encrypted).unwrap();
			assert_eq!(orig, result.to_vec());
		}
		Ok(())
	}

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
