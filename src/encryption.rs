use aes::Aes256;
use block_modes::block_padding::{NoPadding, Padding, Pkcs7};
use block_modes::{BlockMode, Cbc};
use ring::pbkdf2;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const PBKDF2_ITERATIONS: u32 = 50000; // This is excessive, but necessary to maintain compatibility with SteamDesktopAuthenticator.
const SALT_LENGTH: usize = 8;
const KEY_SIZE_BYTES: usize = 32;
const IV_LENGTH: usize = 16;

fn get_encryption_key(passkey: &String, salt: &String) -> anyhow::Result<[u8; KEY_SIZE_BYTES]> {
	let password_bytes = passkey.as_bytes();
	let salt_bytes = base64::decode(salt)?;
	let mut full_key: [u8; KEY_SIZE_BYTES] = [0u8; KEY_SIZE_BYTES];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA1,
		std::num::NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
		&salt_bytes,
		password_bytes,
		&mut full_key,
	);
	return Ok(full_key);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryEncryptionParams {
	#[serde(rename = "encryption_iv")]
	pub iv: String,
	#[serde(rename = "encryption_salt")]
	pub salt: String,
	#[serde(default, rename = "encryption_scheme")]
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
	LegacySdaCompatible = 0,
}

impl Default for EncryptionScheme {
	fn default() -> Self {
		Self::LegacySdaCompatible
	}
}

pub trait EntryEncryptor {
	fn encrypt(
		passkey: &String,
		params: &EntryEncryptionParams,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError>;
	fn decrypt(
		passkey: &String,
		params: &EntryEncryptionParams,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError>;
}

/// Encryption scheme that is compatible with SteamDesktopAuthenticator.
pub struct LegacySdaCompatible;

type Aes256Cbc = Cbc<Aes256, NoPadding>;
impl EntryEncryptor for LegacySdaCompatible {
	// ngl, this logic sucks ass. its kinda annoying that the logic is not completely symetric.

	fn encrypt(
		passkey: &String,
		params: &EntryEncryptionParams,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let key = get_encryption_key(&passkey.into(), &params.salt)?;
		let iv = base64::decode(&params.iv)?;
		let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;

		let origsize = plaintext.len();
		let buffersize: usize = (origsize / 16 + (if origsize % 16 == 0 { 0 } else { 1 })) * 16;
		let mut buffer = vec![];
		for chunk in plaintext.as_slice().chunks(256) {
			let chunksize = chunk.len();
			let buffersize = (chunksize / 16 + (if chunksize % 16 == 0 { 0 } else { 1 })) * 16;
			let mut chunkbuffer = vec![0xffu8; buffersize];
			chunkbuffer[..chunksize].copy_from_slice(&chunk);
			if buffersize != chunksize {
				chunkbuffer = Pkcs7::pad(&mut chunkbuffer, chunksize, buffersize)
					.unwrap()
					.to_vec();
			}
			buffer.append(&mut chunkbuffer);
		}
		let ciphertext = cipher.encrypt(&mut buffer, buffersize)?;
		let final_buffer = base64::encode(&ciphertext);
		return Ok(final_buffer.as_bytes().to_vec());
	}

	fn decrypt(
		passkey: &String,
		params: &EntryEncryptionParams,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let key = get_encryption_key(&passkey.into(), &params.salt)?;
		let iv = base64::decode(&params.iv)?;
		let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;

		let decoded = base64::decode(ciphertext)?;
		let size: usize = decoded.len() / 16 + (if decoded.len() % 16 == 0 { 0 } else { 1 });
		let mut buffer = vec![0xffu8; 16 * size];
		buffer[..decoded.len()].copy_from_slice(&decoded);
		let mut decrypted = cipher.decrypt(&mut buffer)?;
		if decrypted[0] != '{' as u8 && decrypted[decrypted.len() - 1] != '}' as u8 {
			return Err(EntryEncryptionError::IncorrectPasskey);
		}
		let unpadded = Pkcs7::unpad(&mut decrypted)?;
		return Ok(unpadded.to_vec());
	}
}

#[derive(Debug, Error)]
pub enum EntryEncryptionError {
	#[error("Incorrect passkey provided.")]
	IncorrectPasskey,
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

/// For some reason, these errors do not get converted to `ManifestAccountLoadError`s, even though they get converted into `anyhow::Error` just fine. I am too lazy to figure out why right now.
impl From<block_modes::BlockModeError> for EntryEncryptionError {
	fn from(error: block_modes::BlockModeError) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}
impl From<block_modes::InvalidKeyIvLength> for EntryEncryptionError {
	fn from(error: block_modes::InvalidKeyIvLength) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}
impl From<block_modes::block_padding::PadError> for EntryEncryptionError {
	fn from(error: block_modes::block_padding::PadError) -> Self {
		return Self::Unknown(anyhow!("PadError"));
	}
}
impl From<block_modes::block_padding::UnpadError> for EntryEncryptionError {
	fn from(error: block_modes::block_padding::UnpadError) -> Self {
		return Self::Unknown(anyhow!("UnpadError"));
	}
}
impl From<base64::DecodeError> for EntryEncryptionError {
	fn from(error: base64::DecodeError) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}
impl From<std::io::Error> for EntryEncryptionError {
	fn from(error: std::io::Error) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// This test ensures compatibility with SteamDesktopAuthenticator and with previous versions of steamguard-cli
	#[test]
	fn test_encryption_key() {
		assert_eq!(
			get_encryption_key(&"password".into(), &"GMhL0N2hqXg=".into()).unwrap(),
			base64::decode("KtiRa4/OxW83MlB6URf+Z8rAGj7CBY+pDlwD/NuVo6Y=")
				.unwrap()
				.as_slice()
		);

		assert_eq!(
			get_encryption_key(&"password".into(), &"wTzTE9A6aN8=".into()).unwrap(),
			base64::decode("Dqpej/3DqEat0roJaHmu3luYgDzRCUmzX94n4fqvWj8=")
				.unwrap()
				.as_slice()
		);
	}
}
