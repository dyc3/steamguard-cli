use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;

use ring::pbkdf2;

use super::*;

/// Encryption scheme that is compatible with SteamDesktopAuthenticator.
pub struct LegacySdaCompatible;

impl LegacySdaCompatible {
	const PBKDF2_ITERATIONS: u32 = 50000; // This is necessary to maintain compatibility with SteamDesktopAuthenticator.
	const KEY_SIZE_BYTES: usize = 32;
	const IV_LENGTH: usize = 16;

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
		let mut iv = [0u8; Self::IV_LENGTH];
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
		let mut iv = [0u8; Self::IV_LENGTH];
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

#[cfg(test)]
mod tests {
	use super::*;

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
}
