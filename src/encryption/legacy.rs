use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use log::*;
use sha1::Sha1;

use super::*;

/// Encryption scheme that is compatible with SteamDesktopAuthenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacySdaCompatible {
	pub iv: String,
	pub salt: String,
}

impl LegacySdaCompatible {
	const PBKDF2_ITERATIONS: u32 = 50000; // This is necessary to maintain compatibility with SteamDesktopAuthenticator.
	const KEY_SIZE_BYTES: usize = 32;
	const SALT_LENGTH: usize = 8;
	const IV_LENGTH: usize = 16;

	fn get_encryption_key(passkey: &str, salt: &str) -> anyhow::Result<[u8; Self::KEY_SIZE_BYTES]> {
		let password_bytes = passkey.as_bytes();
		let salt_bytes = base64::decode(salt)?;
		let mut full_key: [u8; Self::KEY_SIZE_BYTES] = [0u8; Self::KEY_SIZE_BYTES];
		pbkdf2::pbkdf2_hmac::<Sha1>(
			password_bytes,
			&salt_bytes,
			Self::PBKDF2_ITERATIONS,
			&mut full_key,
		);
		Ok(full_key)
	}
}

impl EntryEncryptor for LegacySdaCompatible {
	fn generate() -> LegacySdaCompatible {
		let mut rng = rand::rngs::OsRng;
		let mut salt = [0u8; Self::SALT_LENGTH];
		let mut iv = [0u8; Self::IV_LENGTH];
		rng.fill(&mut salt);
		rng.fill(&mut iv);
		LegacySdaCompatible {
			iv: base64::encode(iv),
			salt: base64::encode(salt),
		}
	}

	fn encrypt(
		&self,
		passkey: &str,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let start = std::time::Instant::now();
		let key = Self::get_encryption_key(passkey, &self.salt)?;
		debug!("key derivation took: {:?}", start.elapsed());

		let start = std::time::Instant::now();
		let mut iv = [0u8; Self::IV_LENGTH];
		base64::decode_config_slice(&self.iv, base64::STANDARD, &mut iv)?;
		let cipher = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)?;
		let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
		let encoded = base64::encode(ciphertext);
		debug!("encryption took: {:?}", start.elapsed());
		Ok(encoded.as_bytes().to_vec())
	}

	fn decrypt(
		&self,
		passkey: &str,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let start = std::time::Instant::now();
		let key = Self::get_encryption_key(passkey, &self.salt)?;
		debug!("key derivation took: {:?}", start.elapsed());

		let start = std::time::Instant::now();
		let mut iv = [0u8; Self::IV_LENGTH];
		base64::decode_config_slice(&self.iv, base64::STANDARD, &mut iv)?;
		let cipher = cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv)?;
		let decoded = base64::decode(ciphertext)?;
		let size: usize = decoded.len() / 16 + (if decoded.len() % 16 == 0 { 0 } else { 1 });
		let mut buffer = vec![0xffu8; 16 * size];
		buffer[..decoded.len()].copy_from_slice(&decoded);
		let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)?;
		debug!("decryption took: {:?}", start.elapsed());
		Ok(decrypted.to_vec())
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
		let scheme = LegacySdaCompatible::generate();
		for case in cases {
			eprintln!("testing case: {} (len {})", case, case.len());
			let orig = case.as_bytes().to_vec();
			let encrypted = scheme.encrypt(passkey, orig.clone()).unwrap();
			let result = scheme.decrypt(passkey, encrypted).unwrap();
			assert_eq!(orig, result.to_vec());
		}
		Ok(())
	}

	prop_compose! {
		/// An insecure but reproducible strategy for generating encryption params.
		fn encryption_params()(salt in any::<[u8; LegacySdaCompatible::SALT_LENGTH]>(), iv in any::<[u8; LegacySdaCompatible::IV_LENGTH]>()) -> LegacySdaCompatible {
			LegacySdaCompatible {
				salt: base64::encode(salt),
				iv: base64::encode(iv),
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
