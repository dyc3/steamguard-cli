use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use argon2::Argon2;

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2idAes256 {
	iv: String,
	salt: String,
}

impl Argon2idAes256 {
	const KEY_SIZE_BYTES: usize = 32;
	const IV_LENGTH: usize = 16;
	const SALT_LENGTH: usize = 16;

	fn get_encryption_key(passkey: &str, salt: &str) -> anyhow::Result<[u8; Self::KEY_SIZE_BYTES]> {
		let password_bytes = passkey.as_bytes();
		let salt_bytes = base64::decode(salt)?;
		let mut full_key: [u8; Self::KEY_SIZE_BYTES] = [0u8; Self::KEY_SIZE_BYTES];
		let deriver = Argon2::new(
			argon2::Algorithm::Argon2id,
			argon2::Version::V0x13,
			Self::config(),
		);
		deriver.hash_password_into(password_bytes, &salt_bytes, &mut full_key)?;

		Ok(full_key)
	}

	fn config() -> argon2::Params {
		argon2::Params::new(
			62500, // 64MB
			3,
			4,
			Some(Self::KEY_SIZE_BYTES),
		)
		.expect("Unable to create Argon2 config.")
	}
}

impl EntryEncryptor for Argon2idAes256 {
	fn generate() -> Self {
		let rng = ring::rand::SystemRandom::new();
		let mut salt = [0u8; Self::SALT_LENGTH];
		let mut iv = [0u8; Self::IV_LENGTH];
		rng.fill(&mut salt).expect("Unable to generate salt.");
		rng.fill(&mut iv).expect("Unable to generate IV.");
		Argon2idAes256 {
			iv: base64::encode(iv),
			salt: base64::encode(salt),
		}
	}

	fn encrypt(
		&self,
		passkey: &str,
		plaintext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let key = Self::get_encryption_key(passkey, &self.salt)?;
		let mut iv = [0u8; Self::IV_LENGTH];
		base64::decode_config_slice(&self.iv, base64::STANDARD, &mut iv)?;

		let cipher = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)?;

		let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&plaintext);

		let encoded = base64::encode(ciphertext);
		Ok(encoded.as_bytes().to_vec())
	}

	fn decrypt(
		&self,
		passkey: &str,
		ciphertext: Vec<u8>,
	) -> anyhow::Result<Vec<u8>, EntryEncryptionError> {
		let key = Self::get_encryption_key(passkey, &self.salt)?;
		let mut iv = [0u8; Self::IV_LENGTH];
		base64::decode_config_slice(&self.iv, base64::STANDARD, &mut iv)?;
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

	#[test]
	fn test_encryption_key() {
		assert_eq!(
			base64::encode(
				Argon2idAes256::get_encryption_key("password", "GMhL0N2hqXg=")
					.unwrap()
					.as_slice()
			),
			"cLn73uBZWFMeXyGbG3IfJj/OgGjQAAwQoWedUdSoQXI="
		);

		assert_eq!(
			base64::encode(
				Argon2idAes256::get_encryption_key("password", "wTzTE9A6aN8=")
					.unwrap()
					.as_slice()
			),
			"Puvpv6HExFpanhtNtTVuC2K7oSKey3tW96wsZJSwzWQ="
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
		let scheme = Argon2idAes256::generate();
		for case in cases {
			eprintln!("testing case: {} (len {})", case, case.len());
			let orig = case.as_bytes().to_vec();
			let encrypted = scheme.encrypt(passkey, orig.clone()).unwrap();
			let result = scheme.decrypt(passkey, encrypted).unwrap();
			assert_eq!(orig, result.to_vec());
		}
		Ok(())
	}
}
