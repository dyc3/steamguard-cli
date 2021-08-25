use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct TwoFactorSecret(Secret<[u8; 20]>);
// pub struct TwoFactorSecret(Secret<Vec<u8>>);

impl TwoFactorSecret {
	pub fn new() -> Self {
		return Self([0u8; 20].into());
	}

	pub fn parse_shared_secret(secret: String) -> anyhow::Result<Self> {
		ensure!(secret.len() != 0, "unable to parse empty shared secret");
		let result: [u8; 20] = base64::decode(secret)?.try_into().unwrap();
		return Ok(Self(result.into()));
	}

	/// Generate a 5 character 2FA code to that can be used to log in to Steam.
	pub fn generate_code(&self, time: i64) -> String {
		let steam_guard_code_translations: [u8; 26] = [
			50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84,
			86, 87, 88, 89,
		];

		// this effectively makes it so that it creates a new code every 30 seconds.
		let time_bytes: [u8; 8] = build_time_bytes(time / 30i64);
		let hashed_data = hmacsha1::hmac_sha1(self.0.expose_secret(), &time_bytes);
		let mut code_array: [u8; 5] = [0; 5];
		let b = (hashed_data[19] & 0xF) as usize;
		let mut code_point: i32 = ((hashed_data[b] & 0x7F) as i32) << 24
			| ((hashed_data[b + 1] & 0xFF) as i32) << 16
			| ((hashed_data[b + 2] & 0xFF) as i32) << 8
			| ((hashed_data[b + 3] & 0xFF) as i32);

		for i in 0..5 {
			code_array[i] = steam_guard_code_translations
				[code_point as usize % steam_guard_code_translations.len()];
			code_point /= steam_guard_code_translations.len() as i32;
		}

		return String::from_utf8(code_array.iter().map(|c| *c).collect()).unwrap();
	}
}

impl Serialize for TwoFactorSecret {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(base64::encode(&self.0.expose_secret()).as_str())
	}
}

impl<'de> Deserialize<'de> for TwoFactorSecret {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Ok(TwoFactorSecret::parse_shared_secret(String::deserialize(deserializer)?).unwrap())
	}
}

impl PartialEq for TwoFactorSecret {
	fn eq(&self, other: &Self) -> bool {
		return self.0.expose_secret() == other.0.expose_secret();
	}
}

impl Eq for TwoFactorSecret {}

fn build_time_bytes(time: i64) -> [u8; 8] {
	return time.to_be_bytes();
}

mod tests {
	use super::*;

	#[test]
	fn test_serialize() -> anyhow::Result<()> {
		#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
		struct FooBar {
			secret: TwoFactorSecret,
		}

		let secret = FooBar {
			secret: TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?,
		};

		let serialized = serde_json::to_string(&secret)?;
		assert_eq!(serialized, "{\"secret\":\"zvIayp3JPvtvX/QGHqsqKBk/44s=\"}");

		return Ok(());
	}

	#[test]
	fn test_deserialize() -> anyhow::Result<()> {
		#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
		struct FooBar {
			secret: TwoFactorSecret,
		}

		let secret: FooBar =
			serde_json::from_str(&"{\"secret\":\"zvIayp3JPvtvX/QGHqsqKBk/44s=\"}")?;

		let code = secret.secret.generate_code(1616374841i64);
		assert_eq!(code, "2F9J5");

		return Ok(());
	}

	#[test]
	fn test_serialize_and_deserialize() -> anyhow::Result<()> {
		#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
		struct FooBar {
			secret: TwoFactorSecret,
		}

		let secret = FooBar {
			secret: TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?,
		};

		let serialized = serde_json::to_string(&secret)?;
		let deserialized: FooBar = serde_json::from_str(&serialized)?;
		assert_eq!(deserialized, secret);

		return Ok(());
	}

	#[test]
	fn test_build_time_bytes() {
		let t1 = build_time_bytes(1617591917i64);
		let t2: [u8; 8] = [0, 0, 0, 0, 96, 106, 126, 109];
		assert!(
			t1.iter().zip(t2.iter()).all(|(a, b)| a == b),
			"Arrays are not equal, got {:?}",
			t1
		);
	}

	#[test]
	fn test_generate_code() -> anyhow::Result<()> {
		let secret = TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?;

		let code = secret.generate_code(1616374841i64);
		assert_eq!(code, "2F9J5");
		return Ok(());
	}
}
