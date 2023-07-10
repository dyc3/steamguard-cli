use base64::Engine;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, Secret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct TwoFactorSecret(Secret<[u8; 20]>);

impl Default for TwoFactorSecret {
	fn default() -> Self {
		Self::new()
	}
}

impl TwoFactorSecret {
	pub fn new() -> Self {
		Self([0u8; 20].into())
	}

	pub fn from_bytes(bytes: Vec<u8>) -> Self {
		let bytes: [u8; 20] = bytes[..].try_into().unwrap();
		Self(bytes.into())
	}

	pub fn parse_shared_secret(secret: String) -> anyhow::Result<Self> {
		ensure!(!secret.is_empty(), "unable to parse empty shared secret");
		let result: [u8; 20] = base64::engine::general_purpose::STANDARD
			.decode(secret)?
			.try_into()
			.unwrap();
		Ok(Self(result.into()))
	}

	/// Generate a 5 character 2FA code to that can be used to log in to Steam.
	pub fn generate_code(&self, time: u64) -> String {
		let steam_guard_code_translations: [u8; 26] = [
			50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84,
			86, 87, 88, 89,
		];

		let mut mac = Hmac::<Sha1>::new_from_slice(self.0.expose_secret()).unwrap();
		// this effectively makes it so that it creates a new code every 30 seconds.
		mac.update(&build_time_bytes(time / 30u64));
		let result = mac.finalize();
		let hashed_data = result.into_bytes();
		let mut code_array: [u8; 5] = [0; 5];
		let b = (hashed_data[19] & 0xF) as usize;
		let mut code_point: i32 = ((hashed_data[b] & 0x7F) as i32) << 24
			| (hashed_data[b + 1] as i32) << 16
			| (hashed_data[b + 2] as i32) << 8
			| (hashed_data[b + 3] as i32);

		for item in &mut code_array {
			*item = steam_guard_code_translations
				[code_point as usize % steam_guard_code_translations.len()];
			code_point /= steam_guard_code_translations.len() as i32;
		}

		String::from_utf8(code_array.to_vec()).unwrap()
	}

	pub(crate) fn expose_secret(&self) -> &[u8; 20] {
		self.0.expose_secret()
	}
}

impl Serialize for TwoFactorSecret {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(
			base64::engine::general_purpose::STANDARD
				.encode(self.0.expose_secret())
				.as_str(),
		)
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
		self.0.expose_secret() == other.0.expose_secret()
	}
}

impl Eq for TwoFactorSecret {}

fn build_time_bytes(time: u64) -> [u8; 8] {
	time.to_be_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokens {
	access_token: Jwt,
	refresh_token: Jwt,
}

impl Tokens {
	pub fn new(access_token: impl Into<Jwt>, refresh_token: impl Into<Jwt>) -> Self {
		Self {
			access_token: access_token.into(),
			refresh_token: refresh_token.into(),
		}
	}

	pub fn access_token(&self) -> &Jwt {
		&self.access_token
	}

	pub fn set_access_token(&mut self, token: Jwt) {
		self.access_token = token;
	}

	pub fn refresh_token(&self) -> &Jwt {
		&self.refresh_token
	}
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwt(SecretString);

impl Serialize for Jwt {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(self.0.expose_secret())
	}
}

impl Jwt {
	pub fn decode(&self) -> anyhow::Result<SteamJwtData> {
		decode_jwt(self.0.expose_secret())
	}

	pub fn expose_secret(&self) -> &str {
		self.0.expose_secret()
	}
}

impl From<String> for Jwt {
	fn from(s: String) -> Self {
		Self(SecretString::new(s))
	}
}

fn decode_jwt(jwt: impl AsRef<str>) -> anyhow::Result<SteamJwtData> {
	let parts = jwt.as_ref().split('.').collect::<Vec<&str>>();
	ensure!(parts.len() == 3, "Invalid JWT");

	let data = parts[1];
	let bytes = base64::engine::general_purpose::URL_SAFE.decode(data)?;
	let json = String::from_utf8(bytes)?;
	let jwt_data: SteamJwtData = serde_json::from_str(&json)?;
	Ok(jwt_data)
}

#[derive(Deserialize, Debug)]
pub struct SteamJwtData {
	pub exp: u64,
	pub iat: u64,
	pub iss: String,
	/// Audience
	pub aud: Vec<String>,
	/// Subject (steam id)
	pub sub: String,
	pub jti: String,
}

impl SteamJwtData {
	pub fn steam_id(&self) -> u64 {
		self.sub.parse::<u64>().unwrap()
	}
}

mod tests {
	use super::*;

	#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
	struct FooBar {
		secret: TwoFactorSecret,
	}

	#[test]
	fn test_serialize_2fa_secret() -> anyhow::Result<()> {
		let secret = FooBar {
			secret: TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?,
		};

		let serialized = serde_json::to_string(&secret)?;
		assert_eq!(serialized, "{\"secret\":\"zvIayp3JPvtvX/QGHqsqKBk/44s=\"}");

		Ok(())
	}

	#[test]
	fn test_deserialize_2fa_secret() -> anyhow::Result<()> {
		let secret: FooBar = serde_json::from_str("{\"secret\":\"zvIayp3JPvtvX/QGHqsqKBk/44s=\"}")?;

		let code = secret.secret.generate_code(1616374841u64);
		assert_eq!(code, "2F9J5");

		Ok(())
	}

	#[test]
	fn test_serialize_and_deserialize_2fa_secret() -> anyhow::Result<()> {
		let secret = FooBar {
			secret: TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?,
		};

		let serialized = serde_json::to_string(&secret)?;
		let deserialized: FooBar = serde_json::from_str(&serialized)?;
		assert_eq!(deserialized, secret);

		Ok(())
	}

	#[test]
	fn test_build_time_bytes() {
		let t1 = build_time_bytes(1617591917u64);
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

		let code = secret.generate_code(1616374841u64);
		assert_eq!(code, "2F9J5");
		Ok(())
	}

	#[test]
	fn test_decode_jwt() {
		let sample: Jwt = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTE1NTcwNjg5MiIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTcwNTAxMTk1NSwgIm5iZiI6IDE2Nzg0NjQ4MzcsICJpYXQiOiAxNjg3MTA0ODM3LCAianRpIjogIjE4QzVfMjJCM0Y0MzFfQ0RGNkEiLCAib2F0IjogMTY4NzEwNDgzNywgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjY5LjEyMC4xMzYuMTI0IiwgImlwX2NvbmZpcm1lciI6ICI2OS4xMjAuMTM2LjEyNCIgfQ.7p5TPj9pGQbxIzWDDNCSP9OkKYSeDnWBE8E-M8hUrxOEPCW0XwrbDUrh199RzjPDw".to_owned().into();
		let data = sample.decode().expect("Failed to decode JWT");

		assert_eq!(data.exp, 1705011955);
		assert_eq!(data.iat, 1687104837);
		assert_eq!(data.iss, "steam");
		assert_eq!(data.aud, vec!["web", "renew", "derive"]);
		assert_eq!(data.sub, "76561199155706892");
		assert_eq!(data.jti, "18C5_22B3F431_CDF6A");
	}
}
