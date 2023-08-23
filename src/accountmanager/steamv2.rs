use secrecy::SecretString;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use steamguard::{token::TwoFactorSecret, SteamGuardAccount};
use uuid::Uuid;

/// Defines the schema for loading steamguard accounts extracted from backups of the official Steam app (v2).
///
/// ```json
/// {
/// 	"steamid": "X",
/// 	"shared_secret": "X",
/// 	"serial_number": "X",
/// 	"revocation_code": "X",
/// 	"uri": "otpauth:\/\/totp\/Steam:USERNAME?secret=X&issuer=Steam",
/// 	"server_time": "X",
/// 	"account_name": "USERNAME",
/// 	"token_gid": "X",
/// 	"identity_secret": "X",
/// 	"secret_1": "X",
/// 	"status": 1,
/// 	"steamguard_scheme": "2"
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct SteamMobileV2 {
	#[serde(deserialize_with = "de_parse_number")]
	pub steamid: u64,
	pub shared_secret: TwoFactorSecret,
	pub serial_number: String,
	#[serde(with = "crate::secret_string")]
	pub revocation_code: SecretString,
	#[serde(with = "crate::secret_string")]
	pub uri: SecretString,
	pub server_time: serde_json::Value,
	pub account_name: String,
	pub token_gid: String,
	#[serde(with = "crate::secret_string")]
	pub identity_secret: SecretString,
	#[serde(with = "crate::secret_string")]
	pub secret_1: SecretString,
	pub status: serde_json::Value,
	pub steamguard_scheme: serde_json::Value,
}

impl From<SteamMobileV2> for SteamGuardAccount {
	fn from(account: SteamMobileV2) -> Self {
		Self {
			shared_secret: account.shared_secret,
			identity_secret: account.identity_secret,
			revocation_code: account.revocation_code,
			uri: account.uri,
			account_name: account.account_name,
			token_gid: account.token_gid,
			serial_number: account.serial_number,
			steam_id: account.steamid,
			// device_id is unknown, so we just make one up
			device_id: format!("android:{}", Uuid::new_v4()),
			secret_1: account.secret_1,
			tokens: None,
		}
	}
}

fn de_parse_number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
	Ok(match Value::deserialize(deserializer)? {
		Value::String(s) => s.parse().map_err(serde::de::Error::custom)?,
		Value::Number(num) => num
			.as_u64()
			.ok_or(serde::de::Error::custom("Invalid number"))? as u64,
		_ => return Err(serde::de::Error::custom("wrong type")),
	})
}
