use secrecy::SecretString;
use serde::Deserialize;
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
	pub steamid: u64,
	pub shared_secret: TwoFactorSecret,
	pub serial_number: String,
	#[serde(with = "crate::secret_string")]
	pub revocation_code: SecretString,
	#[serde(with = "crate::secret_string")]
	pub uri: SecretString,
	pub server_time: Option<serde_json::Value>,
	pub account_name: String,
	pub token_gid: String,
	#[serde(with = "crate::secret_string")]
	pub identity_secret: SecretString,
	pub status: Option<String>,
	pub steamguard_scheme: Option<String>,
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
			// secret_1 is unknown, so we just set it to all zeros base64 encoded
			secret_1: SecretString::new("AAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()),
			tokens: None,
		}
	}
}
