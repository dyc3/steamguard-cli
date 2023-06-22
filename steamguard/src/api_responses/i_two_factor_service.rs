use crate::{token::TwoFactorSecret, SteamGuardAccount};

use super::parse_json_string_as_number;
use serde::{Deserialize, Serialize};

/// Represents the response from `/ITwoFactorService/QueryTime/v0001`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTimeResponse {
	/// The time that the server will use to check your two factor code.
	#[serde(deserialize_with = "parse_json_string_as_number")]
	pub server_time: u64,
	#[serde(deserialize_with = "parse_json_string_as_number")]
	pub skew_tolerance_seconds: u64,
	#[serde(deserialize_with = "parse_json_string_as_number")]
	pub large_time_jink: u64,
	pub probe_frequency_seconds: u64,
	pub adjusted_time_probe_frequency_seconds: u64,
	pub hint_probe_frequency_seconds: u64,
	pub sync_timeout: u64,
	pub try_again_seconds: u64,
	pub max_attempts: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddAuthenticatorResponse {
	/// Shared secret between server and authenticator
	#[serde(default)]
	pub shared_secret: String,
	/// Authenticator serial number (unique per token)
	#[serde(default)]
	pub serial_number: String,
	/// code used to revoke authenticator
	#[serde(default)]
	pub revocation_code: String,
	/// URI for QR code generation
	#[serde(default)]
	pub uri: String,
	/// Current server time
	#[serde(default, deserialize_with = "parse_json_string_as_number")]
	pub server_time: u64,
	/// Account name to display on token client
	#[serde(default)]
	pub account_name: String,
	/// Token GID assigned by server
	#[serde(default)]
	pub token_gid: String,
	/// Secret used for identity attestation (e.g., for eventing)
	#[serde(default)]
	pub identity_secret: String,
	/// Spare shared secret
	#[serde(default)]
	pub secret_1: String,
	/// Result code
	pub status: i32,
	#[serde(default)]
	pub phone_number_hint: Option<String>,
}

impl AddAuthenticatorResponse {
	pub fn to_steam_guard_account(self) -> SteamGuardAccount {
		SteamGuardAccount {
			shared_secret: TwoFactorSecret::parse_shared_secret(self.shared_secret).unwrap(),
			serial_number: self.serial_number,
			revocation_code: self.revocation_code.into(),
			uri: self.uri.into(),
			account_name: self.account_name,
			token_gid: self.token_gid,
			identity_secret: self.identity_secret.into(),
			secret_1: self.secret_1.into(),
			device_id: "".into(),
			tokens: None,
			session: None,
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
pub struct FinalizeAddAuthenticatorResponse {
	pub status: i32,
	#[serde(deserialize_with = "parse_json_string_as_number")]
	pub server_time: u64,
	pub want_more: bool,
	pub success: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveAuthenticatorResponse {
	pub success: bool,
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::api_responses::SteamApiResponse;

	#[test]
	fn test_parse_add_auth_response() {
		let result = serde_json::from_str::<SteamApiResponse<AddAuthenticatorResponse>>(
			include_str!("../fixtures/api-responses/add-authenticator-1.json"),
		);

		assert!(
			matches!(result, Ok(_)),
			"got error: {}",
			result.unwrap_err()
		);
		let resp = result.unwrap().response;

		assert_eq!(resp.server_time, 1628559846);
		assert_eq!(resp.shared_secret, "wGwZx=sX5MmTxi6QgA3Gi");
		assert_eq!(resp.revocation_code, "R123456");
	}

	#[test]
	fn test_parse_add_auth_response2() {
		let result = serde_json::from_str::<SteamApiResponse<AddAuthenticatorResponse>>(
			include_str!("../fixtures/api-responses/add-authenticator-2.json"),
		);

		assert!(
			matches!(result, Ok(_)),
			"got error: {}",
			result.unwrap_err()
		);
		let resp = result.unwrap().response;

		assert_eq!(resp.status, 29);
	}
}
