use hmac::{Hmac, Mac};
use log::debug;
use reqwest::IntoUrl;
use sha2::Sha256;

use crate::{
	protobufs::{
		enums::ESessionPersistence,
		steammessages_auth_steamclient::{
			CAuthentication_GetAuthSessionInfo_Request,
			CAuthentication_GetAuthSessionInfo_Response,
			CAuthentication_GetAuthSessionsForAccount_Request,
			CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
		},
	},
	steamapi::{AuthenticationClient, EResult},
	token::{Tokens, TwoFactorSecret},
	transport::Transport,
	SteamGuardAccount,
};

/// Login approver. Lets you approve or deny login requests from other devices.
///
/// This can be used to approve a login request from another device that is displaying a QR code.
/// This can also be used to approve any login request that allows the auth guard [`crate::protobufs::steammessages_auth_steamclient::EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation`].
pub struct LoginApprover<'a, T>
where
	T: Transport,
{
	tokens: &'a Tokens,
	client: AuthenticationClient<T>,
}

impl<'a, T> LoginApprover<'a, T>
where
	T: Transport,
{
	pub fn new(transport: T, tokens: &'a Tokens) -> Self {
		let client = AuthenticationClient::new(transport);
		Self { tokens, client }
	}

	/// List all active auth sessions. Returns a list of client IDs.
	pub fn list_auth_sessions(&self) -> Result<Vec<u64>, ApproverError> {
		let req = CAuthentication_GetAuthSessionsForAccount_Request::new();
		let resp = self
			.client
			.get_auth_sessions_for_account(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let data = resp.into_response_data();

		Ok(data.client_ids.clone())
	}

	pub fn get_auth_session_info(
		&self,
		client_id: u64,
	) -> Result<CAuthentication_GetAuthSessionInfo_Response, ApproverError> {
		let mut req = CAuthentication_GetAuthSessionInfo_Request::new();
		req.set_client_id(client_id);
		let resp = self
			.client
			.get_auth_session_info(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		Ok(resp.into_response_data())
	}

	/// Approve a login request from a challenge URL
	pub fn approve(
		&mut self,
		account: &SteamGuardAccount,
		challenge: Challenge,
		persistence: ESessionPersistence,
	) -> Result<(), ApproverError> {
		debug!("building signature");
		let signature = build_signature(&account.shared_secret, account.steam_id, &challenge);

		debug!("approving login");
		let mut req = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request::new();
		req.set_steamid(account.steam_id);
		req.set_version(challenge.version.into());
		req.set_client_id(challenge.client_id);
		req.set_signature(signature.to_vec());
		req.set_confirm(true);
		req.set_persistence(persistence);

		let resp = self
			.client
			.update_session_with_mobile_confirmation(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		Ok(())
	}

	pub fn approve_from_challenge_url(
		&mut self,
		account: &SteamGuardAccount,
		challenge_url: impl IntoUrl,
		persistence: ESessionPersistence,
	) -> Result<(), ApproverError> {
		let challenge = parse_challenge_url(challenge_url)?;
		self.approve(account, challenge, persistence)
	}

	pub fn deny(
		&mut self,
		account: &SteamGuardAccount,
		challenge: Challenge,
	) -> Result<(), ApproverError> {
		debug!("building signature");
		let signature = build_signature(&account.shared_secret, account.steam_id, &challenge);

		debug!("denying login");
		let mut req = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request::new();
		req.set_steamid(account.steam_id);
		req.set_version(challenge.version.into());
		req.set_client_id(challenge.client_id);
		req.set_signature(signature.to_vec());
		req.set_confirm(false);
		req.set_persistence(
			crate::protobufs::enums::ESessionPersistence::k_ESessionPersistence_Persistent,
		);

		let resp = self
			.client
			.update_session_with_mobile_confirmation(req, self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		Ok(())
	}
}

fn build_signature(
	shared_secret: &TwoFactorSecret,
	steam_id: u64,
	challenge: &Challenge,
) -> [u8; 32] {
	let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.expose_secret()).unwrap();
	mac.update(&challenge.version.to_le_bytes());
	mac.update(&challenge.client_id.to_le_bytes());
	mac.update(&steam_id.to_le_bytes());
	let result = mac.finalize();
	result.into_bytes().into()
}

pub fn parse_challenge_url(challenge_url: impl IntoUrl) -> Result<Challenge, ApproverError> {
	let url = challenge_url
		.into_url()
		.map_err(|_| ApproverError::InvalidChallengeUrl)?;

	let regex = regex::Regex::new(r"^https?://s.team/q/(\d+)/(\d+)(\?|$)").unwrap();

	let captures = regex
		.captures(url.as_str())
		.ok_or(ApproverError::InvalidChallengeUrl)?;

	let version = captures[1].parse().expect("regex should only match digits");
	let client_id = captures[2].parse().expect("regex should only match digits");

	Ok(Challenge { version, client_id })
}

/// Metadata about a login challenge.
///
/// The client_id is a unique identifier for this challenge. It is used to identify the challenge when approving it.
/// The version is the version of the challenge. It should be 1.
#[derive(Debug)]
pub struct Challenge {
	version: u16,
	client_id: u64,
}

impl Challenge {
	/// Create a new challenge. The version should likely be 1.
	pub fn new(version: u16, client_id: u64) -> Self {
		Self { version, client_id }
	}

	pub fn version(&self) -> u16 {
		self.version
	}

	pub fn client_id(&self) -> u64 {
		self.client_id
	}
}

#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
	#[error("Invalid challenge URL")]
	InvalidChallengeUrl,
	#[error("Steam says that this login challege has already been used. Start a new session and try again.")]
	DuplicateRequest,
	#[error("Steam says that this login challege has expired. Start a new session and try again.")]
	Expired,
	#[error("Unauthorized")]
	Unauthorized,
	#[error("Transport error: {0}")]
	TransportError(crate::transport::TransportError),
	#[error("Unknown EResult: {0:?}")]
	UnknownEResult(EResult),
	#[error("Unknown error: {0}")]
	Unknown(anyhow::Error),
}

impl From<EResult> for ApproverError {
	fn from(result: EResult) -> Self {
		match result {
			EResult::DuplicateRequest => Self::DuplicateRequest,
			_ => Self::UnknownEResult(result),
		}
	}
}

impl From<anyhow::Error> for ApproverError {
	fn from(err: anyhow::Error) -> Self {
		Self::Unknown(err)
	}
}

impl From<crate::transport::TransportError> for ApproverError {
	fn from(err: crate::transport::TransportError) -> Self {
		match err {
			crate::transport::TransportError::Unauthorized => Self::Unauthorized,
			_ => Self::TransportError(err),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_challenge_url() {
		let url = "https://s.team/q/1/2372462679780599330";
		let challenge = parse_challenge_url(url).unwrap();
		assert_eq!(challenge.version, 1);
		assert_eq!(challenge.client_id, 2372462679780599330);
	}

	#[test]
	fn test_parse_challenge_url_fail() {
		let urls = [
			"https://s.team/q/1/asdf",
			"https://s.team/q/1/123asdf",
			"https://s.team/q/a/123",
			"https://s.team/q/123a/123",
		];
		for url in urls {
			let challenge = parse_challenge_url(url);
			assert!(challenge.is_err(), "url: {}", url);
		}
	}

	#[test]
	fn test_build_signature() {
		let challenge = Challenge {
			version: 1,
			client_id: 2372462679780599330,
		};
		let secret =
			TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".to_owned())
				.unwrap();
		let steam_id = 76561197960265728;
		let signature = build_signature(&secret, steam_id, &challenge);

		assert_eq!(
			signature,
			[
				56, 233, 253, 249, 254, 89, 110, 161, 18, 35, 35, 144, 14, 217, 210, 150, 170, 110,
				61, 166, 176, 161, 140, 211, 108, 78, 138, 202, 61, 52, 85, 46
			]
		);
	}
}
