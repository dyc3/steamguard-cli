use reqwest::IntoUrl;

use crate::{
	protobufs::steammessages_auth_steamclient::CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
	steamapi::{AuthenticationClient, EResult},
	token::Tokens,
	transport::WebApiTransport,
	SteamGuardAccount,
};

/// QR code login approver
///
/// This can be used to approve a login request from another device that is displaying a QR code.
pub struct QrApprover {
	tokens: Tokens,
	client: AuthenticationClient<WebApiTransport>,
}

impl QrApprover {
	pub fn new(tokens: Tokens) -> Self {
		let client = AuthenticationClient::new(WebApiTransport::new());
		Self { tokens, client }
	}

	/// Approve a login request from a challenge URL
	pub fn approve(
		&mut self,
		account: SteamGuardAccount,
		challenge_url: impl IntoUrl,
	) -> Result<(), QrApproverError> {
		let challenge = parse_challenge_url(challenge_url)?;
		let signature = build_signature(&account, &challenge);

		let mut req = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request::new();
		req.set_steamid(account.steam_id);
		req.set_version(challenge.version.into());
		req.set_client_id(challenge.client_id);
		req.set_signature(signature.to_vec());
		req.set_confirm(true);
		req.set_persistence(
			crate::protobufs::enums::ESessionPersistence::k_ESessionPersistence_Persistent,
		);

		let resp = self
			.client
			.update_session_with_mobile_confirmation(req, &self.tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		Ok(())
	}
}

fn build_signature(account: &SteamGuardAccount, challenge: &Challenge) -> [u8; 32] {
	let mut data = Vec::<u8>::new();
	data.extend_from_slice(&challenge.version.to_le_bytes());
	data.extend_from_slice(&challenge.client_id.to_le_bytes());
	data.extend_from_slice(&account.steam_id.to_le_bytes());

	hmac_sha256::HMAC::mac(data, account.shared_secret.expose_secret())
}

fn parse_challenge_url(challenge_url: impl IntoUrl) -> Result<Challenge, QrApproverError> {
	let url = challenge_url
		.into_url()
		.map_err(|_| QrApproverError::InvalidChallengeUrl)?;

	let regex = regex::Regex::new(r"^https?://s.team/q/(\d+)/(\d+)(\?|$)").unwrap();

	let captures = regex
		.captures(url.as_str())
		.ok_or(QrApproverError::InvalidChallengeUrl)?;

	let version = captures[1].parse().expect("regex should only match digits");
	let client_id = captures[2].parse().expect("regex should only match digits");

	Ok(Challenge { version, client_id })
}

#[derive(Debug)]
struct Challenge {
	version: u16,
	client_id: u64,
}

#[derive(Debug)]
pub enum QrApproverError {
	InvalidChallengeUrl,
	UnknownEResult(EResult),
}

impl From<EResult> for QrApproverError {
	fn from(result: EResult) -> Self {
		Self::UnknownEResult(result)
	}
}

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
}
