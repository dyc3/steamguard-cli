use log::debug;
use reqwest::IntoUrl;

use crate::{
	protobufs::steammessages_auth_steamclient::CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
	steamapi::{AuthenticationClient, EResult},
	token::{Tokens, TwoFactorSecret},
	transport::Transport,
	SteamGuardAccount,
};

/// QR code login approver
///
/// This can be used to approve a login request from another device that is displaying a QR code.
pub struct QrApprover<'a, T>
where
	T: Transport,
{
	tokens: &'a Tokens,
	client: AuthenticationClient<T>,
}

impl<'a, T> QrApprover<'a, T>
where
	T: Transport,
{
	pub fn new(transport: T, tokens: &'a Tokens) -> Self {
		let client = AuthenticationClient::new(transport);
		Self { tokens, client }
	}

	/// Approve a login request from a challenge URL
	pub fn approve(
		&mut self,
		account: &SteamGuardAccount,
		challenge_url: impl IntoUrl,
	) -> Result<(), QrApproverError> {
		debug!("building signature");
		let challenge = parse_challenge_url(challenge_url)?;
		let signature = build_signature(&account.shared_secret, account.steam_id, &challenge);

		debug!("approving login");
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
	let mut data = Vec::<u8>::with_capacity(18);
	data.extend_from_slice(&challenge.version.to_le_bytes());
	data.extend_from_slice(&challenge.client_id.to_le_bytes());
	data.extend_from_slice(&steam_id.to_le_bytes());

	hmac_sha256::HMAC::mac(data, shared_secret.expose_secret())
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

#[derive(Debug, thiserror::Error)]
pub enum QrApproverError {
	#[error("Invalid challenge URL")]
	InvalidChallengeUrl,
	#[error("Steam says that this qr login challege has already been used. Try again with a new QR code.")]
	DuplicateRequest,
	#[error("Steam says that this qr login challege has expired. Try again with a new QR code.")]
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

impl From<EResult> for QrApproverError {
	fn from(result: EResult) -> Self {
		match result {
			EResult::DuplicateRequest => Self::DuplicateRequest,
			_ => Self::UnknownEResult(result),
		}
	}
}

impl From<anyhow::Error> for QrApproverError {
	fn from(err: anyhow::Error) -> Self {
		Self::Unknown(err)
	}
}

impl From<crate::transport::TransportError> for QrApproverError {
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
