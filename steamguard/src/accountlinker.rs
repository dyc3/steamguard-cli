use crate::protobufs::service_twofactor::{
	CTwoFactor_AddAuthenticator_Request, CTwoFactor_FinalizeAddAuthenticator_Request,
};
use crate::steamapi::twofactor::TwoFactorClient;
use crate::token::TwoFactorSecret;
use crate::transport::Transport;
use crate::{steamapi::EResult, token::Tokens, SteamGuardAccount};
use log::*;
use thiserror::Error;

#[derive(Debug)]
pub struct AccountLinker<T>
where
	T: Transport,
{
	device_id: String,
	pub account: Option<SteamGuardAccount>,
	pub finalized: bool,
	tokens: Tokens,
	client: TwoFactorClient<T>,
}

impl<T> AccountLinker<T>
where
	T: Transport,
{
	pub fn new(transport: T, tokens: Tokens) -> Self {
		Self {
			device_id: generate_device_id(),
			account: None,
			finalized: false,
			tokens,
			client: TwoFactorClient::new(transport),
		}
	}

	pub fn tokens(&self) -> &Tokens {
		&self.tokens
	}

	pub fn link(&mut self) -> anyhow::Result<AccountLinkSuccess, AccountLinkError> {
		let access_token = self.tokens.access_token();
		let steam_id = access_token.decode()?.steam_id();

		let mut req = CTwoFactor_AddAuthenticator_Request::new();
		req.set_authenticator_type(1);
		req.set_steamid(steam_id);
		req.set_sms_phone_id("1".to_owned());
		req.set_device_identifier(self.device_id.clone());

		let resp = self.client.add_authenticator(req, access_token)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let mut resp = resp.into_response_data();

		let account = SteamGuardAccount {
			account_name: resp.take_account_name(),
			steam_id,
			serial_number: resp.serial_number().to_string(),
			revocation_code: resp.take_revocation_code().into(),
			uri: resp.take_uri().into(),
			shared_secret: TwoFactorSecret::from_bytes(resp.take_shared_secret()),
			token_gid: resp.take_token_gid(),
			identity_secret: base64::encode(resp.take_identity_secret()).into(),
			device_id: self.device_id.clone(),
			secret_1: base64::encode(resp.take_secret_1()).into(),
			tokens: Some(self.tokens.clone()),
		};
		let success = AccountLinkSuccess {
			account,
			server_time: resp.server_time(),
			phone_number_hint: resp.take_phone_number_hint(),
		};
		Ok(success)
	}

	/// You may have to call this multiple times. If you have to call it a bunch of times, then you can assume that you are unable to generate correct 2fa codes.
	pub fn finalize(
		&mut self,
		time: u64,
		account: &mut SteamGuardAccount,
		sms_code: String,
	) -> anyhow::Result<(), FinalizeLinkError> {
		let code = account.generate_code(time);

		let token = self.tokens.access_token();
		let steam_id = account.steam_id;

		let mut req = CTwoFactor_FinalizeAddAuthenticator_Request::new();
		req.set_steamid(steam_id);
		req.set_authenticator_code(code);
		req.set_authenticator_time(time);
		req.set_activation_code(sms_code);

		let resp = self.client.finalize_authenticator(req, token)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let resp = resp.into_response_data();

		if resp.want_more() {
			return Err(FinalizeLinkError::WantMore {
				server_time: resp.server_time(),
			});
		}

		self.finalized = true;
		Ok(())
	}
}

#[derive(Debug)]
pub struct AccountLinkSuccess {
	account: SteamGuardAccount,
	server_time: u64,
	phone_number_hint: String,
}

impl AccountLinkSuccess {
	pub fn account(&self) -> &SteamGuardAccount {
		&self.account
	}

	pub fn into_account(self) -> SteamGuardAccount {
		self.account
	}

	pub fn server_time(&self) -> u64 {
		self.server_time
	}

	pub fn phone_number_hint(&self) -> &str {
		&self.phone_number_hint
	}
}

fn generate_device_id() -> String {
	format!("android:{}", uuid::Uuid::new_v4())
}

#[derive(Error, Debug)]
pub enum AccountLinkError {
	/// No phone number on the account
	#[error("A phone number is needed, but not already present on the account.")]
	MustProvidePhoneNumber,
	/// User need to click link from confirmation email
	#[error("An email has been sent to the user's email, click the link in that email.")]
	MustConfirmEmail,
	#[error("Authenticator is already present on this account.")]
	AuthenticatorPresent,
	#[error("You are sending too many requests to Steam, and we got rate limited. Wait at least a couple hours and try again.")]
	RateLimitExceeded,
	#[error("Steam was unable to link the authenticator to the account. No additional information about this error is available. This is a Steam error, not a steamguard-cli error. Try adding a phone number to your Steam account (which you can do here: https://store.steampowered.com/phone/add), or try again later.")]
	GenericFailure,
	#[error("Steam returned an unexpected error code: {0:?}")]
	UnknownEResult(EResult),
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

impl From<EResult> for AccountLinkError {
	fn from(result: EResult) -> Self {
		match result {
			EResult::RateLimitExceeded => AccountLinkError::RateLimitExceeded,
			EResult::NoVerifiedPhone => AccountLinkError::MustProvidePhoneNumber,
			EResult::DuplicateRequest => AccountLinkError::AuthenticatorPresent,
			// If the user has no phone number on their account, it will always return this status code.
			// However, this does not mean that this status just means "no phone number". It can also
			// be literally anything else, so that's why we return GenericFailure here.
			// update 2023: This may be no longer true, now it seems to return NoVerifiedPhone if there is no phone number. We'll see.
			EResult::Fail => AccountLinkError::GenericFailure,
			r => AccountLinkError::UnknownEResult(r),
		}
	}
}

#[derive(Error, Debug)]
pub enum FinalizeLinkError {
	#[error("Provided SMS code was incorrect.")]
	BadSmsCode,
	/// Steam wants more 2fa codes to verify that we can generate valid codes. Call finalize again.
	#[error("Steam wants more 2fa codes for verification.")]
	WantMore { server_time: u64 },
	#[error("Steam returned an unexpected error code: {0:?}")]
	UnknownEResult(EResult),
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

impl From<EResult> for FinalizeLinkError {
	fn from(result: EResult) -> Self {
		match result {
			EResult::TwoFactorActivationCodeMismatch => FinalizeLinkError::BadSmsCode,
			r => FinalizeLinkError::UnknownEResult(r),
		}
	}
}
