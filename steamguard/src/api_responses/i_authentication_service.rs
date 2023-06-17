use serde::Deserialize;

use crate::protobufs::steammessages_auth_steamclient::{
	CAuthenticationSupport_RevokeToken_Response,
	CAuthentication_AccessToken_GenerateForApp_Response, CAuthentication_AllowedConfirmation,
	CAuthentication_BeginAuthSessionViaCredentials_Response,
	CAuthentication_BeginAuthSessionViaQR_Response,
	CAuthentication_GetPasswordRSAPublicKey_Response,
	CAuthentication_MigrateMobileSession_Response, CAuthentication_RefreshToken_Revoke_Response,
	CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, EAuthSessionGuardType,
};

macro_rules! hack_impl_deserialize {
	($source_type:ty, $target_type:ty) => {
		impl<'de> ::serde::Deserialize<'de> for $target_type {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where
				D: serde::Deserializer<'de>,
			{
				let resp = <$source_type>::deserialize(deserializer)?;
				Ok(resp.into())
			}
		}
	};
}

#[derive(Deserialize, Debug)]
pub struct BeginAuthSessionViaCredentialsResponse {
	pub client_id: u64,
	pub request_id: Vec<u8>,
	pub interval: f32,
	pub allowed_confirmations: Vec<AllowedConfirmation>,
	pub steamid: u64,
	pub agreement_session_url: String,
	pub extended_error_message: String,
}

impl From<BeginAuthSessionViaCredentialsResponse>
	for CAuthentication_BeginAuthSessionViaCredentials_Response
{
	fn from(resp: BeginAuthSessionViaCredentialsResponse) -> Self {
		let mut inner = Self::new();
		inner.set_client_id(resp.client_id);
		inner.set_request_id(resp.request_id);
		inner.set_interval(resp.interval);
		inner.allowed_confirmations = resp
			.allowed_confirmations
			.into_iter()
			.map(|i| i.into())
			.collect();
		inner.set_steamid(resp.steamid);
		inner.set_agreement_session_url(resp.agreement_session_url);
		inner.set_extended_error_message(resp.extended_error_message);
		inner
	}
}

hack_impl_deserialize!(
	BeginAuthSessionViaCredentialsResponse,
	CAuthentication_BeginAuthSessionViaCredentials_Response
);

#[derive(Deserialize, Debug)]
pub struct AllowedConfirmation {
	pub confirmation_type: EAuthSessionGuardType,
	pub associated_messsage: String,
}

impl From<AllowedConfirmation> for CAuthentication_AllowedConfirmation {
	fn from(resp: AllowedConfirmation) -> Self {
		let mut inner = Self::new();
		inner.set_confirmation_type(resp.confirmation_type);
		inner.set_associated_message(resp.associated_messsage);
		inner
	}
}

hack_impl_deserialize!(AllowedConfirmation, CAuthentication_AllowedConfirmation);

#[derive(Deserialize, Debug)]
pub struct BeginAuthSessionViaQRResponse {
	pub client_id: u64,
	pub challenge_url: String,
	pub request_id: Vec<u8>,
	pub interval: f32,
	pub allowed_confirmations: Vec<AllowedConfirmation>,
	pub version: i32,
}

impl From<BeginAuthSessionViaQRResponse> for CAuthentication_BeginAuthSessionViaQR_Response {
	fn from(resp: BeginAuthSessionViaQRResponse) -> Self {
		let mut inner = Self::new();
		inner.set_client_id(resp.client_id);
		inner.set_challenge_url(resp.challenge_url);
		inner.set_request_id(resp.request_id);
		inner.set_interval(resp.interval);
		inner.allowed_confirmations = resp
			.allowed_confirmations
			.into_iter()
			.map(|i| i.into())
			.collect();
		inner.set_version(resp.version);
		inner
	}
}

hack_impl_deserialize!(
	BeginAuthSessionViaQRResponse,
	CAuthentication_BeginAuthSessionViaQR_Response
);

#[derive(Deserialize, Debug)]
pub struct GenerateAccessTokenForAppResponse {
	pub access_token: String,
}

impl From<GenerateAccessTokenForAppResponse>
	for CAuthentication_AccessToken_GenerateForApp_Response
{
	fn from(resp: GenerateAccessTokenForAppResponse) -> Self {
		let mut inner = Self::new();
		inner.set_access_token(resp.access_token);
		inner
	}
}

hack_impl_deserialize!(
	GenerateAccessTokenForAppResponse,
	CAuthentication_AccessToken_GenerateForApp_Response
);

#[derive(Deserialize, Debug)]
pub struct GetPasswordRSAPublicKeyResponse {
	pub publickey_mod: String,
	pub publickey_exp: String,
	pub timestamp: u64,
}

impl From<GetPasswordRSAPublicKeyResponse> for CAuthentication_GetPasswordRSAPublicKey_Response {
	fn from(resp: GetPasswordRSAPublicKeyResponse) -> Self {
		let mut inner = Self::new();
		inner.set_publickey_mod(resp.publickey_mod);
		inner.set_publickey_exp(resp.publickey_exp);
		inner.set_timestamp(resp.timestamp);
		inner
	}
}

hack_impl_deserialize!(
	GetPasswordRSAPublicKeyResponse,
	CAuthentication_GetPasswordRSAPublicKey_Response
);

#[derive(Deserialize, Debug)]
pub struct MigrateMobileSessionResponse {
	pub refresh_token: String,
	pub access_token: String,
}

impl From<MigrateMobileSessionResponse> for CAuthentication_MigrateMobileSession_Response {
	fn from(resp: MigrateMobileSessionResponse) -> Self {
		let mut inner = Self::new();
		inner.set_refresh_token(resp.refresh_token);
		inner.set_access_token(resp.access_token);
		inner
	}
}

hack_impl_deserialize!(
	MigrateMobileSessionResponse,
	CAuthentication_MigrateMobileSession_Response
);

#[derive(Deserialize, Debug)]
pub struct RevokeRefreshTokenResponse {}

impl From<RevokeRefreshTokenResponse> for CAuthentication_RefreshToken_Revoke_Response {
	fn from(_: RevokeRefreshTokenResponse) -> Self {
		Self::new()
	}
}

hack_impl_deserialize!(
	RevokeRefreshTokenResponse,
	CAuthentication_RefreshToken_Revoke_Response
);

#[derive(Deserialize, Debug)]
pub struct RevokeTokenResponse {}

impl From<RevokeTokenResponse> for CAuthenticationSupport_RevokeToken_Response {
	fn from(_: RevokeTokenResponse) -> Self {
		Self::new()
	}
}

hack_impl_deserialize!(
	RevokeTokenResponse,
	CAuthenticationSupport_RevokeToken_Response
);

#[derive(Deserialize, Debug)]
pub struct UpdateAuthSessionWithMobileConfirmationResponse {}

impl From<UpdateAuthSessionWithMobileConfirmationResponse>
	for CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response
{
	fn from(_: UpdateAuthSessionWithMobileConfirmationResponse) -> Self {
		Self::new()
	}
}

hack_impl_deserialize!(
	UpdateAuthSessionWithMobileConfirmationResponse,
	CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response
);

#[derive(Deserialize, Debug)]
pub struct UpdateAuthSessionWithSteamGuardCodeResponse {
	pub agreement_session_url: String,
}

impl From<UpdateAuthSessionWithSteamGuardCodeResponse>
	for CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response
{
	fn from(resp: UpdateAuthSessionWithSteamGuardCodeResponse) -> Self {
		let mut inner = Self::new();
		inner.set_agreement_session_url(resp.agreement_session_url);
		inner
	}
}

hack_impl_deserialize!(
	UpdateAuthSessionWithSteamGuardCodeResponse,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response
);
