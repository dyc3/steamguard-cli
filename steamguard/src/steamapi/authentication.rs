use crate::{
	protobufs::{
		custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
		steammessages_auth_steamclient::{
			CAuthenticationSupport_RevokeToken_Request,
			CAuthenticationSupport_RevokeToken_Response,
			CAuthentication_AccessToken_GenerateForApp_Request,
			CAuthentication_AccessToken_GenerateForApp_Response,
			CAuthentication_BeginAuthSessionViaCredentials_Request,
			CAuthentication_BeginAuthSessionViaCredentials_Response,
			CAuthentication_BeginAuthSessionViaQR_Request,
			CAuthentication_BeginAuthSessionViaQR_Response,
			CAuthentication_GetAuthSessionInfo_Request,
			CAuthentication_GetPasswordRSAPublicKey_Request,
			CAuthentication_GetPasswordRSAPublicKey_Response,
			CAuthentication_MigrateMobileSession_Request,
			CAuthentication_MigrateMobileSession_Response,
			CAuthentication_PollAuthSessionStatus_Request,
			CAuthentication_PollAuthSessionStatus_Response,
			CAuthentication_RefreshToken_Revoke_Request,
			CAuthentication_RefreshToken_Revoke_Response,
			CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
			CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response,
			CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
			CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, EAuthSessionGuardType,
		},
	},
	token::Jwt,
	transport::Transport,
};

use super::{ApiRequest, ApiResponse, BuildableRequest};

#[derive(Debug)]
pub struct AuthenticationClient<T>
where
	T: Transport,
{
	transport: T,
}

impl<T> AuthenticationClient<T>
where
	T: Transport,
{
	#[must_use]
	pub fn new(transport: T) -> Self {
		Self { transport }
	}

	pub fn begin_auth_session_via_credentials(
		&mut self,
		req: CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
	) -> anyhow::Result<ApiResponse<CAuthentication_BeginAuthSessionViaCredentials_Response>> {
		let req = ApiRequest::new(
			"Authentication",
			"BeginAuthSessionViaCredentials",
			1u32,
			req,
		);
		let resp = self.transport.send_request::<
			CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
			CAuthentication_BeginAuthSessionViaCredentials_Response>(req)?;
		Ok(resp)
	}

	pub fn begin_auth_session_via_qr(
		&mut self,
		req: CAuthentication_BeginAuthSessionViaQR_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_BeginAuthSessionViaQR_Response>> {
		let req = ApiRequest::new("Authentication", "BeginAuthSessionViaQR", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_BeginAuthSessionViaQR_Request, CAuthentication_BeginAuthSessionViaQR_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn generate_access_token(
		&mut self,
		req: CAuthentication_AccessToken_GenerateForApp_Request,
		access_token: &Jwt,
	) -> anyhow::Result<ApiResponse<CAuthentication_AccessToken_GenerateForApp_Response>> {
		let req = ApiRequest::new("Authentication", "GenerateAccessTokenForApp", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CAuthentication_AccessToken_GenerateForApp_Request, CAuthentication_AccessToken_GenerateForApp_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn fetch_rsa_key(
		&mut self,
		account_name: String,
	) -> anyhow::Result<ApiResponse<CAuthentication_GetPasswordRSAPublicKey_Response>> {
		let mut inner = CAuthentication_GetPasswordRSAPublicKey_Request::new();
		inner.set_account_name(account_name);
		let req = ApiRequest::new("Authentication", "GetPasswordRSAPublicKey", 1u32, inner);
		let resp = self
			.transport
			.send_request::<CAuthentication_GetPasswordRSAPublicKey_Request, CAuthentication_GetPasswordRSAPublicKey_Response>(
				req,
			)?;

		Ok(resp)
	}

	pub fn migrate_mobile_session(
		&mut self,
		req: CAuthentication_MigrateMobileSession_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_MigrateMobileSession_Response>> {
		let req = ApiRequest::new("Authentication", "MigrateMobileSession", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_MigrateMobileSession_Request, CAuthentication_MigrateMobileSession_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn poll_auth_session(
		&mut self,
		req: CAuthentication_PollAuthSessionStatus_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_PollAuthSessionStatus_Response>> {
		let req = ApiRequest::new("Authentication", "PollAuthSessionStatus", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn revoke_refresh_token(
		&mut self,
		req: CAuthentication_RefreshToken_Revoke_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_RefreshToken_Revoke_Response>> {
		let req = ApiRequest::new("Authentication", "RevokeRefreshToken", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthentication_RefreshToken_Revoke_Request, CAuthentication_RefreshToken_Revoke_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn revoke_access_token(
		&mut self,
		req: CAuthenticationSupport_RevokeToken_Request,
	) -> anyhow::Result<ApiResponse<CAuthenticationSupport_RevokeToken_Response>> {
		let req = ApiRequest::new("Authentication", "RevokeToken", 1u32, req);
		let resp = self
			.transport
			.send_request::<CAuthenticationSupport_RevokeToken_Request, CAuthenticationSupport_RevokeToken_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn update_session_with_mobile_confirmation(
		&mut self,
		req: CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response>>
	{
		let req = ApiRequest::new(
			"Authentication",
			"UpdateAuthSessionWithMobileConfirmation",
			1u32,
			req,
		);
		let resp = self
			.transport
			.send_request::<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request, CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn update_session_with_steam_guard_code(
		&mut self,
		req: CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
	) -> anyhow::Result<ApiResponse<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response>> {
		let req = ApiRequest::new(
			"Authentication",
			"UpdateAuthSessionWithSteamGuardCode",
			1u32,
			req,
		);
		let resp = self
			.transport
			.send_request::<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request, CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response>(
				req,
			)?;
		Ok(resp)
	}
}

macro_rules! impl_buildable_req {
	($type:ty, $needs_auth:literal) => {
		impl BuildableRequest for $type {
			fn method() -> reqwest::Method {
				reqwest::Method::POST
			}

			fn requires_access_token() -> bool {
				$needs_auth
			}
		}
	};
}

impl_buildable_req!(
	CAuthentication_BeginAuthSessionViaCredentials_Request,
	false
);
impl_buildable_req!(
	CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
	false
);
impl_buildable_req!(CAuthentication_BeginAuthSessionViaQR_Request, false);
impl_buildable_req!(CAuthentication_AccessToken_GenerateForApp_Request, true);

impl BuildableRequest for CAuthentication_GetPasswordRSAPublicKey_Request {
	fn method() -> reqwest::Method {
		reqwest::Method::GET
	}

	fn requires_access_token() -> bool {
		false
	}
}

impl_buildable_req!(CAuthentication_GetAuthSessionInfo_Request, true);
impl_buildable_req!(CAuthentication_MigrateMobileSession_Request, false);
impl_buildable_req!(CAuthentication_PollAuthSessionStatus_Request, false);
impl_buildable_req!(CAuthentication_RefreshToken_Revoke_Request, true);
impl_buildable_req!(CAuthenticationSupport_RevokeToken_Request, true);
impl_buildable_req!(
	CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
	false
);
impl_buildable_req!(
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
	false
);

impl EAuthSessionGuardType {
	pub fn requires_prompt(self) -> bool {
		match self {
			EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => true,
			EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => true,
			EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => false,
			EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => false,
			_ => false,
		}
	}
}
