use crate::{
	protobufs::{
		custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
		steammessages_auth_steamclient::*,
	},
	token::Jwt,
	transport::{Transport, TransportError},
};

const SERVICE_NAME: &str = "IAuthenticationService";

use super::{ApiRequest, ApiResponse, BuildableRequest};

#[derive(Debug, Clone)]
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
	) -> Result<ApiResponse<CAuthentication_BeginAuthSessionViaCredentials_Response>, TransportError>
	{
		let req = ApiRequest::new(SERVICE_NAME, "BeginAuthSessionViaCredentials", 1u32, req);
		let resp = self.transport.send_request::<
			CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
			CAuthentication_BeginAuthSessionViaCredentials_Response>(req)?;
		Ok(resp)
	}

	pub fn begin_auth_session_via_qr(
		&mut self,
		req: CAuthentication_BeginAuthSessionViaQR_Request,
	) -> Result<ApiResponse<CAuthentication_BeginAuthSessionViaQR_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "BeginAuthSessionViaQR", 1u32, req);
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
	) -> Result<ApiResponse<CAuthentication_AccessToken_GenerateForApp_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "GenerateAccessTokenForApp", 1u32, req)
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
	) -> Result<ApiResponse<CAuthentication_GetPasswordRSAPublicKey_Response>, TransportError> {
		let mut inner = CAuthentication_GetPasswordRSAPublicKey_Request::new();
		inner.set_account_name(account_name);
		let req = ApiRequest::new(SERVICE_NAME, "GetPasswordRSAPublicKey", 1u32, inner);
		let resp = self
			.transport
			.send_request::<CAuthentication_GetPasswordRSAPublicKey_Request, CAuthentication_GetPasswordRSAPublicKey_Response>(
				req,
			)?;

		Ok(resp)
	}

	pub fn get_auth_sessions_for_account(
		&self,
		req: CAuthentication_GetAuthSessionsForAccount_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CAuthentication_GetAuthSessionsForAccount_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "GetAuthSessionsForAccount", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CAuthentication_GetAuthSessionsForAccount_Request, CAuthentication_GetAuthSessionsForAccount_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn get_auth_session_info(
		&self,
		req: CAuthentication_GetAuthSessionInfo_Request,
		access_token: &Jwt,
	) -> Result<ApiResponse<CAuthentication_GetAuthSessionInfo_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "GetAuthSessionInfo", 1u32, req)
			.with_access_token(access_token);
		let resp = self
			.transport
			.send_request::<CAuthentication_GetAuthSessionInfo_Request, CAuthentication_GetAuthSessionInfo_Response>(
				req,
			)?;
		Ok(resp)
	}

	pub fn migrate_mobile_session(
		&mut self,
		req: CAuthentication_MigrateMobileSession_Request,
	) -> Result<ApiResponse<CAuthentication_MigrateMobileSession_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "MigrateMobileSession", 1u32, req);
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
	) -> Result<ApiResponse<CAuthentication_PollAuthSessionStatus_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "PollAuthSessionStatus", 1u32, req);
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
	) -> Result<ApiResponse<CAuthentication_RefreshToken_Revoke_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "RevokeRefreshToken", 1u32, req);
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
	) -> Result<ApiResponse<CAuthenticationSupport_RevokeToken_Response>, TransportError> {
		let req = ApiRequest::new(SERVICE_NAME, "RevokeToken", 1u32, req);
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
		access_token: &Jwt,
	) -> Result<
		ApiResponse<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response>,
		TransportError,
	> {
		let req = ApiRequest::new(
			SERVICE_NAME,
			"UpdateAuthSessionWithMobileConfirmation",
			1u32,
			req,
		)
		.with_access_token(access_token);
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
	) -> Result<
		ApiResponse<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response>,
		TransportError,
	> {
		let req = ApiRequest::new(
			SERVICE_NAME,
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

impl BuildableRequest for CAuthentication_GetAuthSessionsForAccount_Request {
	fn method() -> reqwest::Method {
		reqwest::Method::GET
	}

	fn requires_access_token() -> bool {
		true
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
