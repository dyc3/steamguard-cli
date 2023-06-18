use crate::protobufs::steammessages_auth_steamclient::{
	CAuthenticationSupport_RevokeToken_Request, CAuthentication_AccessToken_GenerateForApp_Request,
	CAuthentication_BeginAuthSessionViaCredentials_Request,
	CAuthentication_BeginAuthSessionViaQR_Request, CAuthentication_GetPasswordRSAPublicKey_Request,
	CAuthentication_MigrateMobileSession_Request, CAuthentication_PollAuthSessionStatus_Request,
	CAuthentication_RefreshToken_Revoke_Request,
	CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
};

use super::BuildableRequest;

macro_rules! impl_buildable_req {
	($type:ty) => {
		impl BuildableRequest for $type {
			fn method() -> reqwest::Method {
				reqwest::Method::POST
			}
		}
	};
}

impl_buildable_req!(CAuthentication_BeginAuthSessionViaCredentials_Request);
impl_buildable_req!(CAuthentication_BeginAuthSessionViaQR_Request);
impl_buildable_req!(CAuthentication_AccessToken_GenerateForApp_Request);

impl BuildableRequest for CAuthentication_GetPasswordRSAPublicKey_Request {
	fn method() -> reqwest::Method {
		reqwest::Method::GET
	}
}

impl_buildable_req!(CAuthentication_MigrateMobileSession_Request);
impl_buildable_req!(CAuthentication_PollAuthSessionStatus_Request);
impl_buildable_req!(CAuthentication_RefreshToken_Revoke_Request);
impl_buildable_req!(CAuthenticationSupport_RevokeToken_Request);
impl_buildable_req!(CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request);
impl_buildable_req!(CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request);
