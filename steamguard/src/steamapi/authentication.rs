use crate::protobufs::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request;

use super::BuildableRequest;

impl BuildableRequest for CAuthentication_GetPasswordRSAPublicKey_Request {
	fn method() -> reqwest::Method {
		reqwest::Method::GET
	}

	fn build(&self, req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
		req.query(&[("account_name", self.account_name())])
	}
}
