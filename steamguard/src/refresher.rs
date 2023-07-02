use crate::{
	protobufs::steammessages_auth_steamclient::CAuthentication_AccessToken_GenerateForApp_Request,
	steamapi::{AuthenticationClient, EResult},
	token::{Jwt, Tokens},
	transport::Transport,
};

pub struct TokenRefresher<T>
where
	T: Transport,
{
	client: AuthenticationClient<T>,
}

impl<T> TokenRefresher<T>
where
	T: Transport,
{
	pub fn new(client: AuthenticationClient<T>) -> Self {
		Self { client }
	}

	pub fn refresh(&mut self, steam_id: u64, tokens: &Tokens) -> Result<Jwt, anyhow::Error> {
		let mut req = CAuthentication_AccessToken_GenerateForApp_Request::new();
		req.set_steamid(steam_id);
		req.set_refresh_token(tokens.refresh_token().expose_secret().to_owned());

		let resp = self
			.client
			.generate_access_token(req, tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(anyhow::anyhow!(
				"Failed to refresh access token: {:?}",
				resp.result
			));
		}

		let mut resp = resp.into_response_data();

		Ok(resp.take_access_token().into())
	}
}
