use reqwest::Url;
use serde::{Deserialize, Serialize};

use super::Transport;
use crate::{
	api_responses::SteamApiResponse,
	steamapi::{ApiRequest, ApiResponse},
};

lazy_static! {
	static ref STEAM_COOKIE_URL: Url = "https://steamcommunity.com".parse::<Url>().unwrap();
	static ref STEAM_API_BASE: String = "https://api.steampowered.com".into();
}

pub struct WebApiTransport {
	cookies: reqwest::cookie::Jar,
	client: reqwest::blocking::Client,
}

impl WebApiTransport {
	pub fn new() -> WebApiTransport {
		return WebApiTransport {
			cookies: reqwest::cookie::Jar::default(),
			client: reqwest::blocking::Client::new(),
		};
	}
}

impl Transport for WebApiTransport {
	fn send_request<'a, Req: Serialize, Res: Deserialize<'a>>(
		&mut self,
		apireq: ApiRequest<Req>,
	) -> anyhow::Result<ApiResponse<Res>> {
		let url = apireq.build_url();
		let mut req = self.client.post(&url);
		if let Some(data) = apireq.request_data() {
			req = req.form(&data);
		}

		let resp = req.send()?;

		let json = resp.json::<SteamApiResponse<Res>>()?;

		let mut api_resp = ApiResponse::new();
		api_resp.set_response_data(json.response);
		if let Some(eresult) = resp.headers().get("x-eresult") {
			api_resp.set_result(eresult.to_str()?.parse::<i32>()?);
		}
		if let Some(error_message) = resp.headers().get("x-error_message") {
			api_resp.set_error_message(error_message.to_str()?.to_owned());
		}
		return Ok(api_resp);
	}

	fn close(&mut self) {}
}
