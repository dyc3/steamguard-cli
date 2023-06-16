use log::trace;
use protobuf::{MessageDyn, MessageFull};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use super::Transport;
use crate::{
	api_responses::SteamApiResponse,
	steamapi::{ApiRequest, ApiResponse, BuildableRequest},
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
	fn send_request<Req: BuildableRequest, Res: MessageFull>(
		&mut self,
		apireq: ApiRequest<Req>,
	) -> anyhow::Result<ApiResponse<Res>> {
		let url = apireq.build_url();
		let mut req = self.client.request(Req::method(), &url);
		req = apireq.request_data().build(req);

		let resp = req.send()?;

		let mut api_resp = ApiResponse::new();
		if let Some(eresult) = resp.headers().get("x-eresult") {
			api_resp.set_result(eresult.to_str()?.parse::<i32>()?);
		}
		if let Some(error_message) = resp.headers().get("x-error_message") {
			api_resp.set_error_message(error_message.to_str()?.to_owned());
		}
		let bytes = resp.bytes()?;
		eprintln!("Response: {:?}", bytes);
		let res = Res::parse_from_bytes(bytes.as_ref())?;
		api_resp.set_response_data(res);
		return Ok(api_resp);
	}

	fn close(&mut self) {}
}
