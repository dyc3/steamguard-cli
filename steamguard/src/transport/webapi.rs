use log::{debug, trace};
use protobuf::MessageFull;
use reqwest::Url;

use super::Transport;
use crate::steamapi::{ApiRequest, ApiResponse, BuildableRequest, EResult};

lazy_static! {
	static ref STEAM_COOKIE_URL: Url = "https://steamcommunity.com".parse::<Url>().unwrap();
	static ref STEAM_API_BASE: String = "https://api.steampowered.com".into();
}

#[derive(Debug)]
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
		debug!("HTTP Request: {} {}", Req::method(), url);
		let mut req = self.client.request(Req::method(), &url);
		req = apireq.request_data().build(req);

		let resp = req.send()?;
		debug!("Response HTTP status: {}", resp.status());

		let eresult = if let Some(eresult) = resp.headers().get("x-eresult") {
			debug!("HTTP Header x-eresult: {}", eresult.to_str()?);
			eresult.to_str()?.parse::<i32>()?.into()
		} else {
			EResult::Invalid
		};
		let error_msg = if let Some(error_message) = resp.headers().get("x-error_message") {
			debug!("HTTP Header x-error_message: {}", error_message.to_str()?);
			Some(error_message.to_str()?.to_owned())
		} else {
			None
		};

		let bytes = resp.bytes()?;
		trace!("Response body: {:?}", bytes);
		let res = Res::parse_from_bytes(bytes.as_ref())?;
		let api_resp = ApiResponse {
			result: eresult,
			error_message: error_msg,
			response_data: res,
		};

		return Ok(api_resp);
	}

	fn close(&mut self) {}
}
