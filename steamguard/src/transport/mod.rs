pub mod webapi;

use protobuf::MessageFull;
pub use webapi::WebApiTransport;

use crate::steamapi::{ApiRequest, ApiResponse, BuildableRequest};

pub trait Transport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		req: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError>;

	fn close(&mut self);

	fn into_http_client(&self) -> anyhow::Result<reqwest::blocking::Client> {
		bail!("Transport does not support extracting HTTP client")
	}
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
	#[error("Transport failed to parse response headers")]
	HeaderParseFailure {
		header: String,
		#[source]
		source: anyhow::Error,
	},
	#[error("Transport failed to parse response body")]
	ProtobufError(#[from] protobuf::Error),
	#[error("Unauthorized: Access token is missing or invalid")]
	Unauthorized,
	#[error("NetworkFailure: Transport failed to make request: {0}")]
	NetworkFailure(#[from] reqwest::Error),
	#[error("Unexpected error when transport was making request: {0}")]
	Unknown(#[from] anyhow::Error),
}
