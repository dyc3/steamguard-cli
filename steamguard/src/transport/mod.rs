pub mod webapi;

use protobuf::MessageFull;
use serde::{Deserialize, Serialize};
pub use webapi::WebApiTransport;

use crate::steamapi::{ApiRequest, ApiResponse, BuildableRequest};

pub trait Transport {
	fn send_request<Req: BuildableRequest, Res: MessageFull>(
		&mut self,
		req: ApiRequest<Req>,
	) -> anyhow::Result<ApiResponse<Res>>;

	fn close(&mut self);
}
