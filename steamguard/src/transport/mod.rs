pub mod webapi;

use serde::{Deserialize, Serialize};
pub use webapi::WebApiTransport;

use crate::steamapi::{ApiRequest, ApiResponse};

pub trait Transport {
	fn send_request<'a, Req: Serialize, Res: Deserialize<'a>>(
		&mut self,
		req: ApiRequest<Req>,
	) -> anyhow::Result<ApiResponse<Res>>;

	fn close(&mut self);
}
