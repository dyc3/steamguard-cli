mod i_authentication_service;
mod i_two_factor_service;
mod login;
mod phone_ajax;

pub use i_authentication_service::*;
pub use i_two_factor_service::*;
pub use login::*;
pub use phone_ajax::*;

use serde::{Deserialize, Deserializer};

pub(crate) fn parse_json_string_as_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
	D: Deserializer<'de>,
{
	// for some reason, deserializing to &str doesn't work but this does.
	let s: String = Deserialize::deserialize(deserializer)?;
	Ok(s.parse().unwrap())
}

#[derive(Debug, Clone, Deserialize)]
pub struct SteamApiResponse<T> {
	pub response: T,
}
