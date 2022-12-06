mod ITwoFactorService;
mod login;
mod phone_ajax;

pub use login::*;
pub use phone_ajax::*;
pub use ITwoFactorService::*;

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
