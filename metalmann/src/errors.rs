use reqwest::header::{HeaderValue, HeaderName};

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("A Steam Web API key is required for this, call metalmann::webapi::set_web_api_key() first")]
	WebApiKeyNotSet,
	#[error("API requiest failed: {0}")]
	NetworkFailure(#[from] reqwest::Error),
	#[error("Failed to parse API response body: {0}")]
	MalformedBody(#[from] serde_json::Error),
	#[error("Failed to parse API response header: {header:?}={value:?}")]
	MalformedHeader{
		header: HeaderName,
		value: HeaderValue,
		source: anyhow::Error,
	},
	#[error("API returned a non-success: {0}")]
	ApiError(String),
	#[error("The requested resource has not been modified, use a cached version.")]
	NotModified,
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

#[macro_export]
macro_rules! require_web_api_key {
	() => {
		{
			let apikey = webapi::get_web_api_key();
			if apikey.is_none() {
				return Err(crate::errors::Error::WebApiKeyNotSet);
			}
			apikey.unwrap()
		}
	};
}
