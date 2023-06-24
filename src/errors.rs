use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum UserError {
	#[error("User aborted the operation.")]
	Aborted,
}

#[derive(Debug, Error)]
pub struct CustomJsonError(serde_json::Error);

impl std::fmt::Display for CustomJsonError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "JSON error: {}", self.0)
	}
}

impl CustomJsonError {}
