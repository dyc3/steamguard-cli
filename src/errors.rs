use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum UserError {
	#[error("User aborted the operation.")]
	Aborted
}