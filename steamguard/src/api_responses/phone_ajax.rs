use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PhoneValidateResponse {
	success: bool,
	number: String,
	is_valid: bool,
	is_voip: bool,
	is_fixed: bool,
}
