use serde::Deserialize;

use crate::protobufs::steammessages_auth_steamclient::{
	CAuthentication_AllowedConfirmation, EAuthSessionGuardType,
};

#[derive(Deserialize, Debug, Clone)]
pub struct AllowedConfirmation {
	pub confirmation_type: EAuthSessionGuardType,
	pub associated_messsage: String,
}

impl From<AllowedConfirmation> for CAuthentication_AllowedConfirmation {
	fn from(resp: AllowedConfirmation) -> Self {
		let mut inner = Self::new();
		inner.set_confirmation_type(resp.confirmation_type);
		inner.set_associated_message(resp.associated_messsage);
		inner
	}
}

impl From<CAuthentication_AllowedConfirmation> for AllowedConfirmation {
	fn from(mut resp: CAuthentication_AllowedConfirmation) -> Self {
		Self {
			confirmation_type: resp.confirmation_type(),
			associated_messsage: resp.take_associated_message(),
		}
	}
}
