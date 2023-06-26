use serde::Deserialize;

/// A mobile confirmation. There are multiple things that can be confirmed, like trade offers.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Confirmation {
	#[serde(rename = "type")]
	pub conf_type: ConfirmationType,
	pub type_name: String,
	pub id: String,
	/// Trade offer ID or market transaction ID
	pub creator_id: String,
	pub nonce: String,
	pub creation_time: u64,
	pub cancel: String,
	pub accept: String,
	pub icon: Option<String>,
	pub multi: bool,
	pub headline: String,
	pub summary: Vec<String>,
}

impl Confirmation {
	/// Human readable representation of this confirmation.
	pub fn description(&self) -> String {
		format!(
			"{:?} - {} - {}",
			self.conf_type,
			self.headline,
			self.summary.join(", ")
		)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[repr(u32)]
#[serde(from = "u32")]
pub enum ConfirmationType {
	Generic = 1,
	Trade = 2,
	MarketSell = 3,
	AccountDetails = 5,
	AccountRecovery = 6,
	Unknown(u32),
}

impl From<u32> for ConfirmationType {
	fn from(text: u32) -> Self {
		match text {
			1 => ConfirmationType::Generic,
			2 => ConfirmationType::Trade,
			3 => ConfirmationType::MarketSell,
			6 => ConfirmationType::AccountRecovery,
			v => ConfirmationType::Unknown(v),
		}
	}
}

#[derive(Debug, Deserialize)]
pub struct ConfirmationListResponse {
	pub success: bool,
	pub conf: Vec<Confirmation>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct SendConfirmationResponse {
	pub success: bool,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_confirmations() -> anyhow::Result<()> {
		struct Test {
			text: &'static str,
			confirmation_type: ConfirmationType,
		}
		let cases = [
			Test {
				text: include_str!("fixtures/confirmations/email-change.json"),
				confirmation_type: ConfirmationType::AccountRecovery,
			},
			Test {
				text: include_str!("fixtures/confirmations/phone-number-change.json"),
				confirmation_type: ConfirmationType::AccountDetails,
			},
		];
		for case in cases.iter() {
			let confirmations = serde_json::from_str::<ConfirmationListResponse>(case.text)?;

			assert_eq!(confirmations.conf.len(), 1);

			let confirmation = &confirmations.conf[0];

			assert_eq!(confirmation.conf_type, case.confirmation_type);
		}

		Ok(())
	}
}
