/// A mobile confirmation. There are multiple things that can be confirmed, like trade offers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Confirmation {
	pub id: u64,
	pub key: u64,
	/// Trade offer ID or market transaction ID
	pub creator: u64,
	pub conf_type: ConfirmationType,
}

impl Confirmation {
	/// Human readable representation of this confirmation.
	pub fn description(&self) -> String {
		format!("{:?} id={} key={}", self.conf_type, self.id, self.key)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationType {
	Generic = 1,
	Trade = 2,
	MarketSell = 3,
	AccountRecovery = 6,
	Unknown
}

impl From<&str> for ConfirmationType {
	fn from(text: &str) -> Self {
		match text {
			"1" => ConfirmationType::Generic,
			"2" => ConfirmationType::Trade,
			"3" => ConfirmationType::MarketSell,
			"6" => ConfirmationType::AccountRecovery,
			_ => ConfirmationType::Unknown,
		}
	}
}
