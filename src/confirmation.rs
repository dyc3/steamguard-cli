/// A mobile confirmation. There are multiple things that can be confirmed, like trade offers.
#[derive(Debug, Clone)]
pub struct Confirmation {
	pub id: u64,
	pub key: u64,
	/// Comes from the `data-type` attribute in the HTML
	pub int_type: i32,
	/// Trade offer ID or market transaction ID
	pub creator: u64,
	pub conf_type: ConfirmationType,
	pub description: String,
}

#[derive(Debug, Clone, Copy)]
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
