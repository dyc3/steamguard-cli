use crate::tui;
use log::*;
use steamguard::{Confirmation, ConfirmationType};

pub fn demo_confirmation_menu() {
	info!("showing demo menu");
	let (accept, deny) = tui::prompt_confirmation_menu(vec![
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::Trade,
			creator: 09870987,
			description: "example confirmation".into(),
		},
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::MarketSell,
			creator: 09870987,
			description: "example confirmation".into(),
		},
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::AccountRecovery,
			creator: 09870987,
			description: "example confirmation".into(),
		},
		Confirmation {
			id: 1234,
			key: 12345,
			conf_type: ConfirmationType::Trade,
			creator: 09870987,
			description: "example confirmation".into(),
		},
	]);
	println!("accept: {}, deny: {}", accept.len(), deny.len());
}
