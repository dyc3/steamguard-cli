use crate::tui;
use log::*;
use steamguard::{Confirmation, ConfirmationType};

pub fn demo_prompt() {
	print!("Prompt: ");
	let result = tui::prompt();
	println!("Result: {}", result);
}

pub fn demo_prompt_char() {
	println!("Showing prompt");
	let result = tui::prompt_char("Continue?", "yn");
	println!("Result: {}", result);
	let result = tui::prompt_char("Continue?", "Yn");
	println!("Result: {}", result);
	let result = tui::prompt_char("Continue?", "yN");
	println!("Result: {}", result);
}

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
	])
	.expect("confirmation menu demo failed");
	println!("accept: {}, deny: {}", accept.len(), deny.len());
}
