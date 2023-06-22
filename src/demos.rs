use crate::tui;
use log::*;
use steamguard::{Confirmation, ConfirmationType};

pub fn demo_prompt() {
	print!("Prompt: ");
	let result = tui::prompt();
	println!("Result: {}", result);
}

pub fn demo_pause() {
	let mut x = 0;
	loop {
		tui::pause();
		x += 1;
		println!("looped {} times", x);
	}
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
			id: "1234".to_owned(),
			nonce: "12345".to_owned(),
			conf_type: ConfirmationType::Trade,
			creator_id: "09870987".to_owned(),
			headline: "example confirmation".into(),
			type_name: "Trade".to_owned(),
			creation_time: 1687457923,
			cancel: "Cancel".to_owned(),
			accept: "Confirm".to_owned(),
			icon: "".to_owned(),
			multi: false,
			summary: vec![],
		},
		Confirmation {
			id: "1234".to_owned(),
			nonce: "12345".to_owned(),
			conf_type: ConfirmationType::MarketSell,
			creator_id: "09870987".to_owned(),
			headline: "example confirmation".into(),
			type_name: "Market Sell".to_owned(),
			creation_time: 1687457923,
			cancel: "Cancel".to_owned(),
			accept: "Confirm".to_owned(),
			icon: "".to_owned(),
			multi: false,
			summary: vec![],
		},
	])
	.expect("confirmation menu demo failed");
	println!("accept: {}, deny: {}", accept.len(), deny.len());
}
