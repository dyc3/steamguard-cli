use log::*;
use steamguard::{Confirmation, ConfirmationType};

use crate::{debug::parse_json_stripped, tui};

use super::*;

#[derive(Debug, Clone, Parser, Default)]
#[clap(about = "Debug stuff, not useful for most users.")]
pub struct DebugCommand {
	#[clap(long, help = "Show a text prompt.")]
	pub demo_prompt: bool,
	#[clap(long, help = "Show a \"press any key\" prompt.")]
	pub demo_pause: bool,
	#[clap(long, help = "Show a character prompt.")]
	pub demo_prompt_char: bool,
	#[clap(long, help = "Show an example confirmation menu using dummy data.")]
	pub demo_conf_menu: bool,

	#[clap(
		long,
		help = "Read the specified file, parse it, strip values, and print the result."
	)]
	pub print_stripped_json: Option<String>,
}

impl ConstCommand for DebugCommand {
	fn execute(&self) -> anyhow::Result<()> {
		if self.demo_prompt {
			demo_prompt();
		}
		if self.demo_pause {
			demo_pause();
		}
		if self.demo_prompt_char {
			demo_prompt_char();
		}
		if self.demo_conf_menu {
			demo_confirmation_menu();
		}
		if let Some(path) = self.print_stripped_json.as_ref() {
			debug_print_json(&path)?;
		}
		Ok(())
	}
}

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

fn debug_print_json(path: &str) -> anyhow::Result<()> {
	let json = std::fs::read_to_string(path)?;
	let v = parse_json_stripped(&json)?;
	println!("{}", serde_json::to_string_pretty(&v)?);

	Ok(())
}
