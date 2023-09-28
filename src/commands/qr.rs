use std::sync::{Arc, Mutex};

use log::*;
use qrcode::QrCode;
use secrecy::ExposeSecret;

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Generate QR codes. This *will* print sensitive data to stdout.")]
pub struct QrCommand {
	#[clap(
		long,
		help = "Force using ASCII chars to generate QR codes. Useful for terminals that don't support unicode."
	)]
	pub ascii: bool,
}

impl<T> AccountCommand<T> for QrCommand
where
	T: Transport,
{
	fn execute(
		&self,
		_transport: T,
		_manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		_args: &GlobalArgs,
	) -> anyhow::Result<()> {
		use anyhow::Context;

		info!("Generating QR codes for {} accounts", accounts.len());

		for account in accounts {
			let account = account.lock().unwrap();
			let qr = QrCode::new(account.uri.expose_secret())
				.context(format!("generating qr code for {}", account.account_name))?;

			info!("Printing QR code for {}", account.account_name);
			let qr_string = if self.ascii {
				qr.render()
					.light_color(' ')
					.dark_color('#')
					.module_dimensions(2, 1)
					.build()
			} else {
				use qrcode::render::unicode;
				qr.render::<unicode::Dense1x2>()
					.dark_color(unicode::Dense1x2::Light)
					.light_color(unicode::Dense1x2::Dark)
					.build()
			};

			println!("{}", qr_string);
		}
		Ok(())
	}
}
