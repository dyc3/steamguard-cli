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

	/// Generate QR codes in Bitwarden-compatible format (steam://<secret>).
	#[clap(
		long,
		conflicts_with = "keepassxc",
		help = "Generate QR codes compatible with Bitwarden (steam://<secret>)"
	)]
	pub bitwarden: bool,

	/// Generate QR codes in KeePassXC-compatible format (includes period, digits, encoder parameters).
	#[clap(
		long,
		conflicts_with = "bitwarden",
		help = "Generate QR codes compatible with KeePassXC (otpauth URI with period=30&digits=5&encoder=steam)"
	)]
	pub keepassxc: bool,
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
			let uri_raw = account.uri.expose_secret();

			let qr_content: String = if self.bitwarden {
				let secret = parse_secret_from_uri(uri_raw)
					.context("failed to parse secret from URI")?;
				format!("steam://{}", secret)
			} else if self.keepassxc {
				let (secret, username) = parse_secret_and_username(uri_raw)
					.context("failed to parse URI")?;
				format!(
					"otpauth://totp/Steam:{}?secret={}&period=30&digits=5&issuer=Steam&encoder=steam",
					username, secret
				)
			} else {
				uri_raw.to_owned()
			};

			let qr = QrCode::new(qr_content.as_bytes())
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

/// Extract the `secret` query parameter from an `otpauth://totp/...` URI.
fn parse_secret_from_uri(uri: &str) -> Option<&str> {
	let query = uri.split('?').nth(1)?;
	for pair in query.split('&') {
		if let Some(val) = pair.strip_prefix("secret=") {
			return Some(val);
		}
	}
	None
}

/// Extract the `secret` and `username` from an `otpauth://totp/Steam:username?...` URI.
fn parse_secret_and_username(uri: &str) -> Option<(String, String)> {
	let uri = uri.strip_prefix("otpauth://totp/")?;
	let (path, query) = uri.split_once('?')?;
	let username = path.split_once(':').map(|(_, u)| u).unwrap_or(path).to_string();
	let secret = query
		.split('&')
		.find_map(|pair| pair.strip_prefix("secret="))?;
	Some((secret.to_string(), username))
}
