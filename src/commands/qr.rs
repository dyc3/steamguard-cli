use std::sync::{Arc, Mutex};

use base64::Engine;
use log::*;
use qrcode::QrCode;
use secrecy::ExposeSecret;

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub(crate) enum QrFormat {
	/// The default Steam otpauth URI
	Steam,
	/// Bitwarden-compatible format: steam://<secret>
	Bitwarden,
	/// KeePassXC-compatible otpauth URI with period, digits, and encoder parameters
	KeePassXc,
}

#[derive(Debug, Clone, Parser)]
#[clap(about = "Generate QR codes. This *will* print sensitive data to stdout.")]
pub struct QrCommand {
	#[clap(
		long,
		help = "Force using ASCII chars to generate QR codes. Useful for terminals that don't support unicode."
	)]
	pub ascii: bool,

	/// Output format for the QR code content.
	#[clap(long, value_enum, default_value = "steam")]
	pub format: QrFormat,
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
			let secret_b64 = base64::engine::general_purpose::STANDARD
				.encode(account.shared_secret.expose_secret());

			let qr_content: String = match self.format {
				QrFormat::Steam => account.uri.expose_secret().to_owned(),
				QrFormat::Bitwarden => format!("steam://{}", secret_b64),
				QrFormat::KeePassXc => {
					let username = percent_encode_username(&account.account_name);
					format!(
						"otpauth://totp/Steam:{}?secret={}&period=30&digits=5&issuer=Steam&encoder=steam",
						username, secret_b64
					)
				}
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

/// Percent-encode characters that are unsafe in a URI path component.
///
/// Only encodes characters that would structurally break a URI (delimiters,
/// the percent escape character itself, and non-ASCII bytes). Safe unreserved
/// characters (RFC 3986) pass through unchanged.
fn percent_encode_username(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
				out.push(b as char);
			}
			_ => {
				out.push('%');
				out.push_str(&format!("{:02X}", b));
			}
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn percent_encode_username_passes_through_safe_chars() {
		assert_eq!(percent_encode_username("abc123_-"), "abc123_-");
	}

	#[test]
	fn percent_encode_username_encodes_reserved_chars() {
		assert_eq!(percent_encode_username("user?name"), "user%3Fname");
		assert_eq!(percent_encode_username("user&name"), "user%26name");
		assert_eq!(percent_encode_username("user#name"), "user%23name");
		assert_eq!(percent_encode_username("user:name"), "user%3Aname");
		assert_eq!(percent_encode_username("user/name"), "user%2Fname");
		assert_eq!(percent_encode_username("user%20name"), "user%2520name");
	}

	#[test]
	fn percent_encode_username_encodes_space() {
		assert_eq!(percent_encode_username("user name"), "user%20name");
	}

	#[test]
	fn percent_encode_username_encodes_non_ascii() {
		assert_eq!(percent_encode_username("usér"), "us%C3%A9r");
	}
}
