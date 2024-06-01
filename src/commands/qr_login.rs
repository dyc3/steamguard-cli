use std::{
	path::{Path, PathBuf},
	sync::{Arc, Mutex},
};

use log::*;
use rqrr::PreparedImage;
use steamguard::{QrApprover, QrApproverError};

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Log in to Steam on another device using the QR code that it's displaying.")]
pub struct QrLoginCommand {
	#[clap(flatten)]
	login_url_source: LoginUrlSource,
}

impl<T> AccountCommand<T> for QrLoginCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		_manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
		ensure!(
			accounts.len() == 1,
			"You can only log in to one account at a time."
		);
		// FIXME: in clap v4, this constraint can be expressed as a arg group: https://stackoverflow.com/questions/76315540/how-do-i-require-one-of-the-two-clap-options
		ensure!(
			self.login_url_source.url.is_some() || self.login_url_source.image.is_some(),
			"You must provide either a URL with --url or an image file with --image."
		);

		let mut account = accounts[0].lock().unwrap();

		info!("Approving login to {}", account.account_name);

		if account.tokens.is_none() {
			crate::do_login(transport.clone(), &mut account, args.password.clone())?;
		}

		let url = self.login_url_source.url()?;
		debug!("Using login URL to approve: {}", url);
		loop {
			let Some(tokens) = account.tokens.as_ref() else {
				error!(
					"No tokens found for {}. Can't approve login if we aren't logged in ourselves.",
					account.account_name
				);
				return Err(anyhow!("No tokens found for {}", account.account_name));
			};

			let mut approver = QrApprover::new(transport.clone(), tokens);
			match approver.approve(&account, url.to_owned()) {
				Ok(_) => {
					info!("Login approved.");
					break;
				}
				Err(QrApproverError::Unauthorized) => {
					warn!("tokens are invalid. Attempting to log in again.");
					crate::do_login(transport.clone(), &mut account, args.password.clone())?;
				}
				Err(e) => {
					error!("Failed to approve login: {}", e);
					break;
				}
			}
		}

		Ok(())
	}
}

#[derive(Debug, Clone, clap::Args)]
pub struct LoginUrlSource {
	/// The URL that would normally open in the Steam app. This is the URL that the QR code is displaying. It should start with \"https://s.team/...\"
	#[clap(long)]
	url: Option<String>,
	/// Path to an image file containing the QR code. The QR code will be scanned from this image.
	#[clap(long)]
	image: Option<PathBuf>,
}

impl LoginUrlSource {
	fn url(&self) -> anyhow::Result<String> {
		match self {
			Self { url: Some(url), .. } => Ok(url.clone()),
			Self {
				image: Some(path), ..
			} => read_qr_image(path),
			_ => Err(anyhow!(
				"You must provide either a URL with --url or an image file with --image."
			)),
		}
	}
}

fn read_qr_image(path: &Path) -> anyhow::Result<String> {
	use image::io::Reader as ImageReader;
	let image = ImageReader::open(path)?.decode()?.to_luma8();
	let mut img = PreparedImage::prepare(image);
	let grids = img.detect_grids();
	for grid in grids {
		let (_meta, text) = grid.decode()?;
		// a rough validation that the QR code is a Steam login code
		if text.contains("s.team") {
			return Ok(text);
		}
	}
	Err(anyhow!("No Steam login url found in the QR code"))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::Path;

	#[test]
	fn test_read_qr_image() {
		let path = Path::new("src/fixtures/qr-codes/login-qr.png");
		let url = read_qr_image(path).unwrap();
		assert_eq!(url, "https://s.team/q/1/2372462679780599330");
	}
}
