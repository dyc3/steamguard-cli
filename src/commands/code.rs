use std::{
	sync::{Arc, Mutex},
	time::{SystemTime, UNIX_EPOCH},
};

use log::*;
use steamguard::{steamapi, SteamGuardAccount};

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Generate 2FA codes")]
pub struct CodeCommand {
	#[clap(
		long,
		help = "Assume the computer's time is correct. Don't ask Steam for the time when generating codes."
	)]
	pub offline: bool,
}

impl<T> AccountCommand<T> for CodeCommand
where
	T: Transport,
{
	fn execute(
		&self,
		transport: T,
		_manager: &mut AccountManager,
		accounts: Vec<Arc<RwLock<SteamGuardAccount>>>,
		_args: &GlobalArgs,
	) -> anyhow::Result<()> {
		let server_time = if self.offline {
			SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
		} else {
			steamapi::get_server_time(transport)?.server_time()
		};
		debug!("Time used to generate codes: {}", server_time);

		for account in accounts {
			let account = account.read().unwrap();
			info!("Generating code for {}", account.account_name);
			trace!("{:?}", account);
			let code = account.generate_code(server_time);
			println!("{}", code);
		}
		Ok(())
	}
}
