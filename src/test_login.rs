use std::sync::{Arc, Mutex};

use log::info;
use qrcode::QrCode;
use steamguard::{
	protobufs::steammessages_auth_steamclient::{
		CAuthentication_AccessToken_GenerateForApp_Request, EAuthTokenPlatformType,
	},
	steamapi::authentication::AuthenticationClient,
	transport::WebApiTransport,
	SteamGuardAccount, UserLogin,
};

use crate::{build_device_details, do_login};

pub fn do_subcmd_test_login(
	selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> anyhow::Result<()> {
	for account in selected_accounts {
		let mut account = account.lock().unwrap();
		do_login(&mut account)?;
		info!("Logged in successfully!");
	}
	Ok(())
}
