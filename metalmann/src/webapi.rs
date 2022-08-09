use once_cell::sync::Lazy;
use std::sync::Mutex;

static GLOBAL_STEAM_WEB_API_KEY: Lazy<Mutex<Option<String>>> = Lazy::new(|| { Mutex::new(None) });

pub fn set_web_api_key(key: String) {
	let mut k = GLOBAL_STEAM_WEB_API_KEY.lock().unwrap();
	*k = Some(key);
}

pub(crate) fn get_web_api_key() -> Option<String> {
	GLOBAL_STEAM_WEB_API_KEY.lock().unwrap().clone()
}
