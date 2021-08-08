use crate::steamapi::{LoginResponse, RsaResponse, Session, SteamApiClient};
use log::*;
use rsa::{PublicKey, RsaPublicKey};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum LoginError {
	BadRSA,
	BadCredentials,
	NeedCaptcha { captcha_gid: String },
	Need2FA,
	NeedEmail,
	TooManyAttempts,
	NetworkFailure(reqwest::Error),
	OtherFailure(anyhow::Error),
}

impl std::fmt::Display for LoginError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for LoginError {}

impl From<reqwest::Error> for LoginError {
	fn from(err: reqwest::Error) -> Self {
		LoginError::NetworkFailure(err)
	}
}

impl From<anyhow::Error> for LoginError {
	fn from(err: anyhow::Error) -> Self {
		LoginError::OtherFailure(err)
	}
}

/// Handles the user login flow.
#[derive(Debug)]
pub struct UserLogin {
	pub username: String,
	pub password: String,
	pub captcha_required: bool,
	pub captcha_gid: String,
	pub captcha_text: String,
	pub twofactor_code: String,
	pub email_code: String,
	pub steam_id: u64,

	client: SteamApiClient,
}

impl UserLogin {
	pub fn new(username: String, password: String) -> UserLogin {
		return UserLogin {
			username,
			password,
			captcha_required: false,
			captcha_gid: String::from("-1"),
			captcha_text: String::from(""),
			twofactor_code: String::from(""),
			email_code: String::from(""),
			steam_id: 0,
			client: SteamApiClient::new(),
		};
	}

	pub fn login(&mut self) -> anyhow::Result<Session, LoginError> {
		trace!("UserLogin::login");
		if self.captcha_required && self.captcha_text.len() == 0 {
			return Err(LoginError::NeedCaptcha {
				captcha_gid: self.captcha_gid.clone(),
			});
		}

		if self.client.session.is_none() {
			self.client.update_session()?;
		}

		let params = hashmap! {
			"donotcache" => format!(
				"{}",
				SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_secs()
					* 1000
			),
			"username" => self.username.clone(),
		};
		let resp = self
			.client
			.post("https://steamcommunity.com/login/getrsakey")
			.form(&params)
			.send()?;

		let encrypted_password: String;
		let rsa_timestamp: String;
		match resp.json::<RsaResponse>() {
			Ok(rsa_resp) => {
				rsa_timestamp = rsa_resp.timestamp.clone();
				encrypted_password = encrypt_password(rsa_resp, &self.password);
			}
			Err(error) => {
				error!("rsa error: {:?}", error);
				return Err(LoginError::BadRSA);
			}
		}

		trace!("captchagid: {}", self.captcha_gid);
		trace!("captcha_text: {}", self.captcha_text);
		trace!("twofactorcode: {}", self.twofactor_code);
		trace!("emailauth: {}", self.email_code);

		let login_resp: LoginResponse = self.client.login(
			self.username.clone(),
			encrypted_password,
			self.twofactor_code.clone(),
			self.email_code.clone(),
			self.captcha_gid.clone(),
			self.captcha_text.clone(),
			rsa_timestamp,
		)?;

		if login_resp.message.contains("too many login") {
			return Err(LoginError::TooManyAttempts);
		}

		if login_resp.message.contains("Incorrect login") {
			return Err(LoginError::BadCredentials);
		}

		if login_resp.captcha_needed {
			self.captcha_gid = login_resp.captcha_gid.clone();
			return Err(LoginError::NeedCaptcha {
				captcha_gid: self.captcha_gid.clone(),
			});
		}

		if login_resp.emailauth_needed {
			self.steam_id = login_resp.emailsteamid.clone();
			return Err(LoginError::NeedEmail);
		}

		if login_resp.requires_twofactor {
			return Err(LoginError::Need2FA);
		}

		if !login_resp.login_complete {
			return Err(LoginError::BadCredentials);
		}

		if login_resp.needs_transfer_login() {
			self.client.transfer_login(login_resp)?;
		}

		return Ok(self.client.session.clone().unwrap());
	}
}

fn encrypt_password(rsa_resp: RsaResponse, password: &String) -> String {
	let rsa_exponent = rsa::BigUint::parse_bytes(rsa_resp.publickey_exp.as_bytes(), 16).unwrap();
	let rsa_modulus = rsa::BigUint::parse_bytes(rsa_resp.publickey_mod.as_bytes(), 16).unwrap();
	let public_key = RsaPublicKey::new(rsa_modulus, rsa_exponent).unwrap();
	#[cfg(test)]
	let mut rng = rand::rngs::mock::StepRng::new(2, 1);
	#[cfg(not(test))]
	let mut rng = rand::rngs::OsRng;
	let padding = rsa::PaddingScheme::new_pkcs1v15_encrypt();
	let encrypted_password = base64::encode(
		public_key
			.encrypt(&mut rng, padding, password.as_bytes())
			.unwrap(),
	);
	return encrypted_password;
}

#[test]
fn test_encrypt_password() {
	let rsa_resp = RsaResponse{
		success: true,
		publickey_exp: String::from("010001"),
		publickey_mod: String::from("98f9088c1250b17fe19d2b2422d54a1eef0036875301731f11bd17900e215318eb6de1546727c0b7b61b86cefccdcb2f8108c813154d9a7d55631965eece810d4ab9d8a59c486bda778651b876176070598a93c2325c275cb9c17bdbcacf8edc9c18c0c5d59bc35703505ef8a09ed4c62b9f92a3fac5740ce25e490ab0e26d872140e4103d912d1e3958f844264211277ee08d2b4dd3ac58b030b25342bd5c949ae7794e46a8eab26d5a8deca683bfd381da6c305b19868b8c7cd321ce72c693310a6ebf2ecd43642518f825894602f6c239cf193cb4346ce64beac31e20ef88f934f2f776597734bb9eae1ebdf4a453973b6df9d5e90777bffe5db83dd1757b"),
		timestamp: String::from("asdf"),
		token_gid: String::from("asdf"),
	};
	let result = encrypt_password(rsa_resp, &String::from("kelwleofpsm3n4ofc"));
	assert_eq!(result.len(), 344);
	assert_eq!(result, "RUo/3IfbkVcJi1q1S5QlpKn1mEn3gNJoc/Z4VwxRV9DImV6veq/YISEuSrHB3885U5MYFLn1g94Y+cWRL6HGXoV+gOaVZe43m7O92RwiVz6OZQXMfAv3UC/jcqn/xkitnj+tNtmx55gCxmGbO2KbqQ0TQqAyqCOOw565B+Cwr2OOorpMZAViv9sKA/G3Q6yzscU6rhua179c8QjC1Hk3idUoSzpWfT4sHNBW/EREXZ3Dkjwu17xzpfwIUpnBVIlR8Vj3coHgUCpTsKVRA3T814v9BYPlvLYwmw5DW3ddx+2SyTY0P5uuog36TN2PqYS7ioF5eDe16gyfRR4Nzn/7wA==");
}
