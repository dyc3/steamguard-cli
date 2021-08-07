use log::*;
use reqwest::{
    blocking::RequestBuilder,
    cookie::CookieStore,
    header::COOKIE,
    header::{HeaderMap, HeaderName, HeaderValue, SET_COOKIE},
    Url,
};
use rsa::{PublicKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize)]
struct LoginResponse {
    success: bool,
    #[serde(default)]
    login_complete: bool,
    #[serde(default)]
    captcha_needed: bool,
    #[serde(default)]
    captcha_gid: String,
    #[serde(default)]
    emailsteamid: u64,
    #[serde(default)]
    emailauth_needed: bool,
    #[serde(default)]
    requires_twofactor: bool,
    #[serde(default)]
    message: String,
    oauth: Option<OAuthData>,
    transfer_urls: Option<Vec<String>>,
    transfer_parameters: Option<LoginTransferParameters>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginTransferParameters {
    steamid: String,
    token_secure: String,
    auth: String,
    remember_login: bool,
    webcookie: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RsaResponse {
    success: bool,
    publickey_exp: String,
    publickey_mod: String,
    timestamp: String,
    token_gid: String,
}

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

        let mut params = HashMap::new();
        params.insert(
            "donotcache",
            format!(
                "{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    * 1000
            ),
        );
        params.insert("username", self.username.clone());
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

        if login_resp.transfer_urls.is_some() || login_resp.transfer_parameters.is_some() {
            self.client.transfer_login(login_resp)?;
        }

        return Ok(self.client.session.clone().unwrap());
    }
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthData {
    oauth_token: String,
    steamid: String,
    wgtoken: String,
    wgtoken_secure: String,
    webcookie: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "SessionID")]
    pub session_id: String,
    #[serde(rename = "SteamLogin")]
    pub steam_login: String,
    #[serde(rename = "SteamLoginSecure")]
    pub steam_login_secure: String,
    #[serde(rename = "WebCookie")]
    pub web_cookie: String,
    #[serde(rename = "OAuthToken")]
    pub token: String,
    #[serde(rename = "SteamID")]
    pub steam_id: u64,
}

pub fn get_server_time() -> i64 {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("https://api.steampowered.com/ITwoFactorService/QueryTime/v0001")
        .body("steamid=0")
        .send();
    let value: serde_json::Value = resp.unwrap().json().unwrap();

    return String::from(value["response"]["server_time"].as_str().unwrap())
        .parse()
        .unwrap();
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

lazy_static! {
    static ref STEAM_COOKIE_URL: Url = "https://steamcommunity.com".parse::<Url>().unwrap();
}

/// Provides raw access to the Steam API. Handles cookies, some deserialization, etc. to make it easier.
#[derive(Debug)]
struct SteamApiClient {
    cookies: reqwest::cookie::Jar,
    client: reqwest::blocking::Client,
    pub session: Option<Session>,
}

impl SteamApiClient {
    pub fn new() -> SteamApiClient {
        SteamApiClient {
			cookies: reqwest::cookie::Jar::default(),
			client: reqwest::blocking::ClientBuilder::new()
				.cookie_store(true)
				.user_agent("Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
				.default_headers(HeaderMap::from_iter(hashmap! {
					HeaderName::from_str("X-Requested-With").expect("could not build default request headers") => HeaderValue::from_str("com.valvesoftware.android.steam.community").expect("could not build default request headers")
				}.into_iter()))
				.build()
				.unwrap(),
			session: None,
		}
    }

    fn build_session(&self, data: &OAuthData) -> Session {
        return Session {
            token: data.oauth_token.clone(),
            steam_id: data.steamid.parse().unwrap(),
            steam_login: format!("{}%7C%7C{}", data.steamid, data.wgtoken),
            steam_login_secure: format!("{}%7C%7C{}", data.steamid, data.wgtoken_secure),
            session_id: self.extract_session_id().unwrap(),
            web_cookie: data.webcookie.clone(),
        };
    }

    fn extract_session_id(&self) -> Option<String> {
        let cookies = self.cookies.cookies(&STEAM_COOKIE_URL).unwrap();
        let all_cookies = cookies.to_str().unwrap();
        for cookie in all_cookies
            .split(";")
            .map(|s| cookie::Cookie::parse(s).unwrap())
        {
            if cookie.name() == "sessionid" {
                return Some(cookie.value().into());
            }
        }
        return None;
    }

    pub fn save_cookies_from_response(&mut self, response: &reqwest::blocking::Response) {
        let set_cookie_iter = response.headers().get_all(SET_COOKIE);

        for c in set_cookie_iter {
            c.to_str()
                .into_iter()
                .for_each(|cookie_str| self.cookies.add_cookie_str(cookie_str, &STEAM_COOKIE_URL));
        }
    }

    pub fn request<U: reqwest::IntoUrl>(&self, method: reqwest::Method, url: U) -> RequestBuilder {
        self.cookies
            .add_cookie_str("mobileClientVersion=0 (2.1.3)", &STEAM_COOKIE_URL);
        self.cookies
            .add_cookie_str("mobileClient=android", &STEAM_COOKIE_URL);
        self.cookies
            .add_cookie_str("Steam_Language=english", &STEAM_COOKIE_URL);

        self.client
            .request(method, url)
            .header(COOKIE, self.cookies.cookies(&STEAM_COOKIE_URL).unwrap())
    }

    pub fn get<U: reqwest::IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(reqwest::Method::GET, url)
    }

    pub fn post<U: reqwest::IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(reqwest::Method::POST, url)
    }

    /// Updates the cookie jar with the session cookies by pinging steam servers.
    fn update_session(&mut self) -> anyhow::Result<()> {
        trace!("SteamApiClient::update_session");

        let resp = self
			.get("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client".parse::<Url>().unwrap())
			.send()?;
        self.save_cookies_from_response(&resp);
        trace!("{:?}", resp);

        trace!("cookies: {:?}", self.cookies);
        Ok(())
    }

    /// Endpoint: POST /login/dologin
    pub fn login(
        &mut self,
        username: String,
        encrypted_password: String,
        twofactor_code: String,
        email_code: String,
        captcha_gid: String,
        captcha_text: String,
        rsa_timestamp: String,
    ) -> anyhow::Result<LoginResponse> {
        let params = hashmap! {
            "donotcache" => format!(
                "{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    * 1000
            ),
            "username" => username,
            "password" => encrypted_password,
            "twofactorcode" => twofactor_code,
            "emailauth" => email_code,
            "captchagid" => captcha_gid,
            "captcha_text" => captcha_text,
            "rsatimestamp" => rsa_timestamp,
            "remember_login" => "true".into(),
            "oauth_client_id" => "DE45CD61".into(),
            "oauth_scope" => "read_profile write_profile read_client write_client".into(),
        };

        let resp = self
            .post("https://steamcommunity.com/login/dologin")
            .form(&params)
            .send()?;
        let text = resp.text()?;
        trace!("raw login response: {}", text);

        let login_resp: LoginResponse = serde_json::from_str(text.as_str())?;

        if let Some(oauth) = &login_resp.oauth {
            self.session = Some(self.build_session(&oauth));
        }

        return Ok(login_resp);
    }

    /// A secondary step in the login flow. Does not seem to always be needed?
    /// Endpoints: provided by `login()`
    fn transfer_login(&mut self, login_resp: LoginResponse) -> anyhow::Result<OAuthData> {
        match (login_resp.transfer_urls, login_resp.transfer_parameters) {
            (Some(urls), Some(params)) => {
                debug!("received transfer parameters, relaying data...");
                for url in urls {
                    trace!("posting transfer to {}", url);
                    let resp = self.client.post(url).json(&params).send()?;
                    self.save_cookies_from_response(&resp);
                }

                let oauth = OAuthData {
                    oauth_token: params.auth,
                    steamid: params.steamid.parse().unwrap(),
                    wgtoken: params.token_secure.clone(), // guessing
                    wgtoken_secure: params.token_secure,
                    webcookie: params.webcookie,
                };
                self.session = Some(self.build_session(&oauth));
                return Ok(oauth);
            }
            (None, None) => {
                bail!("did not receive transfer_urls and transfer_parameters");
            }
            (_, None) => {
                bail!("did not receive transfer_parameters");
            }
            (None, _) => {
                bail!("did not receive transfer_urls");
            }
        }
    }
}

#[test]
fn test_oauth_data_parse() {
    // This example is from a login response that did not contain any transfer URLs.
	let oauth: OAuthData = serde_json::from_str("{\"steamid\":\"78562647129469312\",\"account_name\":\"feuarus\",\"oauth_token\":\"fd2fdb3d0717bcd2220d98c7ec61c7bd\",\"wgtoken\":\"72E7013D598A4F68C7E268F6FA3767D89D763732\",\"wgtoken_secure\":\"21061EA13C36D7C29812CAED900A215171AD13A2\",\"webcookie\":\"6298070A226E5DAD49938D78BCF36F7A7118FDD5\"}").unwrap();

	assert_eq!(oauth.steamid, "78562647129469312");
	assert_eq!(oauth.oauth_token, "fd2fdb3d0717bcd2220d98c7ec61c7bd");
	assert_eq!(oauth.wgtoken, "72E7013D598A4F68C7E268F6FA3767D89D763732");
	assert_eq!(oauth.wgtoken_secure, "21061EA13C36D7C29812CAED900A215171AD13A2");
	assert_eq!(oauth.webcookie, "6298070A226E5DAD49938D78BCF36F7A7118FDD5");
}
