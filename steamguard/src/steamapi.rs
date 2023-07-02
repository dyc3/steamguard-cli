pub mod authentication;
pub mod phone;
pub mod twofactor;

use crate::{
	protobufs::service_twofactor::CTwoFactor_Time_Response, token::Jwt, transport::WebApiTransport,
};
use reqwest::Url;
use serde::Deserialize;

pub use self::authentication::AuthenticationClient;
pub use self::phone::PhoneClient;
pub use self::twofactor::TwoFactorClient;

lazy_static! {
	static ref STEAM_COOKIE_URL: Url = "https://steamcommunity.com".parse::<Url>().unwrap();
	static ref STEAM_API_BASE: String = "https://api.steampowered.com".into();
}

/// Queries Steam for the current time. A convenience function around TwoFactorClient.
///
/// Endpoint: `/ITwoFactorService/QueryTime/v0001`
pub fn get_server_time() -> anyhow::Result<CTwoFactor_Time_Response> {
	let mut client = TwoFactorClient::new(WebApiTransport::default());
	let resp = client.query_time()?;
	if resp.result != EResult::OK {
		return Err(anyhow::anyhow!("QueryTime failed: {:?}", resp));
	}

	Ok(resp.into_response_data())
}

pub trait BuildableRequest {
	fn method() -> reqwest::Method;

	fn requires_access_token() -> bool;
}

#[derive(Debug, Clone)]
pub struct ApiRequest<'a, T> {
	api_interface: String,
	api_method: String,
	api_version: u32,
	access_token: Option<&'a Jwt>,
	request_data: T,
}

impl<'a, T: BuildableRequest> ApiRequest<'a, T> {
	pub fn new(
		api_interface: impl Into<String>,
		api_method: impl Into<String>,
		api_version: u32,
		request_data: T,
	) -> Self {
		Self {
			api_interface: api_interface.into(),
			api_method: api_method.into(),
			api_version,
			access_token: None,
			request_data,
		}
	}

	pub fn with_access_token(mut self, access_token: &'a Jwt) -> Self {
		self.access_token = Some(access_token);
		self
	}

	pub fn access_token(&self) -> Option<&Jwt> {
		self.access_token
	}

	pub(crate) fn build_url(&self) -> String {
		format!(
			"{}/{}/{}/v{}",
			*STEAM_API_BASE, self.api_interface, self.api_method, self.api_version
		)
	}

	pub(crate) fn request_data(&self) -> &T {
		&self.request_data
	}
}

#[derive(Debug, Clone)]
pub struct ApiResponse<T> {
	pub(crate) result: EResult,
	pub(crate) error_message: Option<String>,
	pub(crate) response_data: T,
}

impl<T> ApiResponse<T> {
	pub fn result(&self) -> EResult {
		self.result
	}

	pub fn error_message(&self) -> Option<&String> {
		self.error_message.as_ref()
	}

	pub fn response_data(&self) -> &T {
		&self.response_data
	}

	pub fn into_response_data(self) -> T {
		self.response_data
	}
}

// TODO: generate from protobufs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum EResult {
	Invalid = 0,
	OK = 1,
	Fail = 2,
	NoConnection = 3,
	InvalidPassword = 5,
	LoggedInElsewhere = 6,
	InvalidProtocolVer = 7,
	InvalidParam = 8,
	FileNotFound = 9,
	Busy = 10,
	InvalidState = 11,
	InvalidName = 12,
	InvalidEmail = 13,
	DuplicateName = 14,
	AccessDenied = 15,
	Timeout = 16,
	Banned = 17,
	AccountNotFound = 18,
	InvalidSteamID = 19,
	ServiceUnavailable = 20,
	NotLoggedOn = 21,
	Pending = 22,
	EncryptionFailure = 23,
	InsufficientPrivilege = 24,
	LimitExceeded = 25,
	Revoked = 26,
	Expired = 27,
	AlreadyRedeemed = 28,
	DuplicateRequest = 29,
	AlreadyOwned = 30,
	IPNotFound = 31,
	PersistFailed = 32,
	LockingFailed = 33,
	LogonSessionReplaced = 34,
	ConnectFailed = 35,
	HandshakeFailed = 36,
	IOFailure = 37,
	RemoteDisconnect = 38,
	ShoppingCartNotFound = 39,
	Blocked = 40,
	Ignored = 41,
	NoMatch = 42,
	AccountDisabled = 43,
	ServiceReadOnly = 44,
	AccountNotFeatured = 45,
	AdministratorOK = 46,
	ContentVersion = 47,
	TryAnotherCM = 48,
	PasswordRequiredToKickSession = 49,
	AlreadyLoggedInElsewhere = 50,
	Suspended = 51,
	Cancelled = 52,
	DataCorruption = 53,
	DiskFull = 54,
	RemoteCallFailed = 55,
	PasswordNotSetOrUnset = 56,
	ExternalAccountUnlinked = 57,
	PSNTicketInvalid = 58,
	ExternalAccountAlreadyLinked = 59,
	RemoteFileConflict = 60,
	IllegalPassword = 61,
	SameAsPreviousValue = 62,
	AccountLogonDenied = 63,
	CannotUseOldPassword = 64,
	InvalidLoginAuthCode = 65,
	AccountLogonDeniedNoMailSent = 66,
	HardwareNotCapableOfIPT = 67,
	IPTInitError = 68,
	ParentalControlRestricted = 69,
	FacebookQueryError = 70,
	ExpiredLoginAuthCode = 71,
	IPLoginRestrictionFailed = 72,
	AccountLocked = 73,
	AccountLogonDeniedVerifiedEmailRequired = 74,
	NoMatchingURL = 75,
	BadResponse = 76,
	RequirePasswordReEntry = 77,
	ValueOutOfRange = 78,
	UnexpectedError = 79,
	Disabled = 80,
	InvalidCEGSubmission = 81,
	RestrictedDevice = 82,
	RegionLocked = 83,
	RateLimitExceeded = 84,
	AccountLoginDeniedNeedTwoFactor = 85,
	ItemOrEntryHasBeenDeleted = 86,
	AccountLoginDeniedThrottle = 87,
	TwoFactorCodeMismatch = 88,
	TwoFactorActivationCodeMismatch = 89,
	AccountAssociatedToMultipleAccounts = 90,
	NotModified = 91,
	NoMobileDeviceAvailable = 92,
	TimeNotSynced = 93,
	SMSCodeFailed = 94,
	AccountLimitExceeded = 95,
	AccountActivityLimitExceeded = 96,
	PhoneActivityLimitExceeded = 97,
	RefundToWallet = 98,
	EmailSendFailure = 99,
	NotSettled = 100,
	NeedCaptcha = 101,
	GSLTDenied = 102,
	GSOwnerDenied = 103,
	InvalidItemType = 104,
	IPBanned = 105,
	GSLTExpired = 106,
	InsufficientFunds = 107,
	TooManyPending = 108,
	NoSiteLicensesFound = 109,
	WGNetworkSendExceeded = 110,
	AccountNotFriends = 111,
	LimitedUserAccount = 112,
	CantRemoveItem = 113,
	AccountDeleted = 114,
	ExistingUserCancelledLicense = 115,
	DeniedDueToCommunityCooldown = 116,
	NoLauncherSpecified = 117,
	MustAgreeToSSA = 118,
	ClientNoLongerSupported = 119,
	SteamRealmMismatch = 120,
	InvalidSignature = 121,
	ParseFailure = 122,
	NoVerifiedPhone = 123,
	InsufficientBattery = 124,
	ChargerRequired = 125,
	CachedCredentialInvalid = 126,
	PhoneNumberIsVOIP = 127,
}

impl From<i32> for EResult {
	fn from(value: i32) -> Self {
		match value {
			1 => EResult::OK,
			2 => EResult::Fail,
			3 => EResult::NoConnection,
			5 => EResult::InvalidPassword,
			6 => EResult::LoggedInElsewhere,
			7 => EResult::InvalidProtocolVer,
			8 => EResult::InvalidParam,
			9 => EResult::FileNotFound,
			10 => EResult::Busy,
			11 => EResult::InvalidState,
			12 => EResult::InvalidName,
			13 => EResult::InvalidEmail,
			14 => EResult::DuplicateName,
			15 => EResult::AccessDenied,
			16 => EResult::Timeout,
			17 => EResult::Banned,
			18 => EResult::AccountNotFound,
			19 => EResult::InvalidSteamID,
			20 => EResult::ServiceUnavailable,
			21 => EResult::NotLoggedOn,
			22 => EResult::Pending,
			23 => EResult::EncryptionFailure,
			24 => EResult::InsufficientPrivilege,
			25 => EResult::LimitExceeded,
			26 => EResult::Revoked,
			27 => EResult::Expired,
			28 => EResult::AlreadyRedeemed,
			29 => EResult::DuplicateRequest,
			30 => EResult::AlreadyOwned,
			31 => EResult::IPNotFound,
			32 => EResult::PersistFailed,
			33 => EResult::LockingFailed,
			34 => EResult::LogonSessionReplaced,
			35 => EResult::ConnectFailed,
			36 => EResult::HandshakeFailed,
			37 => EResult::IOFailure,
			38 => EResult::RemoteDisconnect,
			39 => EResult::ShoppingCartNotFound,
			40 => EResult::Blocked,
			41 => EResult::Ignored,
			42 => EResult::NoMatch,
			43 => EResult::AccountDisabled,
			44 => EResult::ServiceReadOnly,
			45 => EResult::AccountNotFeatured,
			46 => EResult::AdministratorOK,
			47 => EResult::ContentVersion,
			48 => EResult::TryAnotherCM,
			49 => EResult::PasswordRequiredToKickSession,
			50 => EResult::AlreadyLoggedInElsewhere,
			51 => EResult::Suspended,
			52 => EResult::Cancelled,
			53 => EResult::DataCorruption,
			54 => EResult::DiskFull,
			55 => EResult::RemoteCallFailed,
			56 => EResult::PasswordNotSetOrUnset,
			57 => EResult::ExternalAccountUnlinked,
			58 => EResult::PSNTicketInvalid,
			59 => EResult::ExternalAccountAlreadyLinked,
			60 => EResult::RemoteFileConflict,
			61 => EResult::IllegalPassword,
			62 => EResult::SameAsPreviousValue,
			63 => EResult::AccountLogonDenied,
			64 => EResult::CannotUseOldPassword,
			65 => EResult::InvalidLoginAuthCode,
			66 => EResult::AccountLogonDeniedNoMailSent,
			67 => EResult::HardwareNotCapableOfIPT,
			68 => EResult::IPTInitError,
			69 => EResult::ParentalControlRestricted,
			70 => EResult::FacebookQueryError,
			71 => EResult::ExpiredLoginAuthCode,
			72 => EResult::IPLoginRestrictionFailed,
			73 => EResult::AccountLocked,
			74 => EResult::AccountLogonDeniedVerifiedEmailRequired,
			75 => EResult::NoMatchingURL,
			76 => EResult::BadResponse,
			77 => EResult::RequirePasswordReEntry,
			78 => EResult::ValueOutOfRange,
			79 => EResult::UnexpectedError,
			80 => EResult::Disabled,
			81 => EResult::InvalidCEGSubmission,
			82 => EResult::RestrictedDevice,
			83 => EResult::RegionLocked,
			84 => EResult::RateLimitExceeded,
			85 => EResult::AccountLoginDeniedNeedTwoFactor,
			86 => EResult::ItemOrEntryHasBeenDeleted,
			87 => EResult::AccountLoginDeniedThrottle,
			88 => EResult::TwoFactorCodeMismatch,
			89 => EResult::TwoFactorActivationCodeMismatch,
			90 => EResult::AccountAssociatedToMultipleAccounts,
			91 => EResult::NotModified,
			92 => EResult::NoMobileDeviceAvailable,
			93 => EResult::TimeNotSynced,
			94 => EResult::SMSCodeFailed,
			95 => EResult::AccountLimitExceeded,
			96 => EResult::AccountActivityLimitExceeded,
			97 => EResult::PhoneActivityLimitExceeded,
			98 => EResult::RefundToWallet,
			99 => EResult::EmailSendFailure,
			100 => EResult::NotSettled,
			101 => EResult::NeedCaptcha,
			102 => EResult::GSLTDenied,
			103 => EResult::GSOwnerDenied,
			104 => EResult::InvalidItemType,
			105 => EResult::IPBanned,
			106 => EResult::GSLTExpired,
			107 => EResult::InsufficientFunds,
			108 => EResult::TooManyPending,
			109 => EResult::NoSiteLicensesFound,
			110 => EResult::WGNetworkSendExceeded,
			111 => EResult::AccountNotFriends,
			112 => EResult::LimitedUserAccount,
			113 => EResult::CantRemoveItem,
			114 => EResult::AccountDeleted,
			115 => EResult::ExistingUserCancelledLicense,
			116 => EResult::DeniedDueToCommunityCooldown,
			117 => EResult::NoLauncherSpecified,
			118 => EResult::MustAgreeToSSA,
			119 => EResult::ClientNoLongerSupported,
			120 => EResult::SteamRealmMismatch,
			121 => EResult::InvalidSignature,
			122 => EResult::ParseFailure,
			123 => EResult::NoVerifiedPhone,
			124 => EResult::InsufficientBattery,
			125 => EResult::ChargerRequired,
			126 => EResult::CachedCredentialInvalid,
			127 => EResult::PhoneNumberIsVOIP,
			_ => EResult::Invalid,
		}
	}
}
