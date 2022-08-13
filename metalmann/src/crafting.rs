use bytes::BufMut;
use steam_vent::gc::ClientToGCMessage;
use steam_vent::message::NetMessage;
use steam_vent::message::ServiceMethodRequestMessage;
use steam_vent::proto::enums_clientserver::EMsg;
use steam_vent::proto::steammessages_clientserver::CMsgClientCMList;
use steam_vent::proto::steammessages_clientserver_2::CMsgClientPlayingSessionState;
use steam_vent::proto::steammessages_clientserver_login::CMsgClientAccountInfo;
use steam_vent::service_method::ServiceMethodRequest;
use steamid_ng::SteamID;
use tokio::runtime::Handle;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::Receiver;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::bail;
use log::*;
use secrecy::{SecretString, ExposeSecret};
use steam_vent::connection::Connection;
use steam_vent::enums::EPersonaState;
use steam_vent::net::{RawNetMessage, NetworkError};
use steam_vent::proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;
use steamguard::SteamGuardAccount;
use tokio::runtime::Runtime;

/// A hyper-purpose built Steam client specifically for crafting TF2 items. It provides a synchronous, blocking API over the asynchronous steam_vent connection. While it technically can be expanded to do other things, it probably shouldn't be.
/// Commands are sent to async land via a channel, kinda like a remote control.
pub struct Crafter {
	account: SteamGuardAccount,
	password: SecretString,

	state: Option<CrafterState>,
}

struct CrafterState {
	pub(crate) rt: Runtime,
	pub(crate) async_driver: std::thread::JoinHandle<()>,
	pub(crate) cmd_bus_tx: Sender<CrafterCmdBusMsg>,
	/// A map of channel senders that will be sent a message when the connection receives a given message.
	// pub(crate) msg_waiters: std::sync::Arc<std::sync::Mutex<HashMap<EMsg, Vec<std::sync::mpsc::Sender<RawNetMessage>>>>>,
	pub(crate) msg_waiters: HashMap<EMsg, Vec<std::sync::mpsc::Sender<RawNetMessage>>>,
}

#[derive(Debug, Clone)]
enum CrafterCmdBusMsg {
	SendHeartbeat,
	SetGame {
		appid: u64,
	},
	GcHello,
	CraftItems {
		recipe: ECraftingRecipe,
		ids: Vec<u64>,
	},
	Disconnected,
}

impl Crafter {
	pub fn from_steam_guard_account(account: SteamGuardAccount, password: String) -> Self {
		Crafter {
			account,
			password: password.into(),
			state: None,
		}
	}

	/// Initialize the Crafter. This creates an async runtime and a new thread drive it.
	pub fn init(&mut self) -> anyhow::Result<()> {
		trace!("Crafter::init");
		if self.state.is_some() {
			bail!("Crafter already initialized.");
		}
		let rt  = Runtime::new().unwrap();
		let handle = rt.handle();

		let (conn, recv) = handle.block_on(self.login())?;
		let (tx, rx) = tokio::sync::mpsc::channel::<CrafterCmdBusMsg>(10);
		let msg_reader = Crafter::read_messages(&handle, recv, tx.clone());
		let heartbeat_poller = Crafter::poll_heartbeat(&handle, 60, tx.clone());
		let bus_handler = handle.spawn(async move {
			Crafter::handle_bus_messages(conn, rx).await.unwrap()
		});

		let async_handles = vec![msg_reader, heartbeat_poller, bus_handler];

		let handle = rt.handle().clone();
		let async_driver = thread::spawn(move || handle.block_on(async {
			for h in async_handles {
				match h.await {
					Ok(_) => {},
					Err(err) => {
						error!("{:?}", err);
					}
				}
			}
		}));

		self.state = Some(CrafterState {
			rt,
			async_driver,
			cmd_bus_tx: tx,
			msg_waiters: Default::default()
		});

		Ok(())
	}

	async fn login(&mut self) -> anyhow::Result<(Connection, Receiver<Result<RawNetMessage, NetworkError>>)> {
		trace!("Crafter::login");
		debug!("Starting connection and logging in...");
		let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		let mut credentials = Connection::default_login_message(
			self.account.account_name.clone(),
			self.password.expose_secret().to_string(),
		);
		credentials.set_two_factor_code(self.account.generate_code(time));
		let (conn, recv) = Connection::login(credentials).await?;
		debug!("Connection created");

		Ok((conn, recv))
	}

	fn read_messages(
		handle: &Handle,
		mut rest: Receiver<Result<RawNetMessage, NetworkError>>,
		tx: Sender<CrafterCmdBusMsg>,
	) -> tokio::task::JoinHandle<()> {
		async fn read_message(
			msg_result: Result<RawNetMessage, NetworkError>,
			tx: &Sender<CrafterCmdBusMsg>,
		) -> Result<(), NetworkError> {
			let msg = msg_result?;

			trace!("Got raw net message: {:?}", msg.kind);

			match msg.kind {
				EMsg::k_EMsgClientCMList => {
					let message = msg.into_message::<CMsgClientCMList>()?;
					debug!("Got CM server list, has {} addresses", message.get_cm_addresses().len());
				}
				EMsg::k_EMsgClientPlayingSessionState => {
					debug!("got client playing session state, safe to proceed with GC messages");
				}
				EMsg::k_EMsgServiceMethod => Crafter::service_method(msg, &tx).await?,
				EMsg::k_EMsgClientAccountInfo => {
					let message = msg.into_message::<CMsgClientAccountInfo>()?;
					let persona_name = message.get_persona_name();
					// let _ = tx.send(Message::PersonaName(persona_name.to_owned())).await;
				},
				k => {
					trace!("Ignored raw net message: {:?}", k);
				},
			}

			Ok(())
		}

		handle.spawn(async move {
			while let Some(msg_result) = rest.recv().await {
				if let Err(error) = read_message(
					msg_result,
					&tx
				).await {
					error!("Error reading message: {}", error);
				}
			}

			// no more messages means connection was most likely disconnected
			let _ = tx.send(CrafterCmdBusMsg::Disconnected).await;
		})
	}

	async fn service_method(
		msg: RawNetMessage,
		tx: &Sender<CrafterCmdBusMsg>,
	) -> Result<(), NetworkError> {
		fn get_service_request<Request: ServiceMethodRequest>(
			msg: RawNetMessage,
		) -> Result<Request, NetworkError> {
			let msg = msg.into_message::<ServiceMethodRequestMessage>()?;

			msg.into_message::<Request>()
		}

		let target_job_name = msg.header.target_job_name.as_ref()
			.ok_or(NetworkError::InvalidHeader)?;

		match target_job_name.as_ref() {
			// CFriendMessages_IncomingMessage_Notification::NAME => {
			// 	let msg = get_service_request::<CFriendMessages_IncomingMessage_Notification>(msg)?;
			// 	let message = msg.get_message().to_string();

			// 	if !message.is_empty() {
			// 		let steamid = SteamID::from(msg.get_steamid_friend());
			// 		let _ = tx.send(Message::ChatMessage {
			// 			message,
			// 			steamid,
			// 		}).await;
			// 	}
			// },
			target_job_name => {
				debug!("unknown target job name: {}", target_job_name)
			},
		}

		Ok(())
	}

	// This will continue to send a heartbeat to the connection
	fn poll_heartbeat(
		handle: &Handle,
		interval: u64,
		tx: Sender<CrafterCmdBusMsg>,
	) -> tokio::task::JoinHandle<()> {
		handle.spawn(async move {
			loop {
				async_std::task::sleep(std::time::Duration::from_secs(interval)).await;

				let _ = tx.send(CrafterCmdBusMsg::SendHeartbeat).await;
			}
		})
	}

	async fn handle_bus_messages(
		mut conn: Connection,
		mut bus_rx: Receiver<CrafterCmdBusMsg>
	) -> Result<(), NetworkError> {

		while let Some(message) = &bus_rx.recv().await {
			debug!("command: {:?}", message);
			match message {
				CrafterCmdBusMsg::Disconnected => {
					info!("Crafter Disconnected");
				}
				CrafterCmdBusMsg::SendHeartbeat => {
					conn.send_heartbeat().await?;
				}
				CrafterCmdBusMsg::SetGame { appid } => {
					info!("setting game to {}", appid);
					conn.set_games_played(&[*appid]).await?;
				}
				CrafterCmdBusMsg::CraftItems { recipe, ids } => {
					info!("crafting items: recipe {:?} - {:?}", recipe, ids);
					let msg = MsgCraft {
						recipe: (*recipe).into(),
						num_items: ids.len() as u16,
						items: ids.clone(),
					};
					let buffer = msg.build();
					let mut gcmsg = ClientToGCMessage::new(440, MsgCraft::msg_type(), false);
					gcmsg.set_payload(buffer.into());
					let result = conn.send_gc(gcmsg).await?;
					debug!("craft send result: {}", result);
				},
				c => {
					warn!("Unhandled command: {:?}", c)
				}
			}
		}

		info!("handle_bus_messages exiting");
		Ok(())
	}

	/// Blocks the current thread until the client receives a message of type M.
	pub fn wait_for_message_typed<M>(&mut self) -> anyhow::Result<M> where M: NetMessage {
		if self.state.is_none() {
			bail!("Crafter is not initialized");
		}
		let (tx, mut rx) = std::sync::mpsc::channel::<RawNetMessage>();
		{
			let state = self.state.as_mut().unwrap();
			state.msg_waiters.entry(M::KIND).and_modify(|e| e.push(tx.clone())).or_insert(vec![tx]);
		}
		if let Ok(raw) = rx.recv_timeout(Duration::from_secs(20)) {
			return Ok(raw.into_message::<M>()?);
		}
		bail!("Channel closed, can't wait for message");
	}

	/// Blocks the current thread until the client receives a message of type M.
	pub fn wait_for_message(&mut self, kind: EMsg) -> anyhow::Result<RawNetMessage> {
		debug!("waiting for {:?}", kind);
		if self.state.is_none() {
			bail!("Crafter is not initialized");
		}
		let (tx, rx) = std::sync::mpsc::channel::<RawNetMessage>();
		{
			let state = self.state.as_mut().unwrap();
			state.msg_waiters.entry(kind).and_modify(|e| e.push(tx.clone())).or_insert(vec![tx]);
		}
		if let Ok(raw) = rx.recv_timeout(Duration::from_secs(20)) {
			debug!("done waiting for {:?}", kind);
			return Ok(raw);
		}
		bail!("Channel closed, can't wait for message");
	}

	pub fn set_game(&mut self, appid: u64) -> anyhow::Result<()> {
		trace!("Crafter::set_game");
		self.state.as_ref().unwrap().cmd_bus_tx.blocking_send(CrafterCmdBusMsg::SetGame { appid })?;
		// self.wait_for_message(EMsg::k_EMsgClientPlayingSessionState)?;
		Ok(())
	}

	// pub fn gc_hello(&mut self) -> anyhow::Result<()> {
	// 	self.state.as_ref().unwrap().cmd_bus_tx.blocking_send(CrafterCmdBusMsg::GcHello)?;
	// 	// self.wait_for_message(EMsg::)?;
	// 	Ok(())
	// }

	pub fn craft_items(&self, recipe: ECraftingRecipe, ids: Vec<u64>) -> anyhow::Result<()> {
		trace!("Crafter::craft_items");
		Ok(self.state.as_ref().unwrap().cmd_bus_tx.blocking_send(CrafterCmdBusMsg::CraftItems { recipe, ids })?)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ECraftingRecipe {
	SmeltClassWeapons = 3,
	CombineScrap = 4,
	CombineReclaimed = 5,
	SmeltReclaimed = 22,
	SmeltRefined = 23,
}

impl From<ECraftingRecipe> for u16 {
	fn from(r: ECraftingRecipe) -> Self {
		r as u16
	}
}

#[derive(Debug, Clone)]
struct MsgCraft {
	pub(crate) recipe: u16,
	pub(crate) num_items: u16,
	pub(crate) items: Vec<u64>,
}

impl MsgCraft {
	fn msg_type() -> i32 {
		1002
	}

	fn build(self) -> bytes::Bytes {
		let mut bytes = bytes::BytesMut::new();
		bytes.put_u16(self.recipe);
		bytes.put_u16(self.num_items);
		for item in self.items {
			bytes.put_u64(item);
		}
		bytes.into()
	}
}

pub async fn test() -> anyhow::Result<()> {
	info!("Connecting anonymously...");
	let (mut conn, _recv) = Connection::anonymous().await?;

	info!("Connection created");

	let mut req = CGameServers_GetServerList_Request::new();
	req.set_limit(16);
	req.set_filter("\\appid\\440".into());
	info!("Calling GetServerList");
	let rx = conn.service_method(req).await?;
	let some_tf2_servers = rx.await??;
	for server in some_tf2_servers.servers {
		println!(
			"{}({}) playing {}",
			server.get_name(),
			server.get_addr(),
			server.get_map()
		);
	}

	Ok(())
}

pub async fn test_login(account: &SteamGuardAccount, password: String) -> anyhow::Result<()> {
	info!("Connecting with login...");
	let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let mut credentials = Connection::default_login_message(
		account.account_name.clone(),
		password,
	);
	credentials.set_two_factor_code(account.generate_code(time));
	let (mut conn, _recv) = Connection::anonymous().await?;

	info!("Connection created");

	conn.send_heartbeat().await?;

	let result = conn.set_persona_state(EPersonaState::Online).await;
	info!("set persona state: {:?}", result);

	let result = conn.chat_message(76561198054667933.into(), "test".to_owned()).await?.await?;
	info!("sent chat message: {:?}", result);

	Ok(())
}

