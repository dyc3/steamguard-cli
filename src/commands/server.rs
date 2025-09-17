use std::sync::{Arc, Mutex};
use clap::Parser;
use log::*;
use crate::{http_server::HttpServer, AccountManager};
use steamguard::{SteamGuardAccount, transport::Transport};
use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Start HTTP API server for browser extension integration")]
pub struct ServerCommand {
    #[clap(
        short,
        long,
        default_value = "8080",
        help = "Port to bind the HTTP server to"
    )]
    pub port: u16,
}

impl<T> AccountCommand<T> for ServerCommand
where
    T: Transport + Clone + Send + Sync + 'static,
{
    fn execute(
        &self,
        transport: T,
        _manager: &mut AccountManager,
        accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
        _args: &GlobalArgs,
    ) -> anyhow::Result<()> {
        let server = HttpServer::new(transport, accounts);
        
        info!("Starting HTTP API server on port {}", self.port);
        info!("Browser extensions can make requests to http://localhost:{}", self.port);
        
        // Run the async server in a blocking context
        let rt = tokio::runtime::Runtime::new()?;
        match rt.block_on(server.start(self.port)) {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("Server error: {}", e)),
        }
    }
}