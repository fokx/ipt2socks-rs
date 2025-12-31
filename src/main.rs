mod cli;
mod error;
mod server;
mod socks5;
mod tcp;
mod udp;
mod utils;

use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        "ipt2socks_rs=debug,tower_http=debug"
    } else {
        "ipt2socks_rs=info"
    };

    tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| filter.into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

    info!("ipt2socks-rs v{}", env!("CARGO_PKG_VERSION"));
    info!("SOCKS5 server: {}:{}", args.server_addr, args.server_port);

    if !args.ipv6_only {
        info!("IPv4 listen: {}:{}", args.listen_addr4, args.listen_port);
    }
    if !args.ipv4_only {
        info!("IPv6 listen: {}:{}", args.listen_addr6, args.listen_port);
    }

    // Set nofile limit if specified
    if let Some(limit) = args.nofile_limit {
        if let Err(e) = utils::set_nofile_limit(limit) {
            error!("Failed to set nofile limit: {}", e);
        } else {
            info!("Set nofile limit to: {}", limit);
        }
    }

    // Display current nofile limit
    if let Ok((soft, hard)) = utils::get_nofile_limit() {
        info!("Current nofile limit: soft={}, hard={}", soft, hard);
    }

    // Drop privileges if run-user specified
    if let Some(ref user) = args.run_user {
        utils::drop_privileges(user)?;
        info!("Dropped privileges to user: {}", user);
    }

    // Start the server
    let server = server::Server::new(args)?;
    server.run().await?;

    Ok(())
}