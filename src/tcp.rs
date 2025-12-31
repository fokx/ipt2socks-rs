use crate::cli::Args;
use crate::error::Result;
use crate::socks5::Socks5Client;
use crate::utils;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, trace, warn};

#[derive(Clone)]
pub struct TcpProxy {
    args: Arc<Args>,
}

impl TcpProxy {
    pub fn new(args: Arc<Args>) -> Result<Self> {
        Ok(Self { args })
    }

    pub async fn run_ipv4(&self, thread_id: usize) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.args.listen_addr4, self.args.listen_port)
                .parse()?;

        let listener = self.create_listener(addr, false).await?;
        debug!("TCP IPv4 thread {} listening on {}", thread_id, addr);

        self.accept_loop(listener).await
    }

    pub async fn run_ipv6(&self, thread_id: usize) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("[{}]:{}", self.args.listen_addr6, self.args.listen_port)
                .parse()?;

        let listener = self.create_listener(addr, true).await?;
        debug!("TCP IPv6 thread {} listening on {}", thread_id, addr);

        self.accept_loop(listener).await
    }

    async fn create_listener(&self, addr: SocketAddr, is_ipv6: bool) -> anyhow::Result<TcpListener> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if is_ipv6 {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        // Set socket options
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;

        if self.args.reuse_port || self.args.thread_nums > 1 {
            utils::set_reuse_port(&socket)?;
        }

        if !self.args.redirect {
            // Set IP_TRANSPARENT for TPROXY
            utils::set_transparent(&socket, is_ipv6)?;
        }

        if self.args.tfo_accept {
            utils::set_tcp_fastopen(&socket, true)?;
        }

        socket.bind(&addr.into())?;
        socket.listen(128)?;

        let listener: std::net::TcpListener = socket.into();
        Ok(TcpListener::from_std(listener)?)
    }

    async fn accept_loop(&self, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let proxy = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_connection(stream, peer_addr).await {
                            trace!("Connection from {} failed: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        &self,
        mut client_stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        // Get original destination
        let target_addr = if self.args.redirect {
            utils::get_original_dest(&client_stream)?
        } else {
            utils::get_tproxy_dest(&client_stream)?
        };

        trace!("TCP connection from {} to {}", peer_addr, target_addr);

        // Connect to SOCKS5 server
        let mut socks_client = Socks5Client::connect(
            &self.args.server_addr,
            self.args.server_port,
            self.args.auth_username.clone(),
            self.args.auth_password.clone(),
        )
                .await?;

        // SOCKS5 handshake
        socks_client.handshake().await?;

        // Connect to target through SOCKS5
        socks_client.tcp_connect(target_addr).await?;

        let mut server_stream = socks_client.into_stream();

        // Relay data bidirectionally
        let (mut client_read, mut client_write) = client_stream.split();
        let (mut server_read, mut server_write) = server_stream.split();

        let client_to_server = io::copy(&mut client_read, &mut server_write);
        let server_to_client = io::copy(&mut server_read, &mut client_write);

        // Wait for both directions to complete
        tokio::select! {
            result = client_to_server => {
                if let Err(e) = result {
                    trace!("Client->Server relay error: {}", e);
                }
            }
            result = server_to_client => {
                if let Err(e) = result {
                    trace!("Server->Client relay error: {}", e);
                }
            }
        }

        trace!("TCP connection {} -> {} closed", peer_addr, target_addr);
        Ok(())
    }
}