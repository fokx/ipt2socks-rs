use crate::cli::Args;
use crate::error::Result;
use crate::socks5::{decode_udp_header, encode_udp_header, Socks5Client};
use crate::utils;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, trace, warn};

struct UdpContext {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    relay_socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    last_active: Instant,
}

#[derive(Clone)]
pub struct UdpProxy {
    args: Arc<Args>,
    contexts: Arc<Mutex<HashMap<SocketAddr, UdpContext>>>,
}

impl UdpProxy {
    pub fn new(args: Arc<Args>) -> Result<Self> {
        Ok(Self {
            args,
            contexts: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run_ipv4(&self, thread_id: usize) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.args.listen_addr4, self.args.listen_port)
                .parse()?;

        let socket = self.create_socket(addr, false).await?;
        debug!("UDP IPv4 thread {} listening on {}", thread_id, addr);

        self.receive_loop(socket).await
    }

    pub async fn run_ipv6(&self, thread_id: usize) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("[{}]:{}", self.args.listen_addr6, self.args.listen_port)
                .parse()?;

        let socket = self.create_socket(addr, true).await?;
        debug!("UDP IPv6 thread {} listening on {}", thread_id, addr);

        self.receive_loop(socket).await
    }

    async fn create_socket(&self, addr: SocketAddr, is_ipv6: bool) -> anyhow::Result<Arc<UdpSocket>> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if is_ipv6 {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;

        if self.args.reuse_port || self.args.thread_nums > 1 {
            utils::set_reuse_port(&socket)?;
        }

        // Set IP_TRANSPARENT for TPROXY
        utils::set_transparent(&socket, is_ipv6)?;

        // Enable IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR
        utils::set_recvorigdstaddr(&socket, is_ipv6)?;

        socket.bind(&addr.into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        Ok(Arc::new(UdpSocket::from_std(std_socket)?))
    }

    async fn receive_loop(&self, socket: Arc<UdpSocket>) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 65536];

        // Spawn cleanup task
        let proxy = self.clone();
        tokio::spawn(async move {
            proxy.cleanup_loop().await;
        });

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((size, peer_addr)) => {
                    let data = buf[..size].to_vec();
                    let proxy = self.clone();
                    let socket = socket.clone();

                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_packet(socket, peer_addr, data).await {
                            trace!("UDP packet from {} error: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("UDP receive error: {}", e);
                }
            }
        }
    }

    async fn handle_packet(
        &self,
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        // Try to get original destination (TPROXY)
        let target_addr = utils::get_udp_original_dest(&client_addr)?;

        trace!("UDP packet from {} to {} ({} bytes)", client_addr, target_addr, data.len());

        // Get or create context
        let context = {
            let mut contexts = self.contexts.lock().await;

            if let Some(ctx) = contexts.get_mut(&client_addr) {
                ctx.last_active = Instant::now();
                ctx.clone()
            } else {
                // Create new context
                if contexts.len() >= self.args.cache_size {
                    // Remove oldest context
                    if let Some(oldest_key) = contexts.iter()
                            .min_by_key(|(_, ctx)| ctx.last_active)
                            .map(|(k, _)| *k)
                    {
                        contexts.remove(&oldest_key);
                    }
                }

                let ctx = self.create_context(client_addr, target_addr).await?;
                contexts.insert(client_addr, ctx.clone());

                // Start relay task for this context
                let proxy = self.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy.relay_from_socks(socket, client_addr).await {
                        trace!("UDP relay from SOCKS error: {}", e);
                    }
                });

                ctx
            }
        };

        // Encode SOCKS5 UDP header
        let mut packet = encode_udp_header(target_addr);
        packet.extend_from_slice(&data);

        // Send to SOCKS5 relay
        context.relay_socket.send_to(&packet, context.relay_addr).await?;

        Ok(())
    }

    async fn create_context(
        &self,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> anyhow::Result<UdpContext> {
        // Create TCP connection for UDP association
        let mut socks_client = Socks5Client::connect(
            &self.args.server_addr,
            self.args.server_port,
            self.args.auth_username.clone(),
            self.args.auth_password.clone(),
        )
                .await?;

        socks_client.handshake().await?;

        // Create local UDP socket for relay
        let relay_socket = if target_addr.is_ipv6() {
            UdpSocket::bind("[::]:0").await?
        } else {
            UdpSocket::bind("0.0.0.0:0").await?
        };

        let local_addr = relay_socket.local_addr()?;

        // UDP associate
        let relay_addr = socks_client.udp_associate(local_addr).await?;

        // Keep TCP connection alive
        tokio::spawn(async move {
            let _ = socks_client.into_stream();
        });

        Ok(UdpContext {
            client_addr,
            target_addr,
            relay_socket: Arc::new(relay_socket),
            relay_addr,
            last_active: Instant::now(),
        })
    }

    async fn relay_from_socks(
        &self,
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let context = {
            let contexts = self.contexts.lock().await;
            contexts.get(&client_addr).cloned()
        };

        let context = match context {
            Some(ctx) => ctx,
            None => return Ok(()),
        };

        let mut buf = vec![0u8; 65536];

        loop {
            match tokio::time::timeout(
                Duration::from_secs(self.args.udp_timeout),
                context.relay_socket.recv_from(&mut buf),
            )
                    .await
            {
                Ok(Ok((size, _))) => {
                    // Decode SOCKS5 UDP header
                    let (_, offset) = decode_udp_header(&buf[..size])?;
                    let data = &buf[offset..size];

                    // Send back to client
                    socket.send_to(data, client_addr).await?;

                    // Update last active time
                    let mut contexts = self.contexts.lock().await;
                    if let Some(ctx) = contexts.get_mut(&client_addr) {
                        ctx.last_active = Instant::now();
                    }
                }
                Ok(Err(e)) => {
                    error!("UDP relay receive error: {}", e);
                    break;
                }
                Err(_) => {
                    // Timeout
                    trace!("UDP context {} timed out", client_addr);
                    break;
                }
            }
        }

        // Remove context
        let mut contexts = self.contexts.lock().await;
        contexts.remove(&client_addr);

        Ok(())
    }

    async fn cleanup_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            let timeout = Duration::from_secs(self.args.udp_timeout);
            let mut contexts = self.contexts.lock().await;

            contexts.retain(|addr, ctx| {
                let keep = ctx.last_active.elapsed() < timeout;
                if !keep {
                    trace!("Removing idle UDP context {}", addr);
                }
                keep
            });
        }
    }
}

impl Clone for UdpContext {
    fn clone(&self) -> Self {
        Self {
            client_addr: self.client_addr,
            target_addr: self.target_addr,
            relay_socket: self.relay_socket.clone(),
            relay_addr: self.relay_addr,
            last_active: self.last_active,
        }
    }
}