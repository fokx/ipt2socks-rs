use crate::cli::Args;
use crate::error::Result;
use crate::tcp::TcpProxy;
use crate::udp::UdpProxy;
use anyhow::Context;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{error, info};

pub struct Server {
    args: Arc<Args>,
}

impl Server {
    pub fn new(args: Args) -> Result<Self> {
        args.validate().unwrap();
        Ok(Self {
            args: Arc::new(args),
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let mut tasks = JoinSet::new();

        // Start TCP proxy if not UDP-only
        if !self.args.udp_only {
            let tcp_proxy = TcpProxy::new(self.args.clone())?;

            if !self.args.ipv6_only {
                info!("Starting IPv4 TCP proxy on {}:{}", self.args.listen_addr4, self.args.listen_port);
                for i in 0..self.args.thread_nums {
                    let proxy = tcp_proxy.clone();
                    tasks.spawn(async move {
                        if let Err(e) = proxy.run_ipv4(i).await {
                            error!("IPv4 TCP proxy thread {} error: {}", i, e);
                        }
                    });
                }
            }

            if !self.args.ipv4_only {
                info!("Starting IPv6 TCP proxy on [{}]:{}", self.args.listen_addr6, self.args.listen_port);
                for i in 0..self.args.thread_nums {
                    let proxy = tcp_proxy.clone();
                    tasks.spawn(async move {
                        if let Err(e) = proxy.run_ipv6(i).await {
                            error!("IPv6 TCP proxy thread {} error: {}", i, e);
                        }
                    });
                }
            }
        }

        // Start UDP proxy if not TCP-only
        if !self.args.tcp_only {
            let udp_proxy = UdpProxy::new(self.args.clone())?;

            if !self.args.ipv6_only {
                info!("Starting IPv4 UDP proxy on {}:{}", self.args.listen_addr4, self.args.listen_port);
                for i in 0..self.args.thread_nums {
                    let proxy = udp_proxy.clone();
                    tasks.spawn(async move {
                        if let Err(e) = proxy.run_ipv4(i).await {
                            error!("IPv4 UDP proxy thread {} error: {}", i, e);
                        }
                    });
                }
            }

            if !self.args.ipv4_only {
                info!("Starting IPv6 UDP proxy on [{}]:{}", self.args.listen_addr6, self.args.listen_port);
                for i in 0..self.args.thread_nums {
                    let proxy = udp_proxy.clone();
                    tasks.spawn(async move {
                        if let Err(e) = proxy.run_ipv6(i).await {
                            error!("IPv6 UDP proxy thread {} error: {}", i, e);
                        }
                    });
                }
            }
        }

        info!("Server started successfully");

        // Wait for all tasks
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                error!("Task failed: {}", e);
            }
        }

        Ok(())
    }
}