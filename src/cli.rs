use clap::Parser;
use std::net::IpAddr;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ipt2socks-rs",
    about = "Convert iptables/nftables REDIRECT/TPROXY traffic to SOCKS5",
    version
)]
pub struct Args {
    /// SOCKS5 server IP address
    #[arg(short = 's', long = "server-addr", default_value = "127.0.0.1")]
    pub server_addr: String,

    /// SOCKS5 server port
    #[arg(short = 'p', long = "server-port", default_value_t = 1080)]
    pub server_port: u16,

    /// Username for SOCKS5 authentication
    #[arg(short = 'a', long = "auth-username")]
    pub auth_username: Option<String>,

    /// Password for SOCKS5 authentication
    #[arg(short = 'k', long = "auth-password")]
    pub auth_password: Option<String>,

    /// Listen IPv4 address
    #[arg(short = 'b', long = "listen-addr4", default_value = "127.0.0.1")]
    pub listen_addr4: String,

    /// Listen IPv6 address
    #[arg(short = 'B', long = "listen-addr6", default_value = "::1")]
    pub listen_addr6: String,

    /// Listen port number
    #[arg(short = 'l', long = "listen-port", default_value_t = 60080)]
    pub listen_port: u16,

    /// TCP SYN retransmit count
    #[arg(short = 'S', long = "tcp-syncnt")]
    pub tcp_syncnt: Option<u32>,

    /// UDP context cache max size
    #[arg(short = 'c', long = "cache-size", default_value_t = 256)]
    pub cache_size: usize,

    /// UDP context idle timeout (seconds)
    #[arg(short = 'o', long = "udp-timeout", default_value_t = 60)]
    pub udp_timeout: u64,

    /// Number of worker threads
    #[arg(short = 'j', long = "thread-nums", default_value_t = 1)]
    pub thread_nums: usize,

    /// Set nofile limit
    #[arg(short = 'n', long = "nofile-limit")]
    pub nofile_limit: Option<u64>,

    /// Run as specified user
    #[arg(short = 'u', long = "run-user")]
    pub run_user: Option<String>,

    /// Listen TCP only (disable UDP proxy)
    #[arg(short = 'T', long = "tcp-only")]
    pub tcp_only: bool,

    /// Listen UDP only (disable TCP proxy)
    #[arg(short = 'U', long = "udp-only")]
    pub udp_only: bool,

    /// Listen IPv4 only (disable IPv6 proxy)
    #[arg(short = '4', long = "ipv4-only")]
    pub ipv4_only: bool,

    /// Listen IPv6 only (disable IPv4 proxy)
    #[arg(short = '6', long = "ipv6-only")]
    pub ipv6_only: bool,

    /// Use REDIRECT instead of TPROXY for TCP
    #[arg(short = 'R', long = "redirect")]
    pub redirect: bool,

    /// Enable SO_REUSEPORT for single thread
    #[arg(short = 'r', long = "reuse-port")]
    pub reuse_port: bool,

    /// Enable TCP Fast Open for server socket
    #[arg(short = 'w', long = "tfo-accept")]
    pub tfo_accept: bool,

    /// Enable TCP Fast Open for client socket
    #[arg(short = 'W', long = "tfo-connect")]
    pub tfo_connect: bool,

    /// Print verbose log
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

impl Args {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.tcp_only && self.udp_only {
            anyhow::bail!("Cannot specify both --tcp-only and --udp-only");
        }
        if self.ipv4_only && self.ipv6_only {
            anyhow::bail!("Cannot specify both --ipv4-only and --ipv6-only");
        }
        if self.thread_nums == 0 {
            anyhow::bail!("Thread number must be at least 1");
        }
        if self.auth_username.is_some() != self.auth_password.is_some() {
            anyhow::bail!("Both username and password must be specified for authentication");
        }
        Ok(())
    }
}