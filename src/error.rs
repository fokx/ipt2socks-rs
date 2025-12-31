use thiserror::Error;

#[derive(Error, Debug)]
pub enum Ipt2SocksError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SOCKS5 protocol error: {0}")]
    Socks5Protocol(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, Ipt2SocksError>;