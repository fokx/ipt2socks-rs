use crate::error::{Ipt2SocksError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_METHOD_NONE: u8 = 0x00;
const AUTH_METHOD_USERNAME: u8 = 0x02;
const AUTH_METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;

pub struct Socks5Client {
    stream: TcpStream,
    auth_username: Option<String>,
    auth_password: Option<String>,
}

impl Socks5Client {
    pub async fn connect(
        server: &str,
        port: u16,
        auth_username: Option<String>,
        auth_password: Option<String>,
    ) -> Result<Self> {
        let addr = format!("{}:{}", server, port);
        let stream = TcpStream::connect(&addr).await?;

        Ok(Self {
            stream,
            auth_username,
            auth_password,
        })
    }

    pub async fn handshake(&mut self) -> Result<()> {
        // Send authentication method negotiation
        let methods = if self.auth_username.is_some() {
            vec![SOCKS5_VERSION, 2, AUTH_METHOD_NONE, AUTH_METHOD_USERNAME]
        } else {
            vec![SOCKS5_VERSION, 1, AUTH_METHOD_NONE]
        };

        self.stream.write_all(&methods).await?;

        // Read server's choice
        let mut buf = [0u8; 2];
        self.stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            return Err(Ipt2SocksError::Socks5Protocol(
                "Invalid SOCKS5 version".to_string(),
            ));
        }

        match buf[1] {
            AUTH_METHOD_NONE => {
                debug!("SOCKS5 authentication: none");
                Ok(())
            }
            AUTH_METHOD_USERNAME => {
                debug!("SOCKS5 authentication: username/password");
                self.authenticate().await
            }
            AUTH_METHOD_NO_ACCEPTABLE => {
                Err(Ipt2SocksError::AuthFailed)
            }
            _ => Err(Ipt2SocksError::Socks5Protocol(
                "Unknown authentication method".to_string(),
            )),
        }
    }

    async fn authenticate(&mut self) -> Result<()> {
        let username = self.auth_username.as_ref().ok_or_else(|| {
            Ipt2SocksError::ConfigError("Username required".to_string())
        })?;
        let password = self.auth_password.as_ref().ok_or_else(|| {
            Ipt2SocksError::ConfigError("Password required".to_string())
        })?;

        // Send authentication request
        let mut buf = Vec::new();
        buf.push(0x01); // Auth version
        buf.push(username.len() as u8);
        buf.extend_from_slice(username.as_bytes());
        buf.push(password.len() as u8);
        buf.extend_from_slice(password.as_bytes());

        self.stream.write_all(&buf).await?;

        // Read response
        let mut response = [0u8; 2];
        self.stream.read_exact(&mut response).await?;

        if response[1] == 0x00 {
            Ok(())
        } else {
            Err(Ipt2SocksError::AuthFailed)
        }
    }

    pub async fn tcp_connect(&mut self, target: SocketAddr) -> Result<()> {
        // Build request
        let mut request = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];

        match target.ip() {
            IpAddr::V4(ip) => {
                request.push(ATYP_IPV4);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(ATYP_IPV6);
                request.extend_from_slice(&ip.octets());
            }
        }

        request.extend_from_slice(&target.port().to_be_bytes());

        self.stream.write_all(&request).await?;

        // Read response
        let mut buf = [0u8; 4];
        self.stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            return Err(Ipt2SocksError::Socks5Protocol(
                "Invalid SOCKS5 version in response".to_string(),
            ));
        }

        if buf[1] != REP_SUCCESS {
            return Err(Ipt2SocksError::ProxyError(format!(
                "SOCKS5 connect failed with code: {}",
                buf[1]
            )));
        }

        // Read bound address
        match buf[3] {
            ATYP_IPV4 => {
                let mut addr = [0u8; 6];
                self.stream.read_exact(&mut addr).await?;
            }
            ATYP_IPV6 => {
                let mut addr = [0u8; 18];
                self.stream.read_exact(&mut addr).await?;
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                self.stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize + 2];
                self.stream.read_exact(&mut domain).await?;
            }
            _ => {
                return Err(Ipt2SocksError::Socks5Protocol(
                    "Invalid address type".to_string(),
                ));
            }
        }

        trace!("SOCKS5 TCP connection established to {}", target);
        Ok(())
    }

    pub async fn udp_associate(&mut self, local_addr: SocketAddr) -> Result<SocketAddr> {
        // Build request
        let mut request = vec![SOCKS5_VERSION, CMD_UDP_ASSOCIATE, 0x00];

        match local_addr.ip() {
            IpAddr::V4(ip) => {
                request.push(ATYP_IPV4);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(ATYP_IPV6);
                request.extend_from_slice(&ip.octets());
            }
        }

        request.extend_from_slice(&local_addr.port().to_be_bytes());

        self.stream.write_all(&request).await?;

        // Read response
        let mut buf = [0u8; 4];
        self.stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            return Err(Ipt2SocksError::Socks5Protocol(
                "Invalid SOCKS5 version in response".to_string(),
            ));
        }

        if buf[1] != REP_SUCCESS {
            return Err(Ipt2SocksError::ProxyError(format!(
                "SOCKS5 UDP associate failed with code: {}",
                buf[1]
            )));
        }

        // Read bound address
        let udp_relay_addr = match buf[3] {
            ATYP_IPV4 => {
                let mut octets = [0u8; 4];
                self.stream.read_exact(&mut octets).await?;
                let mut port_bytes = [0u8; 2];
                self.stream.read_exact(&mut port_bytes).await?;
                let port = u16::from_be_bytes(port_bytes);
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
            }
            ATYP_IPV6 => {
                let mut octets = [0u8; 16];
                self.stream.read_exact(&mut octets).await?;
                let mut port_bytes = [0u8; 2];
                self.stream.read_exact(&mut port_bytes).await?;
                let port = u16::from_be_bytes(port_bytes);
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
            }
            _ => {
                return Err(Ipt2SocksError::Socks5Protocol(
                    "Invalid address type for UDP associate".to_string(),
                ));
            }
        };

        trace!("SOCKS5 UDP associate established, relay: {}", udp_relay_addr);
        Ok(udp_relay_addr)
    }

    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

pub fn encode_udp_header(target: SocketAddr) -> Vec<u8> {
    let mut header = vec![0x00, 0x00, 0x00]; // RSV | FRAG

    match target.ip() {
        IpAddr::V4(ip) => {
            header.push(ATYP_IPV4);
            header.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            header.push(ATYP_IPV6);
            header.extend_from_slice(&ip.octets());
        }
    }

    header.extend_from_slice(&target.port().to_be_bytes());
    header
}

pub fn decode_udp_header(data: &[u8]) -> Result<(SocketAddr, usize)> {
    if data.len() < 10 {
        return Err(Ipt2SocksError::Socks5Protocol(
            "UDP header too short".to_string(),
        ));
    }

    let atyp = data[3];
    let (addr, offset) = match atyp {
        ATYP_IPV4 => {
            if data.len() < 10 {
                return Err(Ipt2SocksError::Socks5Protocol(
                    "Invalid IPv4 UDP header".to_string(),
                ));
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            (SocketAddr::new(IpAddr::V4(ip), port), 10)
        }
        ATYP_IPV6 => {
            if data.len() < 22 {
                return Err(Ipt2SocksError::Socks5Protocol(
                    "Invalid IPv6 UDP header".to_string(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            (SocketAddr::new(IpAddr::V6(ip), port), 22)
        }
        _ => {
            return Err(Ipt2SocksError::Socks5Protocol(
                "Unsupported address type".to_string(),
            ));
        }
    };

    Ok((addr, offset))
}