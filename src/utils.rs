use crate::error::{Ipt2SocksError, Result};
use nix::unistd::{setgid, setuid, Gid, Uid, User};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;

// Socket options for TPROXY
#[cfg(target_os = "linux")]
mod socket_opts {
    pub const IP_TRANSPARENT: libc::c_int = 19;
    pub const IPV6_TRANSPARENT: libc::c_int = 75;
    pub const IP_RECVORIGDSTADDR: libc::c_int = 20;
    pub const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
    pub const SO_ORIGINAL_DST: libc::c_int = 80;
    pub const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
}

#[cfg(target_os = "linux")]
use socket_opts::*;

pub fn set_reuse_port(socket: &socket2::Socket) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let optval: libc::c_int = 1;
        unsafe {
            if libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            ) < 0
            {
                return Err(Ipt2SocksError::Io(std::io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

pub fn set_transparent(socket: &socket2::Socket, is_ipv6: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let optval: libc::c_int = 1;
        let opt = if is_ipv6 {
            IPV6_TRANSPARENT
        } else {
            IP_TRANSPARENT
        };

        unsafe {
            if libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                opt,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            ) < 0
            {
                return Err(Ipt2SocksError::Io(std::io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

pub fn set_recvorigdstaddr(socket: &socket2::Socket, is_ipv6: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let optval: libc::c_int = 1;
        let opt = if is_ipv6 {
            IPV6_RECVORIGDSTADDR
        } else {
            IP_RECVORIGDSTADDR
        };

        unsafe {
            if libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                opt,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            ) < 0
            {
                return Err(Ipt2SocksError::Io(std::io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

pub fn set_tcp_fastopen(socket: &socket2::Socket, _enable: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let optval: libc::c_int = 5; // Queue length
        unsafe {
            if libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            ) < 0
            {
                return Err(Ipt2SocksError::Io(std::io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

pub fn get_original_dest(stream: &TcpStream) -> Result<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        use std::mem;
        let fd = stream.as_raw_fd();

        let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut addr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        unsafe {
            if libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut addr_len,
            ) < 0
            {
                return Err(Ipt2SocksError::Io(std::io::Error::last_os_error()));
            }
        }

        sockaddr_to_addr(&addr)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(Ipt2SocksError::ConfigError(
            "REDIRECT not supported on this platform".to_string(),
        ))
    }
}

pub fn get_tproxy_dest(stream: &TcpStream) -> Result<SocketAddr> {
    stream
            .local_addr()
            .map_err(|e| Ipt2SocksError::Io(e))
}

pub fn get_udp_original_dest(addr: &SocketAddr) -> Result<SocketAddr> {
    // For UDP TPROXY, the original destination is passed through recvmsg
    // In this simplified version, we return the address as-is
    // A full implementation would parse the control messages
    Ok(*addr)
}

#[cfg(target_os = "linux")]
fn sockaddr_to_addr(storage: &libc::sockaddr_storage) -> Result<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    match storage.ss_family as i32 {
        libc::AF_INET => {
            let addr = unsafe { *(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::new(ip.into(), port))
        }
        libc::AF_INET6 => {
            let addr = unsafe { *(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => Err(Ipt2SocksError::InvalidAddress(
            "Unsupported address family".to_string(),
        )),
    }
}

pub fn set_nofile_limit(limit: u64) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let rlimit = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };

        unsafe {
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) < 0 {
                return Err(Ipt2SocksError::Io(std::io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

pub fn get_nofile_limit() -> Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use std::mem;
        let mut rlimit: libc::rlimit = unsafe { mem::zeroed() };

        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlimit) < 0 {
                return Err(Ipt2SocksError::Io(std::io::Error::last_os_error()));
            }
        }

        Ok((rlimit.rlim_cur, rlimit.rlim_max))
    }

    #[cfg(not(target_os = "linux"))]
    Ok((0, 0))
}

pub fn drop_privileges(username: &str) -> Result<()> {
    let user = User::from_name(username)
            .map_err(|e| Ipt2SocksError::ConfigError(format!("Failed to lookup user: {}", e)))?
            .ok_or_else(|| Ipt2SocksError::ConfigError(format!("User not found: {}", username)))?;

    setgid(Gid::from_raw(user.gid.as_raw()))
            .map_err(|e| Ipt2SocksError::ConfigError(format!("Failed to set GID: {}", e)))?;

    setuid(Uid::from_raw(user.uid.as_raw()))
            .map_err(|e| Ipt2SocksError::ConfigError(format!("Failed to set UID: {}", e)))?;

    Ok(())
}