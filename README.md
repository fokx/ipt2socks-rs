# ipt2socks-rs

A Rust implementation of [ipt2socks](https://github.com/zfl9/ipt2socks) - a utility to convert iptables/nftables (REDIRECT/TPROXY) traffic to SOCKS5 (TCP/UDP).

## Features

- ✅ Convert transparent proxy traffic (REDIRECT/TPROXY) to SOCKS5
- ✅ TCP and UDP transparent proxy support
- ✅ IPv4 and IPv6 dual-stack support
- ✅ Multi-threaded with SO_REUSEPORT for high performance
- ✅ Full Cone NAT support for UDP (if SOCKS5 server supports it)
- ✅ SOCKS5 authentication support
- ✅ TCP Fast Open support
- ✅ Low overhead, async I/O with Tokio

## Use Cases

1. **Transparent Proxy Integration**: Provide iptables/nftables transparent proxy support for SOCKS5-only proxy programs (like ss-local, v2ray socks5, trojan client)

2. **Load Distribution**: Separate the proxy process from the transparent proxy host for better performance, especially when the transparent proxy host has limited resources

## Building

```bash
git clone <your-repo-url>
cd ipt2socks-rs
cargo build --release
```

The binary will be available at `target/release/ipt2socks-rs`

### Cross-compilation

```bash
# For ARM64
cargo build --release --target aarch64-unknown-linux-gnu

# For other targets, install the appropriate toolchain first
rustup target add <target-triple>
cargo build --release --target <target-triple>
```

## Installation

```bash
cargo install --path .
# Or
sudo cp target/release/ipt2socks-rs /usr/local/bin/
```

## Usage

### Basic Usage

```bash
# Connect to SOCKS5 server at 127.0.0.1:1080
ipt2socks-rs -s 127.0.0.1 -p 1080

# Run in background
nohup ipt2socks-rs -s 127.0.0.1 -p 1080 > /var/log/ipt2socks.log 2>&1 &
```

### Common Options

```bash
# Multi-threaded mode (4 threads)
ipt2socks-rs -s 127.0.0.1 -p 1080 -j 4

# SOCKS5 authentication
ipt2socks-rs -s 127.0.0.1 -p 1080 -a username -k password

# TCP-only mode (disable UDP)
ipt2socks-rs -s 127.0.0.1 -p 1080 -T

# Use REDIRECT instead of TPROXY for TCP
ipt2socks-rs -s 127.0.0.1 -p 1080 -R

# Verbose logging
ipt2socks-rs -s 127.0.0.1 -p 1080 -v

# Set nofile limit
ipt2socks-rs -s 127.0.0.1 -p 1080 -n 65535

# Drop privileges after binding
sudo ipt2socks-rs -s 127.0.0.1 -p 1080 -u nobody
```

### All Options

```
Options:
  -s, --server-addr <addr>      SOCKS5 server IP address [default: 127.0.0.1]
  -p, --server-port <port>      SOCKS5 server port [default: 1080]
  -a, --auth-username <user>    Username for SOCKS5 authentication
  -k, --auth-password <passwd>  Password for SOCKS5 authentication
  -b, --listen-addr4 <addr>     Listen IPv4 address [default: 127.0.0.1]
  -B, --listen-addr6 <addr>     Listen IPv6 address [default: ::1]
  -l, --listen-port <port>      Listen port [default: 60080]
  -S, --tcp-syncnt <cnt>        TCP SYN retransmit count
  -c, --cache-size <size>       UDP context cache max size [default: 256]
  -o, --udp-timeout <sec>       UDP context idle timeout [default: 60]
  -j, --thread-nums <num>       Number of worker threads [default: 1]
  -n, --nofile-limit <num>      Set nofile limit (requires root)
  -u, --run-user <user>         Run as specified user (requires root)
  -T, --tcp-only                TCP only (disable UDP proxy)
  -U, --udp-only                UDP only (disable TCP proxy)
  -4, --ipv4-only               IPv4 only (disable IPv6 proxy)
  -6, --ipv6-only               IPv6 only (disable IPv4 proxy)
  -R, --redirect                Use REDIRECT instead of TPROXY for TCP
  -r, --reuse-port              Enable SO_REUSEPORT for single thread
  -w, --tfo-accept              Enable TCP Fast Open for server socket
  -W, --tfo-connect             Enable TCP Fast Open for client socket
  -v, --verbose                 Print verbose log
  -h, --help                    Print help
  -V, --version                 Print version
```

## iptables/nftables Configuration

After starting ipt2socks-rs, configure your iptables/nftables rules. For examples, see:

- [ss-tproxy](https://github.com/zfl9/ss-tproxy)
- [iptables TPROXY examples](https://gist.github.com/zfl9/d52482118f38ce2c16195583dffc44d2)

### Example iptables rules (TPROXY)

```bash
# TCP
iptables -t mangle -N IPT2SOCKS
iptables -t mangle -A IPT2SOCKS -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A IPT2SOCKS -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A IPT2SOCKS -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A IPT2SOCKS -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A IPT2SOCKS -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A IPT2SOCKS -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A IPT2SOCKS -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A IPT2SOCKS -p tcp -j TPROXY --on-port 60080 --tproxy-mark 0x1/0x1
iptables -t mangle -A PREROUTING -j IPT2SOCKS

# UDP
iptables -t mangle -A IPT2SOCKS -p udp -j TPROXY --on-port 60080 --tproxy-mark 0x1/0x1

# Routing
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

## Running as Non-Root User

For security, you can run ipt2socks-rs as a non-root user:

```bash
# Set capabilities
sudo setcap cap_net_bind_service,cap_net_admin+ep /usr/local/bin/ipt2socks-rs

# Run as regular user
ipt2socks-rs -s 127.0.0.1 -p 1080
```

Or use the `-u` option to drop privileges after binding:

```bash
sudo ipt2socks-rs -s 127.0.0.1 -p 1080 -u nobody
```

## Performance Notes

- **Multi-threading**: Use `-j` to specify multiple worker threads for better performance
- **SO_REUSEPORT**: Automatically enabled with multiple threads
- **File descriptors**: Increase nofile limit for transparent proxy scenarios (use `-n` option)
- **TCP Fast Open**: Enable with `-w` and `-W` (requires kernel support)

## Differences from Original ipt2socks

This Rust implementation aims to provide the same functionality as the original C version with these characteristics:

- **Memory Safety**: Rust's ownership system prevents memory leaks and buffer overflows
- **Async I/O**: Uses Tokio for efficient async I/O operations
- **Type Safety**: Compile-time type checking reduces runtime errors
- **Modern Tooling**: Cargo for easy building and dependency management

## Requirements

- Linux kernel with TPROXY/REDIRECT support
- Rust 1.70+ (for building)
- Root privileges or appropriate capabilities for binding privileged ports and setting socket options

## License

MIT OR Apache-2.0

## See Also

- [Original ipt2socks (C)](https://github.com/zfl9/ipt2socks)
- [ss-tproxy](https://github.com/zfl9/ss-tproxy)
- [redsocks](https://github.com/darkk/redsocks)
