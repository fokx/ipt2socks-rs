#!/bin/bash

## a convenient scipt to setup transparent proxy using nftables
## inspired by https://gist.github.com/zfl9/d52482118f38ce2c16195583dffc44d2

# Configuration
# ipt2socks-rs's upstream SOCKS5 proxy port
SOCKS5_PORT="3999"
# ipt2socks-rs default listening port
LOCAL_PROXY_PORT="60080"
# usually no need to change
PROXY_MARK="0x2333"
# You want traffic of user 'tr' to be excluded from proxy
EXCLUDE_USER="tr"
# Get UID of the user to exclude (must exist before running)
EXCLUDE_UID=$(id -u "$EXCLUDE_USER" 2>/dev/null)

if [ -z "$EXCLUDE_UID" ]; then
    echo "Warning: User '$EXCLUDE_USER' not found. Proxy will apply to ALL users."
    # Set to a dummy invalid ID (e.g., -1) so the rule never matches an exclusion
    EXCLUDE_UID=-1
fi

start_ipt2socks() {
    ulimit -n 102400
    # Ensure ipt2socks is actually listening on LOCAL_PROXY_PORT for TPROXY to work.
    # Note: Depending on your version of ipt2socks, you might need -l 60080 here
    # if it doesn't default to the port used in nftables.

    (ipt2socks-rs -s 127.0.0.1 -p $SOCKS5_PORT -v </dev/null &>>/var/log/ipt2socks.log &)
}

stop_ipt2socks() {
    killall ipt2socks &>/dev/null
}

start_nftables() {
    # We use the bash variable $EXCLUDE_UID inside the heredoc
    nft -f - << EOF
flush ruleset
table inet mangle_proxy {
    set reserved_ipv4 {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8,
            10.0.0.0/8,
            100.64.0.0/10,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.0.0.0/24,
            192.0.2.0/24,
            192.88.99.0/24,
            192.168.0.0/16,
            198.18.0.0/15,
            198.51.100.0/24,
            203.0.113.0/24,
            224.0.0.0/4,
            240.0.0.0/4
            # append the IPs your want to exclude, remove the last ',' and blank lines before '}'
        }
    }

    set reserved_ipv6 {
        type ipv6_addr
        flags interval
        elements = {
            ::1/128,
            ::/128,
            ::ffff:0:0/96,
            64:ff9b::/96,
            100::/64,
            2001::/32,
            2001:20::/28,
            2001:db8::/32,
            2002::/16,
            fc00::/7,
            fe80::/10,
            ff00::/8
            # append the IPv6s your want to exclude, remove the last ',' and blank lines before '}'
        }
    }

    chain ssredir {
        # Restore connection mark to packet mark
        ct mark != 0 meta mark set ct mark
        meta mark $PROXY_MARK return

        # Ignore reserved addresses
        ip daddr @reserved_ipv4 return
        ip6 daddr @reserved_ipv6 return

        # Mark the first packet of connections
        tcp flags syn meta mark set $PROXY_MARK
        meta l4proto udp ct state new meta mark set $PROXY_MARK

        # Save packet mark to connection mark
        meta mark != 0 ct mark set meta mark
    }

    chain output {
        type route hook output priority mangle; policy accept;
        # meta skuid $EXCLUDE_UID return

        # Proxy outbound traffic from local host (IPv4 and IPv6)
        # Added check: meta skuid != $EXCLUDE_UID
        # This ensures all users EXCEPT 'tr' are proxied.
        
        meta skuid != $EXCLUDE_UID \
        meta nfproto ipv4 fib saddr type local fib daddr type != local meta l4proto tcp jump ssredir

        meta skuid != $EXCLUDE_UID \
        meta nfproto ipv4 fib saddr type local fib daddr type != local meta l4proto udp jump ssredir

        meta skuid != $EXCLUDE_UID \
        meta nfproto ipv6 fib saddr type local fib daddr type != local meta l4proto tcp jump ssredir

        meta skuid != $EXCLUDE_UID \
        meta nfproto ipv6 fib saddr type local fib daddr type != local meta l4proto udp jump ssredir
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        # Proxy traffic from other hosts (gateway mode) - IPv4 and IPv6
        # We do NOT filter by UID here to allow gateway mode (LAN clients) to work.
        # Gateway traffic has no local UID, so it would bypass the rule if we added 'skuid != ...'.
        
        meta nfproto ipv4 fib saddr type != local fib daddr type != local meta l4proto tcp jump ssredir
        meta nfproto ipv4 fib saddr type != local fib daddr type != local meta l4proto udp jump ssredir
        meta nfproto ipv6 fib saddr type != local fib daddr type != local meta l4proto tcp jump ssredir
        meta nfproto ipv6 fib saddr type != local fib daddr type != local meta l4proto udp jump ssredir

        # Redirect marked packets to TPROXY - IPv4
        meta nfproto ipv4 meta mark $PROXY_MARK meta l4proto tcp tproxy ip to 127.0.0.1:$LOCAL_PROXY_PORT accept
        meta nfproto ipv4 meta mark $PROXY_MARK meta l4proto udp tproxy ip to 127.0.0.1:$LOCAL_PROXY_PORT accept
        
        # Redirect marked packets to TPROXY - IPv6
        meta nfproto ipv6 meta mark $PROXY_MARK meta l4proto tcp tproxy ip6 to [::1]:$LOCAL_PROXY_PORT accept
        meta nfproto ipv6 meta mark $PROXY_MARK meta l4proto udp tproxy ip6 to [::1]:$LOCAL_PROXY_PORT accept
    }
}
EOF
}

stop_nftables() {
    nft delete table inet mangle_proxy &>/dev/null
}

start_iproute2() {
    # IPv4 routing
    ip route add local default dev lo table 100 &>/dev/null || true
    ip rule add fwmark $PROXY_MARK table 100 &>/dev/null || true
    
    # IPv6 routing
    ip -6 route add local default dev lo table 100 &>/dev/null || true
    ip -6 rule add fwmark $PROXY_MARK table 100 &>/dev/null || true
}

stop_iproute2() {
    ip rule del table 100 &>/dev/null
    ip route flush table 100 &>/dev/null
    ip -6 rule del table 100 &>/dev/null
    ip -6 route flush table 100 &>/dev/null
}

start() {
    echo "start ..."
    start_ipt2socks
    start_nftables
    start_iproute2
    echo "start end"
}

stop() {
    echo "stop ..."
    stop_iproute2
    stop_nftables
    stop_ipt2socks
    echo "stop end"
}

restart() {
    stop
    sleep 1
    start
}

status() {
    echo "=== nftables rules ==="
    nft list table inet mangle_proxy 2>/dev/null || echo "Table not found"
    echo ""
    echo "=== ip rules ==="
    echo "IPv4:"
    ip rule show
    echo "IPv6:"
    ip -6 rule show
    echo ""
    echo "=== ip routes (table 100) ==="
    echo "IPv4:"
    ip route show table 100
    echo "IPv6:"
    ip -6 route show table 100
    echo ""
    echo "=== processes ==="
    ps aux | grep ipt2socks | grep -v grep
    echo ""
    echo "=== listening sockets ==="
    ss -tlnp | grep ipt2socks
}

main() {
    if [ $# -eq 0 ]; then
        echo "usage: $0 start|stop|restart|status ..."
        return 1
    fi

    for funcname in "$@"; do
        if [ "$(type -t $funcname)" != 'function' ]; then
            echo "'$funcname' not a shell function"
            return 1
        fi
    done

    for funcname in "$@"; do
        $funcname
    done
    return 0
}

main "$@"
