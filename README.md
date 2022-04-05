NDP Proxy
=========

This software is an answer to the fact that the Linux kernel does not support proxying of ICMPv6 Neighbor Discovery Protocol packets for whole IPv6 subnets, but only for a given set of single addresses.

`ndp-proxy` binds promiscuously to an interface, and when it receives an NDP _Network Solicitation_ packet for an IPv6 address in any of one of many configured subnets, it will answer with a _Network Advertisement_ packet, similar to an IPv4 Proxy ARP mechanism.

This enables the ability to easily route whole subnets through a machine acting as a router (or an address-space black-hole), without needing to configure a route to that machine on upstream routers. It is useful especially if upstream routers are managed by somebody else and cannot be modified.

Usage
------
The binary is intended to be used as a background daemon, managed with systemd. To run as a daemon, the `-d` option should always be provided.

```
Options:
 -h --help                    Display this help
 -c --configfile <configfile> Set the configuration file location manually
 -i --interface <interface>   Set the interface manually
 -n --network <network>       Add a network to proxy (NET::/CIDR format)
 -p --pidfile <pidfile>       Set the pidfile location manually
 -l --logfile <logfile>       Set the logfile location manually
 -d --daemon                  Daemon mode; forks the running process into the background
 -q --quiet                   Quiet mode; disables non-error output and logging forcibly
                                Note however that this will NOT disable syslogging
 -v --verbosity <level>       Verbosity level; overridden by Quiet mode
    0 = same as quiet mode
    1 = [default] output level; logs on startup and when a packet is proxied
    2 = descriptive output level; very detailed description of operations
    3 = debug logging; hexadecimal packet capturing
```

Build
------
To install the daemon, simply run the following command in the project's base directory:

```
make && make install
```
