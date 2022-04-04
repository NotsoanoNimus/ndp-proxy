#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>
#include <getopt.h>
#include <err.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>


/*
 * Definitions
 */

#define PACKET_BUFFER_SIZE 2048
#define MAX_PROXIED_NETWORKS 256
// Taken from STDINT.H directly.
#define UINT32_MAX             (4294967295U)

typedef enum output_type {
    ERROR_NONE = 0,
    ERROR_APPEND,
    ERROR_NO_APPEND,
    ERROR_SYSLOG
} output_type_t;


/*
 * Packet structures
 */

struct ndp_proxy_icmp6_ns {
    struct ethhdr eth;
    struct ip6_hdr ip;
    struct nd_neighbor_solicit ns_packet;
} __attribute__((__packed__));

struct ndp_proxy_icmp6_ns_opt {
    struct nd_opt_hdr opt;
    unsigned char lla[ETH_ALEN];
} __attribute__((__packed__));

struct ndp_proxy_ip6_proxied_net {
    struct in6_addr network;
    int mask;
} __attribute__((__packed__));


/*
 * Functions headers
 */

void write_output(
    output_type_t msg_type,
    int log_priority,
    const char* format,
    ...
);
void print_hex( unsigned char *data, size_t len );
int apply_config( struct ndp_proxy_ip6_proxied_net *net );
int parse_ip6_network( struct ndp_proxy_ip6_proxied_net *net, char *str );
int ip6_addr_is_proxied( struct in6_addr *address, struct ndp_proxy_ip6_proxied_net *proxied_networks );
uint16_t icmp6_cksum(
    unsigned char *icmp_packet,
    size_t len,
    struct in6_addr* src,
    struct in6_addr* dst
);
int forge_icmp6_na (
    unsigned char *buffer,
    unsigned char *srcmac,
    unsigned char *dstmac,
    struct in6_addr *srcip,
    struct in6_addr *dstip,
    struct in6_addr *target,
    unsigned char *lla
);
void daemonize();
void handle_signal( int signal );
void *issue_stats_update( void *vargp );


/*
 * Global vars
 */

time_t now;      // Used by a separate thread to track when an update message is needed.
struct tm *tm;   // ^^^
pthread_t stats_thread;

int verbose      = 1;          // Verbosity level
int verbosity_o  = 0;          // Whether the verbosity has been overridden by CLI parameter
int daemon_mode  = 0;          // Daemon mode
int quiet_mode   = 0;          // Quiet mode
int config_read  = 0;          // Whether the config has yet been read/verified

int proxied_nets = 0;          // How many networks are being proxied; running counter
uint32_t answers = 0;          // How many NA responses have been issued throughout the program's lifetime

char pidfile_c[PATH_MAX];      // PID File
char logfile_c[PATH_MAX];      // Logging File (when running as a daemon only)
char configfile_c[PATH_MAX];   // Configuration File
char *pidfile    = &pidfile_c[0];
char *logfile    = &logfile_c[0];
char *configfile = &configfile_c[0];

FILE *stdout_log_h;            // STDOUT program log handle
FILE *stderr_log_h;            // STDERR program log handle

// Scoped globally so config file reads can apply interface settings.
char interface_c[IF_NAMESIZE]; // Interface to bind to
char *interface = &interface_c[0];
int interface_index;           // Interface index
unsigned char
    interface_mac[ETH_ALEN];   // Interface MAC address

const char *syslog_tag = "ndp-proxy";   // Syslog tagname for program output.


/*
 * Main
 */

int main( int argc, char **argv ) {
    // Array of network IDs + netmasks that will be proxied by the program.
    struct ndp_proxy_ip6_proxied_net networks[MAX_PROXIED_NETWORKS];

    // Zero out all global string buffers, or set their default values as needed.
    memset( interface, 0, IF_NAMESIZE );
    memset( pidfile, 0, PATH_MAX );
    memset( logfile, 0, PATH_MAX );
    configfile = "/etc/ndp-proxy.conf";

    // Print an initial date banner for the application's custom log-file.
    now = time( 0 );
    struct tm *tm;
    if ( (tm = localtime( &now )) != NULL ) {
        fprintf( stderr,
            "\n\n====================================\n"
            "==== Init: %04d-%02d-%02d  %02d:%02d:%02d ====\n"
            "====================================\n",
            tm->tm_year, tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec
        );
    } else  fprintf( stderr, "\n\n====================\n====================\n====================\n" );

    // Open the syslog stream (or at least get it init'd).
    //  It shouldn't really matter if the running user selected daemon_mode (-d) or not.
    openlog( syslog_tag, (LOG_CONS | LOG_NDELAY | LOG_PID), LOG_DAEMON );
    write_output( ERROR_NONE, LOG_NOTICE, "Initializing.\n" );

    // Create and start the stats thread.
    ////pthread_create( &stats_thread, NULL, issue_stats_update, NULL );

    // Signals handling registration.
    struct sigaction sa;
    memset( &sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = handle_signal;
    sigaction( SIGINT,  &sa, NULL );
    sigaction( SIGTERM, &sa, NULL );

    // CLI long options
    struct option cli_long_options[] = {
        { "help",       no_argument,       NULL, 'h' },
        { "daemon",     no_argument,       NULL, 'd' },
        { "quiet",      no_argument,       NULL, 'q' },
        { "verbose",    required_argument, NULL, 'v' },
        { "configfile", required_argument, NULL, 'c' },
        { "interface",  required_argument, NULL, 'i' },
        { "network",    required_argument, NULL, 'n' },
        { "pidfile",    required_argument, NULL, 'p' },
        { "logfile",    required_argument, NULL, 'l' },
        { 0,            0,                 0,    0 }
    };
    int cli_option_index = 0;
    int cli_opt;

    // Parse CLI args. Parameters entered by CLI can serve to explicitly override configuration values.
    for ( ; ; ) {
        cli_opt = getopt_long( argc, argv, "hc:i:n:p:l:dqv:", cli_long_options, &cli_option_index );
        if ( cli_opt == -1 )  break;

        switch ( cli_opt ) {
            default :
            case 'h':
                write_output( ERROR_SYSLOG, LOG_NOTICE, "Showing help and exiting." );
                fprintf( stderr,
                       "NDP Proxy is a CLI or daemonized utility to answer IPv6 Neighbor Solicitation packets\n"
                       "  on the behalf of another device. CLI options can be manually provided to either\n"
                       "  override configuration presets, or for when simply running in the foreground.\n"
                       "\n"
                       "Options:\n"
                       " -h --help                    Display this help\n"
                       " -c --configfile <configfile> Set the configuration file location manually\n"
                       " -i --interface <interface>   Set the interface manually\n"
                       " -n --network <network>       Add a network to proxy (NET::/CIDR format)\n"
                       " -p --pidfile <pidfile>       Set the pidfile location manually\n"
                       " -l --logfile <logfile>       Set the logfile location manually\n"
                       " -d --daemon                  Daemon mode; forks the running process into the background\n"
                       " -q --quiet                   Quiet mode; disables non-error output and logging forcibly\n"
                       "                                Note however that this will NOT disable syslogging\n"
                       " -v --verbosity <level>       Verbosity level; overridden by Quiet mode\n"
                       "    0 = same as quiet mode\n"
                       "    1 = [default] output level; logs on startup and when a packet is proxied\n"
                       "    2 = descriptive output level; very detailed description of operations\n"
                       "    3 = debug logging; hexadecimal packet capturing\n"
                       "\n"
                );
                exit( 0 );
            case 'i':
                if ( strnlen(interface, IF_NAMESIZE) )  break;
                strncpy( interface, optarg, IF_NAMESIZE-1 );
                interface[IF_NAMESIZE] = 0;   // force null-termination
                if ( verbose )  write_output( ERROR_NONE, LOG_INFO, "Set listening interface: '%s'\n", interface );
                break;
            case 'n':
                if ( proxied_nets >= MAX_PROXIED_NETWORKS )
                    write_output( ERROR_NO_APPEND, LOG_ERR,
                        "exceeded proxied networks limit of %d", MAX_PROXIED_NETWORKS );
                if ( verbose )
                    write_output( ERROR_NONE, LOG_INFO, "Reading parameterized network entry: '%s'\n", optarg );
                if ( parse_ip6_network( &networks[proxied_nets], optarg ) == 1 )  proxied_nets++;
                else  write_output( ERROR_NONE, LOG_WARNING, "Invalid IPv6 network in CLI params: '%s'\n", optarg );
                break;
            case 'v':
                if ( quiet_mode || verbosity_o )  break;   // don't allow it to change if quiet-mode is enabled.
                int verbosity = atoi( optarg );
                if ( verbosity >= 0 && verbosity <= 3 )  verbose = verbosity;
                verbosity_o = 1;
                write_output( ERROR_NONE, LOG_INFO, "Verbosity overridden by CLI param to '%d'.\n", verbose );
                break;
            case 'q':
                if ( quiet_mode )  break;
                quiet_mode = 1;
                verbose = 0;
                write_output( ERROR_NONE, LOG_INFO, "Quiet mode enabled.\n" );
                break;
            case 'd':
                daemon_mode = 1;
                write_output( ERROR_NONE, LOG_INFO, "Daemon mode enabled by CLI param.\n" );
                break;
            case 'p':
                if ( (pidfile = strndup(optarg,PATH_MAX)) == NULL )
                    write_output( ERROR_APPEND, LOG_ERR, "strndup: failed to copy PIDfile override parameter" );
                break;
            case 'l':
                if ( (logfile = strndup(optarg,PATH_MAX)) == NULL )
                    write_output( ERROR_APPEND, LOG_ERR, "strndup: failed to copy logfile override parameter" );
                break;
            case 'c':
                if ( (configfile = strndup(optarg,PATH_MAX)) == NULL )
                    write_output( ERROR_APPEND, LOG_ERR, "strndup: failed to copy configfile override parameter" );
                break;
        }
    }

    // Read configuration values. When a value is already defined by optargs, don't step over it.
    if ( apply_config( networks ) != 1 )
        write_output( ERROR_NO_APPEND, LOG_ERR, "failed to read or apply configuration" );

    // Sanity checks, post-configuration-application.
    //// At least one network is defined.
    if ( proxied_nets <= 0 )  write_output( ERROR_NO_APPEND, LOG_ERR, "no networks to proxy" );
    //// A valid interface string was provided.
    if ( strnlen(interface,IF_NAMESIZE) < 1 )
        write_output( ERROR_NO_APPEND, LOG_ERR, "no interface name was defined explicitly or by configuration" );
    //// PID file is defined.
    if ( strnlen(pidfile,PATH_MAX) < 1 )
        write_output( ERROR_NO_APPEND, LOG_ERR, "no PID file was defined explicitly or by configuration" );
    //// Log file is defined (if daemon_mode).
    if ( daemon_mode && strnlen(logfile,PATH_MAX) < 1 )
        write_output( ERROR_NO_APPEND, LOG_ERR, "no log file was defined explicitly or by configuration" );

    // Used by write_output to always emit a syslog message on early terminating errors.
    config_read = 1;

    // Daemonize, if requested.
    if ( daemon_mode ) {
        if ( verbose )  write_output( ERROR_NONE, LOG_INFO, "Daemonizing.\n" );
        daemonize( pidfile, logfile );
    }

    // Print service parameters, if not quiet-mode.
    if ( verbose ) {
        write_output( ERROR_NONE, LOG_INFO, "Listening on interface '%s'.\n", interface );
        write_output( ERROR_NONE, LOG_INFO, "Proxying for %d networks", proxied_nets );
        if ( verbose > 1 ) {
            fprintf( stderr, ":\n" );
            struct ndp_proxy_ip6_proxied_net *ntwk = networks;
            for ( int i = 0; i < proxied_nets; i++, ntwk++ ) {
                char netaddr_c[INET6_ADDRSTRLEN];
                char *netaddr = &netaddr_c[0];
                inet_ntop( AF_INET6, &ntwk->network, netaddr, INET6_ADDRSTRLEN );
                write_output( ERROR_NONE, LOG_INFO, "\tNetwork: %s/%d\n", netaddr, ntwk->mask );
            }
            fprintf( stderr, "\n" );
        } else  fprintf( stderr, ".\n" );
    } else  write_output( ERROR_NONE, LOG_INFO, "Listening...\n" );


    // Linux Socket Filtering filter
    static struct sock_filter BPF_code[] = {
        { BPF_LD  + BPF_H   + BPF_ABS , 0, 0, 12 },
        { BPF_JMP + BPF_JEQ + BPF_K   , 0, 5, ETH_P_IPV6 },
        { BPF_LD  + BPF_B   + BPF_ABS , 0, 0, 20 },
        { BPF_JMP + BPF_JEQ + BPF_K   , 0, 3, IPPROTO_ICMPV6 },
        { BPF_LD  + BPF_B   + BPF_ABS , 0, 0, 54 },
        { BPF_JMP + BPF_JEQ + BPF_K   , 0, 1, ND_NEIGHBOR_SOLICIT },
        { BPF_RET + BPF_K             , 0, 0, 65535 },
        { BPF_RET + BPF_K             , 0, 0, 0 }
    };
    struct sock_fprog filter = { 8, BPF_code };
    struct ifreq ethreq;   // ioctl data buffer
    int sock;   // Socket

    // Open the socket
    if ( (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) < 0 )
        write_output( ERROR_APPEND, LOG_ERR, "failed to initialize the listening socket" );

    // Bind to interface
    if ( setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strnlen(interface,IF_NAMESIZE) ) < 0 )
        write_output( ERROR_APPEND, LOG_ERR, "could not bind to interface '%s'", interface );

    // Get interface MAC address
    memset( &ethreq, 0, sizeof(struct ifreq) );
    strncpy( ethreq.ifr_name, interface, IF_NAMESIZE );
    if ( ioctl(sock, SIOCGIFHWADDR, &ethreq) == -1 )
        write_output( ERROR_APPEND, LOG_ERR, "problem getting interface HW addr" );
    memcpy( interface_mac, ethreq.ifr_hwaddr.sa_data, ETH_ALEN );

    // Get interface ifindex
    memset( &ethreq, 0, sizeof(struct ifreq) );
    strncpy( ethreq.ifr_name, interface, IF_NAMESIZE );
    if ( ioctl(sock, SIOCGIFINDEX, &ethreq) == -1 )
        write_output( ERROR_APPEND, LOG_ERR, "ioctl: failed to get interface index" );
    interface_index = ethreq.ifr_ifindex;

    // Enable the interface's promiscuous mode flag
    memset( &ethreq, 0, sizeof(struct ifreq) );
    strncpy( ethreq.ifr_name, interface, IF_NAMESIZE );
    if ( ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1 )
        write_output( ERROR_APPEND, LOG_ERR, "ioctl: failed to get interface flags" );
    ethreq.ifr_flags |= IFF_PROMISC;
    if ( ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1 )
        write_output( ERROR_APPEND, LOG_ERR, "ioctl: failed to set interface flags" );

    // Attach the filter to the socket
    if ( setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0 )
        write_output( ERROR_APPEND, LOG_ERR, "setsockopt: failed to attach the filter to the socket" );


    // Data structures/values used within the primary program loop.
    struct in6_addr *target_ip;          // Target IP
    struct in6_addr *client_ip;          // Client IP
    unsigned char *client_mac;           // Client MAC address string
    struct ndp_proxy_icmp6_ns *icmp6_ns;           // ICMPv6 Neighbor Solicitation structure
    struct ndp_proxy_icmp6_ns_opt *icmp6_ns_opt;   // ICMPv6 Neighbor Solicitation option structure

    unsigned char in_buffer[PACKET_BUFFER_SIZE];   // Input buffer
    unsigned char out_buffer[PACKET_BUFFER_SIZE];   // Output buffer
    size_t nbytes;   // Data length from/to socket

    // Miscellaneous buffers used to display variables in a human readable format.
    char target_ip_c[INET6_ADDRSTRLEN];
    char client_ip_c[INET6_ADDRSTRLEN];
    char srcmac_c[18];
    char dstmac_c[18];
    char client_mac_c[18];
    char network_c[INET6_ADDRSTRLEN];

    // Enter the primary program loop, indefinitely, until a signal is received.
    while ( 1 ) {
        // Receive a packet
        if ( verbose == 3 )  write_output( ERROR_NONE, LOG_DEBUG, "Waiting for data.\n" );
        if ( (nbytes = recv(sock, in_buffer, PACKET_BUFFER_SIZE, 0)) < 0 )  write_output( ERROR_APPEND, LOG_ERR, "recv" );
        if ( verbose == 3 ) {
            write_output( ERROR_NONE, LOG_DEBUG, "Received %d bytes of socket data.", nbytes );
            if ( !daemon_mode ) {
                // Hex dumps will not be written in daemon mode, regardless of verbosity.
                print_hex( in_buffer, nbytes );
                fprintf( stderr, "\n\n" );
            } else  fprintf( stderr, "\n" );
        }

        // Decode ICMP
        icmp6_ns = (struct ndp_proxy_icmp6_ns *)in_buffer;
        // Decode ICMP Option if present
        icmp6_ns_opt = ( ntohs(icmp6_ns->ip.ip6_plen) > sizeof(struct nd_neighbor_solicit) )
            ? (struct ndp_proxy_icmp6_ns_opt *)(icmp6_ns + 1)
            : NULL;

        // Extract needed values
        target_ip = &icmp6_ns->ns_packet.nd_ns_target;
        client_ip = &icmp6_ns->ip.ip6_src;
        client_mac = (unsigned char *)( (icmp6_ns_opt != NULL) ? &icmp6_ns_opt->lla : &icmp6_ns->eth.h_source );

        // Print a resume
        inet_ntop( AF_INET6, client_ip, client_ip_c, INET6_ADDRSTRLEN );
        inet_ntop( AF_INET6, target_ip, target_ip_c, INET6_ADDRSTRLEN );
        ether_ntoa_r( (const struct ether_addr *)icmp6_ns->eth.h_source, srcmac_c );
        ether_ntoa_r( (const struct ether_addr *)icmp6_ns->eth.h_dest,   dstmac_c );
        if ( verbose == 3 ) {
            write_output(
                     ERROR_NONE, LOG_DEBUG,
                     "%s > %s : Neighbor Solicitation from client '%s' for target '%s'",
                     srcmac_c, dstmac_c, client_ip_c, target_ip_c
            );
        } else if ( verbose > 1 ) {
            write_output(
                     ERROR_NONE, LOG_INFO,
                     "Neighbor Solicitation from '%s', seeking target '%s'",
                     client_ip_c, target_ip_c
            );
        }
        if ( icmp6_ns_opt != NULL ) {
            ether_ntoa_r( (const struct ether_addr *)client_mac, client_mac_c );
            if ( verbose >= 2 )  write_output( ERROR_NONE, LOG_DEBUG, " >>> (Client LLA: [%s])", client_mac_c );
        }

        // If it matches a subnet from the list of proxied networks...
        if ( ip6_addr_is_proxied(target_ip, networks) == 1 ) {
            // ... Then prepare and send the answer.
            nbytes = forge_icmp6_na(
                out_buffer,
                interface_mac,
                client_mac,
                target_ip,
                client_ip,
                target_ip,
                interface_mac
            );

            struct sockaddr_ll addr;
            memset( &addr, 0, sizeof(struct sockaddr_ll) );

            addr.sll_family = AF_PACKET;
            addr.sll_ifindex = interface_index;
            addr.sll_halen = ETH_ALEN;
            memcpy( &addr.sll_addr, client_mac, ETH_ALEN );

            if ( sendto(sock, out_buffer, nbytes, 0, (const struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0 )
                write_output( ERROR_APPEND, LOG_ERR, "sendto: could not transmit output buffer" );

            if ( verbose == 3 ) {
                write_output( ERROR_NONE, LOG_DEBUG, "\nSent %d bytes of socket data.", nbytes );
                if ( !daemon_mode ) {
                    // Hex dumps will not be written in daemon mode, regardless of verbosity.
                    print_hex( out_buffer, nbytes );
                    fprintf( stderr, "\n\n" );
                } else  fprintf( stderr, "\n" );
            } else if ( verbose > 1 )  write_output( ERROR_NONE, LOG_INFO, " >>> [Answered]" );

            // Increment the counter.
            if ( answers < UINT32_MAX ) {
                answers++;
            } else {
                write_output( ERROR_NONE, LOG_NOTICE, "Answers counter rollover beyond UINT32_MAX. Resetting value.\n" );
                answers = 0;
            }
        }

        if ( verbose )  fprintf( stderr, "\n" );
    }
}


/*
 * Functions
 */

void write_output( output_type_t msg_type, int log_priority, const char* format, ... ) {
    va_list ap, ap2;
    va_start( ap, format );
    va_copy( ap2, ap );

    // Syslog messages should only be written in daemon-mode or before
    //   the program can fully recognize if it's even supposed to be in daemon-mode.
    if ( msg_type == ERROR_SYSLOG || daemon_mode || (!config_read && msg_type == ERROR_NONE) )
        vsyslog( log_priority, format, ap );

    // Regardless of the syslog params, write the message to STDERR.
    //   This will always send the message to the custom daemon log-file, regardless of syslogging.
    if ( msg_type == ERROR_NONE )  vfprintf( stderr, format, ap2 );
    else if ( msg_type == ERROR_APPEND )  verr( 1, format, ap2 );
    else if ( msg_type == ERROR_NO_APPEND )  verrx( 1, format, ap2 );

    va_end( ap );
    va_end( ap2 );
}


void print_hex( unsigned char *data, size_t len ) {
    for ( size_t i = 0; i < len; i++ ) {
        if ( !(i % 8) )   fprintf(stderr, "  ");
        if ( !(i % 16) )  fprintf(stderr, "\n");
        fprintf( stderr, "%02x ", data[i] );
    }
    fprintf( stderr, "\n" );
}


// Quick string trimming function for configuration parsing.
char* strtrim( char *str ) {
    char *end;
    while ( isspace((unsigned char)*str) )  str++;
    if ( *str == 0 )  return str;
    end = str + strlen(str) - 1;
    while ( end > str && isspace((unsigned char)*end) )  end--;
    end[1] = '\0';
    return str;
}

#define MAX_CONF_STRLEN 512
int apply_config( struct ndp_proxy_ip6_proxied_net *net ) {
    FILE *config_file_h;

    // Open the configuration file for reading.
    if ( verbose )  write_output( ERROR_NONE, LOG_INFO, "Attempting to read configuration at: '%s'\n", configfile );
    if ( (config_file_h = fopen(configfile, "r")) == NULL )
        write_output( ERROR_APPEND, LOG_ERR, "fopen: failed to read configuration", configfile );

    // Parse each line.
    char buf[MAX_CONF_STRLEN];
    const char delim[] = "=";   // Delimiter for key-value mapping.
    while ( !feof(config_file_h) ) {
        // Read a line from the configuration file.
        fgets( buf, MAX_CONF_STRLEN, config_file_h );
        // Any line starting with [#;\s] or less than 3 chars should be skipped.
        if ( buf[0] == '#' || buf[0] == ';' || isspace(buf[0]) || strlen(buf) < 3 )  continue;

        // Get the key-value pair being parsed.
        char *confVal = strtok( buf, delim );   // Get the left side of the '='
        if ( confVal == NULL ) {
            if ( verbose == 3 )  write_output( ERROR_NONE, LOG_DEBUG, "Skipping bad key line: |%s|\n", buf );
            continue;
        }
        char *key = strtrim( confVal );   // trim it

        confVal = strtok( NULL, delim );   // Get the right side
        if ( confVal == NULL ) {
            if ( verbose == 3 )  write_output( ERROR_NONE, LOG_DEBUG, "Skipping bad value line: |%s|\n", buf );
            continue;
        }
        char *val = strtrim( confVal );   // trim it
        // If any '=' is found within the value itself (for ex: a path or file char), make sure it gets lumped on.
        while ( (confVal = strtok(NULL,delim)) != NULL )
            strncat( val, confVal, MAX_CONF_STRLEN );

        // Sanity check.
        if ( strlen(key) < 1 || strlen(val) < 1 ) {
            if ( verbose == 3 )  write_output( ERROR_NONE, LOG_DEBUG, "Skipping bad key-value pair: |%s|\n", buf );
            continue;
        } else {
            // Convert both values to lower-case.
            char *k = key;
            char *v = val;
            for ( ; *k; ++k )  *k = tolower(*k);
            for ( ; *v; ++v )  *v = tolower(*v);
            if ( verbose == 3 )  write_output( ERROR_NONE, LOG_DEBUG, "Reading key-value pair: |%s|,|%s|\n", key, val );
        }

        // Set global variable values depending on the setting being parsed.
        if ( strcmp( key, "verbosity" ) == 0 ) {
            if ( quiet_mode ) {
                //fprintf( stderr, "Quiet mode is enabled; ignoring configuration verbosity setting.\n" );
                continue;
            } else if ( verbosity_o ) {
                if ( verbose )
                    write_output( ERROR_NONE, LOG_INFO,
                        "\tVerbosity was set by CLI param; not setting by configuration.\n" );
                continue;
            }
            int v = atoi( val );
            if ( v >= 0 && v <= 3 )  verbose = v;
            if ( verbose >= 2 )  write_output( ERROR_NONE, LOG_DEBUG, "\tSet verbosity to '%d'.\n", v );
        } else if ( strcmp( key, "interface" ) == 0 ) {
            if ( strnlen(interface,IF_NAMESIZE) > 0 ) {
                if ( verbose )
                    write_output( ERROR_NONE, LOG_INFO,
                        "\tInterface was set by CLI param; not setting by configuration.\n" );
                continue;
            }
            if ( (interface = strndup(val, IF_NAMESIZE)) == NULL )
                write_output( ERROR_APPEND, LOG_ERR, "strndup: failed to set interface" );
            if ( verbose >= 2 )  write_output( ERROR_NONE, LOG_DEBUG, "\tSet interface to '%s'.\n", interface );
        } else if ( strcmp( key, "pidfile" ) == 0 ) {
            if ( strnlen(pidfile,PATH_MAX) > 0 ) {
                if ( verbose )
                    write_output( ERROR_NONE, LOG_DEBUG,
                        "PID file was set by CLI param; not setting by configuration.\n" );
                continue;
            }
            if ( (pidfile = strndup(val, PATH_MAX)) == NULL )
                write_output( ERROR_APPEND, LOG_ERR, "strndup: failed to read pidfile path" );
            if ( verbose >= 2 )  write_output( ERROR_NONE, LOG_DEBUG, "\tSet PIDFile to '%s'.\n", pidfile );
        } else if ( strcmp( key, "logfile" ) == 0 ) {
            if ( strnlen(logfile,PATH_MAX) > 0 ) {
                if ( verbose )
                    write_output( ERROR_NONE, LOG_DEBUG,
                        "\tLog file was set by CLI param; not setting by configuration.\n" );
                continue;
            }
            if ( (logfile = strndup(val, PATH_MAX)) == NULL )
                write_output( ERROR_APPEND, LOG_ERR, "strndup: failed to read logfile path" );
            if ( verbose >= 2 )  write_output( ERROR_NONE, LOG_DEBUG, "\tSet output log-file to '%s'.\n", logfile );
        } else if ( strcmp( key, "proxynet" ) == 0 ) {
            if ( proxied_nets >= MAX_PROXIED_NETWORKS )
                write_output( ERROR_NO_APPEND, LOG_ERR,
                    "exceeded proxied networks limit of %d", MAX_PROXIED_NETWORKS );
            if ( verbose >= 2 )  write_output( ERROR_NONE, LOG_DEBUG, "\tParsing IPv6 proxy network: '%s'\n", val );
            if ( parse_ip6_network( &net[proxied_nets], val ) == 1 )  proxied_nets++;
            else  write_output( ERROR_NONE, LOG_NOTICE, "Invalid IPv6 network in configuration: '%s'\n", val );
        } else {
            if ( verbose == 3 )  write_output( ERROR_NONE, LOG_DEBUG, "Skipping unknown key: |%s|\n", key );
        }
    }

    if ( fclose(config_file_h) == EOF )
        write_output( ERROR_APPEND, LOG_ERR, "fclose: problem closing configuration file handle" );

    return 1;
}


int parse_ip6_network( struct ndp_proxy_ip6_proxied_net *net, char *str ) {
    const char delim[] = "/";   // Delimiter for CIDR masking

    char *token = strtok( str, delim );
    if ( token == NULL || inet_pton(AF_INET6, token, &net->network) != 1 ) {
        if ( verbose >= 2 )
            write_output( ERROR_NONE, LOG_DEBUG, "'%s' is not valid: bad network\n", str );
        return 0;
    }

    token = strtok( NULL, delim );   // Seek the second token
    if ( token == NULL || atoi( token ) < 0 || atoi( token ) > 128 ) {
        if ( verbose >= 2 )
            write_output( ERROR_NONE, LOG_DEBUG, "'%s' is not valid: netmask must be between 0 and 128\n", str );
        return 0;
    }
    net->mask = atoi( token );

    return 1;
}


int ip6_addr_is_proxied( struct in6_addr *address, struct ndp_proxy_ip6_proxied_net *proxied_networks ) {
    if ( verbose == 3 )  fprintf( stderr, "\n" );
    for ( int i = 0; i < proxied_nets; i++, proxied_networks++ ) {
        if ( verbose == 3 ) {
            char add_c[INET6_ADDRSTRLEN];
            char pxy_c[INET6_ADDRSTRLEN];
            inet_ntop( AF_INET6, address, add_c, INET6_ADDRSTRLEN );
            inet_ntop( AF_INET6, &proxied_networks->network, pxy_c, INET6_ADDRSTRLEN );
            write_output( ERROR_NONE, LOG_DEBUG,
                "\tSeeing if address '%s' is within '%s/%d'\n", add_c, pxy_c, proxied_networks->mask );
        }
        // Create a bitmask of the right length to match the subnet.
        struct in6_addr mask;
        memset( &mask, 0x00, sizeof(struct in6_addr) );
        memset( &mask, 0xFF, (proxied_networks->mask / 8) );
        mask.s6_addr[proxied_networks->mask / 8] = 0xFF << (8 - (proxied_networks->mask % 8));

        int match = 1;
        for ( int j = 0; j < 4; j++ ) {
            if ( (address->s6_addr32[j] & mask.s6_addr32[j])
                  != (proxied_networks->network.s6_addr32[j] & mask.s6_addr32[j]) )  match = 0;
        }

        // If a proxied network exists that matches the masked address, return a true.
        if ( match ) {
            if ( verbose == 3 )  write_output( ERROR_NONE, LOG_DEBUG, "\t\t >>> It is!\n" );
            return 1;
        }
    }

    // Otherwise, fall through to false if all networks were iterated and no match was found.
    return 0;
}


uint16_t icmp6_cksum( unsigned char *icmp_packet, size_t len, struct in6_addr* src, struct in6_addr* dst ) {
    uint16_t *data;
    uint32_t cksum;

    data = (uint16_t *)icmp_packet;
    cksum = 0;

    // Sum fake header
    for ( int i = 0; i < 8; i++ ) {
        cksum += src->s6_addr16[i];
        cksum += (cksum < src->s6_addr16[i]) ? 1 : 0;
        cksum += dst->s6_addr16[i];
        cksum += (cksum < dst->s6_addr16[i]) ? 1 : 0;
    }

    cksum += htonl( (uint32_t)len );
    cksum += (cksum < len) ? 1 : 0;
    cksum += htonl( (uint32_t)IPPROTO_ICMPV6 );
    cksum += (cksum < IPPROTO_ICMPV6) ? 1 : 0;

    // Sum data
    while ( len > 1 ) {
        cksum += *data;
        cksum += (cksum < *data) ? 1 : 0;
        data++;
        len -= sizeof(uint16_t);
    }

    if ( len ) {
        cksum += htonl( (uint16_t)(*(uint8_t *)data) << 8 );
        cksum += (cksum < ((*(uint8_t *)data) << 8)) ? 1 : 0;
    }

    // Fold sum
    cksum = (cksum & 0xFFFF) + (cksum >> 16);
    cksum = (cksum & 0xFFFF) + (cksum >> 16);

    return (uint16_t)(~cksum);
}


int forge_icmp6_na(
        unsigned char *buffer,
        unsigned char *srcmac,
        unsigned char *dstmac,
        struct in6_addr *srcip,
        struct in6_addr *dstip,
        struct in6_addr *target,
        unsigned char *lla
) {
    struct packet {
        struct ethhdr eth;
        struct ip6_hdr ip;
        struct nd_neighbor_advert na;
        struct nd_opt_hdr na_opt;
        unsigned char na_opt_lla[ETH_ALEN];
    } __attribute__((__packed__)) packet;

    // Link-local Address
    memcpy( &packet.na_opt_lla, lla, sizeof(struct in6_addr) );

    // Neighbor Advertisement Option (source link layer address)
    packet.na_opt.nd_opt_type = 2;
    packet.na_opt.nd_opt_len = 1;

    // Neighbor Advertisement
    packet.na.nd_na_type = ND_NEIGHBOR_ADVERT;
    packet.na.nd_na_code = 0;
    packet.na.nd_na_cksum = 0;
    packet.na.nd_na_flags_reserved = (ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_ROUTER);
    memcpy( &packet.na.nd_na_target, target, sizeof(struct in6_addr) );

    packet.na.nd_na_cksum = icmp6_cksum(
        (unsigned char *)&packet.na,
        sizeof(struct packet) - sizeof(struct ethhdr) - sizeof(struct ip6_hdr),
        srcip,
        dstip
    );

    // IPv6
    packet.ip.ip6_flow = htonl( 0x60000000 );
    packet.ip.ip6_plen = htons( sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + ETH_ALEN );
    packet.ip.ip6_nxt  = IPPROTO_ICMPV6;
    packet.ip.ip6_hlim = 0xFF;
    memcpy( &packet.ip.ip6_src, srcip, sizeof(struct in6_addr) );
    memcpy( &packet.ip.ip6_dst, dstip, sizeof(struct in6_addr) );

    // Ethernet
    memcpy( &packet.eth.h_dest, dstmac, ETH_ALEN );
    memcpy( &packet.eth.h_source, srcmac, ETH_ALEN );
    packet.eth.h_proto = htons( ETH_P_IPV6 );

    memcpy( buffer, &packet, sizeof(struct packet) );

    return sizeof(struct packet);
}


void daemonize( char *pidfile, char *logfile ) {
    FILE *pidfile_h;   // PID File handle
    pid_t pid;

    // First fork.
    pid = fork();
    if ( pid < 0 )  write_output( ERROR_APPEND, LOG_ERR, "first fork" );
    if ( pid > 0 )  exit( 0 );

    // Get a clean environment.
    if ( setsid() < 0 )    write_output( ERROR_APPEND, LOG_ERR, "setsid" );
    if ( chdir("/") < 0 )  write_output( ERROR_APPEND, LOG_ERR, "chdir" );
    umask( 0 );

    // Since we are not supposed to output anything, disable standard files.
    if ( quiet_mode ) {
        freopen( "/dev/null", "r", stdin );
        freopen( "/dev/null", "w", stdout );
        freopen( "/dev/null", "w", stderr );
    } else {
        freopen( "/dev/null", "r",  stdin  );
        if ( (stdout_log_h = freopen( logfile, "a+", stdout )) == NULL )
            write_output( ERROR_APPEND, LOG_ERR, "freopen: failed to open logging file for STDOUT" );
        if ( (stderr_log_h = freopen( logfile, "a+", stderr )) == NULL )
            write_output( ERROR_APPEND, LOG_ERR, "freopen: failed to open logging file for STDERR" );
    }

    // Second fork
    pid = fork();
    if ( pid < 0 )  write_output( ERROR_APPEND, LOG_ERR, "second fork" );
    if ( pid > 0 )  exit( 0 );

    // Write the PID into the pidfile.
    pid = getpid();

    if ( (pidfile_h = fopen(pidfile, "w+")) == NULL )
        write_output( ERROR_APPEND, LOG_ERR, "fopen: unable to write to pidfile" );
    if ( fprintf(pidfile_h, "%d", pid) < 0 )
        write_output( ERROR_APPEND, LOG_ERR, "fprintf: unable to write to pidfile" );
    if ( fclose(pidfile_h) == EOF )
        write_output( ERROR_APPEND, LOG_ERR, "fclose: failed to close pidfile handle" );
}


void handle_signal( int signal ) {
    if ( verbose )  write_output( ERROR_NONE, LOG_INFO, "Signal '%d' received. Exiting.\n", signal );
    else  write_output( ERROR_NONE, LOG_NOTICE, "Exiting.\n" );

    if ( daemon_mode && unlink(pidfile) < 0 )
        write_output( ERROR_APPEND, LOG_ERR, "unlink: failed to remove pidfile" );

    if ( stdout_log_h != NULL && fclose(stdout_log_h) == EOF )
        write_output( ERROR_APPEND, LOG_ERR, "fclose: failed to close STDOUT log stream" );
    if ( stderr_log_h != NULL && fclose(stderr_log_h) == EOF )
        write_output( ERROR_APPEND, LOG_ERR, "fclose: failed to close STDERR log stream" );

    exit( 0 );
}


void *issue_stats_update( void *vargp ) {
    pthread_detach( pthread_self() );
    while ( 1 ) {
            write_output( ERROR_NONE, LOG_INFO, "Stats: %d NA packets issued since initialization.\n", answers );
        sleep( 1 );
        if ( answers <= 0 )  continue;
        // Check if the counter needs an update via sys/log output.
        now = time( NULL );
        tm = localtime( &now );
        if ( tm->tm_sec == 0 ) {
            // If the clock's minute field went back to 00 (meaning a new hour), write the message.
            write_output( ERROR_NONE, LOG_INFO, "Stats: %d NA packets issued since initialization.\n", answers );
        }
    }
}
