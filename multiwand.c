/*
    Created by Paul Chambers on 11/5/23.
*/

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <memory.h>

/* generic Linux network stuff */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <linux/rtnetlink.h>

/* specific to libnl3 (/usr/include/libnl3) */
#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/errno.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>


#include "multiwand.h"

typedef unsigned char byte;

#ifdef DEBUG

const char * icmpTypeAsString[] = {
    [ICMP_ECHOREPLY]         = "Echo Reply",
    [ICMP_DEST_UNREACH]      = "Destination Unreachable",
    [ICMP_SOURCE_QUENCH]     = "Source Quench",
    [ICMP_REDIRECT]          = "Redirect (change route)",
    [ICMP_ECHO]              = "Echo Request",
    [ICMP_TIME_EXCEEDED]     = "Time Exceeded",
    [ICMP_PARAMETERPROB]     = "Parameter Problem",
    [ICMP_TIMESTAMP]         = "Timestamp Request",
    [ICMP_TIMESTAMPREPLY]    = "Timestamp Reply",
    [ICMP_INFO_REQUEST]      = "Information Request",
    [ICMP_INFO_REPLY]        = "Information Reply",
    [ICMP_ADDRESS]           = "Address Mask Request",
    [ICMP_ADDRESSREPLY]      = "Address Mask Reply"
};

/* map a socket 'family' ID to a string for debugging messages */
const char * familyAsString[] = {
    [AF_UNSPEC]      = "Unspecified",
    [AF_LOCAL]       = "Local",
    [AF_INET]        = "IPv4",
    [AF_AX25]        = "Amateur Radio AX.25",
    [AF_IPX]         = "Novell Internet Protocol",
    [AF_APPLETALK]   = "Appletalk DDP",
    [AF_NETROM]      = "Amateur Radio NetROM",
    [AF_BRIDGE]      = "Multiprotocol bridge",
    [AF_ATMPVC]      = "ATM PVCs",
    [AF_X25]         = "X.25",
    [AF_INET6]       = "IPv6",
    [AF_ROSE]        = "Amateur Radio X.25 PLP",
    [AF_DECnet]      = "DECnet",
    [AF_NETBEUI]     = "802.2LLC",
    [AF_SECURITY]    = "Security callback pseudo AF",
    [AF_KEY]         = "PF_KEY key management",
    [AF_NETLINK]     = "Netlink",
    [AF_PACKET]      = "Packet",
    [AF_ASH]         = "Ash",
    [AF_ECONET]      = "Acorn Econet",
    [AF_ATMSVC]      = "ATM SVCs",
    [AF_RDS]         = "RDS",
    [AF_SNA]         = "Linux SNA",
    [AF_IRDA]        = "IRDA",
    [AF_PPPOX]       = "PPPoX",
    [AF_WANPIPE]     = "Wanpipe API",
    [AF_LLC]         = "Linux LLC",
    [AF_IB]          = "Native InfiniBand",
    [AF_MPLS]        = "MPLS",
    [AF_CAN]         = "CANbus",
    [AF_TIPC]        = "TIPC",
    [AF_BLUETOOTH]   = "Bluetooth",
    [AF_IUCV]        = "IUCV",
    [AF_RXRPC]       = "RxRPC",
    [AF_ISDN]        = "mISDN",
    [AF_PHONET]      = "Phonet",
    [AF_IEEE802154]  = "IEEE 802.15.4",
    [AF_CAIF]        = "CAIF",
    [AF_ALG]         = "Algorithm",
    [AF_NFC]         = "NFC",
    [AF_VSOCK]       = "vSockets",
    [AF_KCM]         = "Kernel Connection Multiplexer",
    [AF_QIPCRTR]     = "Qualcomm IPC Router",
    [AF_SMC]         = "SMC",
    [AF_XDP]         = "XDP",
    [AF_MCTP]        = "Management component transport protocol"
};
#endif

typedef union {
    sa_family_t          family;
    struct sockaddr      common;
    struct sockaddr_in   in;
    struct sockaddr_in6  in6;
    struct sockaddr_nl   nl;
} uSockAddr;

typedef struct {
    struct iphdr   ip;
    struct icmphdr icmp;
    uint8_t        payload[384];
} tICMPpacket;

typedef struct sProbe {
    struct sProbe * next;
    uSockAddr       dest;
} tProbe;

typedef struct sWANroute {
    struct sWANroute * next;

    struct {
        int             socketFD;
        int             index;
        const char *    name;
    } intf;

    uSockAddr   gateway;
    uSockAddr   source;
    uint32_t    metric;

    tProbe *    probeList;
} tWANroute;

typedef struct {
    struct {
        pid_t               pid;
        const char *        name;
    } my;
    struct {
        struct nl_sock *    socket;
    } netlink;
    uint16_t                seq;
    tICMPpacket *           packetList;
    tWANroute *             wanList;

    struct nl_cache *       routeCache;
    struct nl_cache *       linkCache;
    struct nl_cache *       addrCache;

    // libnl3 configuration for dumping structures
    struct nl_dump_params dp;
} tGlobals;

tGlobals g;

/************************************************************************************/

void dumpHex( void * ptr, size_t len )
{
    const char * sep;
    unsigned int offset = 0;

    if ( ptr == NULL || len == 0 ) return;
    do  {
        switch ( offset % 16 )
        {
        case 0:
            sep = " ";
            fprintf( stderr, "%04x: ", offset );
            break;

        case 3:
        case 7:
        case 11:
            sep = "  ";
            break;

        case 15:
            sep = (len > 1) ? "\n" : "";
            break;

        default:
            sep = " ";
            break;
        }
        fprintf( stderr, "%02x%s", ((uint8_t *)ptr)[offset], sep );
        offset++;
        len--;
    } while ( len > 0);

    fprintf( stderr, "\n" );
}

void dumpDec( void * ptr, size_t len )
{
    const char * sep;
    unsigned int offset = 0;

    if ( ptr == NULL || len == 0 ) return;
    do  {
        switch ( offset % 16 )
        {
        case 15:
            sep = (len > 1) ? "\n" : "";
            break;

        default:
            sep = " ";
            break;
        }
        fprintf( stderr, "%d%s", ((uint8_t *)ptr)[offset], sep );
        offset++;
        len--;
    } while ( len > 0);

    fprintf( stderr, "\n" );
}

void ipv6ToStr( byte * p, char * str, size_t strSize )
{
    uint16_t word;
    bool doneDouble = false;
    for ( int i = 0; i < 8 && strSize > 5; i++ )
    {
        word = (p[0] << 8) | p[1];
        p += 2;

        fprintf( stderr, "%d: 0x%04x\n", i, word);

        if ( word == 0 && doneDouble == false )
        {
            *str++ = ':';
            --strSize;
            while ( p[0] == 0 && p[1] == 0 ) {
                p += 2;
                i++;
            }
            doneDouble = true;
        } else {
            int size = snprintf( str, strSize, "%x", word );
            str += size;
            strSize -= size;
            if (i < 7) {
                *str++ = ':';
                --strSize;
            }
        }
    }
}

char * sockAddrToStr( uSockAddr * sockAddr, char * dest, size_t destSize )
{
    byte * d = dest;
    size_t dl = destSize;

    byte * p;

    switch (sockAddr->family)
    {
    case AF_UNSPEC:
        snprintf( dest, destSize,
                  "<address family not specified)>");
        break;
    case AF_INET:
        p = (byte *)&sockAddr->in.sin_addr;
        snprintf( dest, destSize,
                  "%s: %d.%d.%d.%d",
                  familyAsString[ sockAddr->family ],
                  p[0], p[1], p[2], p[3] );
        break;

    case AF_INET6:
        ipv6ToStr( (byte *) &sockAddr->in6.sin6_addr, dest, destSize );
        break;

    default:
        snprintf( dest, destSize,
                  "<unsupported socket address family (%s)>",
                  familyAsString[ sockAddr->family ]);
        break;
    }
    return dest;
}

/*
        char ipv6str[256];
        byte ip6Addr[] = { 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
                           0x00,0x00,0x00,0x00,0x12,0x34,0x56,0x78 };
        uSockAddr addr;
        addr.family = AF_INET6;
        memcpy( &addr.in6.sin6_addr, ip6Addr, sizeof(addr.in6.sin6_addr) );
        sockAddrToStr( &addr, ipv6str, sizeof(ipv6str));
        logDebug( "test: \'%s\'\n", ipv6str );
 */

/* generic test to see if two socket addresses are on the same subnet */
bool isSameAddr( uSockAddr * a, uSockAddr * b )
{
    if ( a->family != b->family ) {
        return false;
    } else {
        byte *pa;
        byte *pb;
        size_t len;
        switch (a->family)
        {
        case AF_INET:
            pa = (byte *)&a->in.sin_addr;
            pb = (byte *)&b->in.sin_addr;
            len = 4;
            break;

        case AF_INET6:
            pa = (byte *)&a->in6.sin6_addr;
            pb = (byte *)&b->in6.sin6_addr;
            len = 16;
            break;

        default:
            return false;
        }

        return memcmp( pa, pb, len ) == 0;
    }
}

/* generic test to see if two socket addresses are on the same subnet */
bool isSameSubnet( uSockAddr * a, uSockAddr * b, unsigned int maskBitLen )
{
    if ( a->family != b->family ) {
        return false;
    } else {
        byte *pa;
        byte *pb;
        switch (a->family)
        {
        case AF_INET:
            pa = (byte *)&a->in.sin_addr;
            pb = (byte *)&b->in.sin_addr;
            break;

        case AF_INET6:
            pa = (byte *)&a->in6.sin6_addr;
            pb = (byte *)&b->in6.sin6_addr;
            break;

        default:
            return false;
        }

        for ( unsigned int len = maskBitLen; len > 0; len -= 8 )
        {
            byte mask = ~((~0) >> len);
            if ( (*pa++ & mask) != (*pb++ & mask) )
            {
                return false;
            }
        }
        return true;
    }
}

/*
 * RFC 1071 checksum calculation
 */
unsigned int headerChecksum( void * header, size_t length )
{
    register uint16_t * word = (uint16_t *)header;
    register uint32_t   sum  = 0;

    // Sum adjacent 16 bit words
    while ( length > 1) {
        sum += *word++;
        length -= 2;
    }

    // if length was odd, there's one more byte to add. Assume upper 8 bits are zero.
    if (length > 0) {
        sum += *(uint8_t *)word;
    }

    // deferred carry processing: dd the carry bits that overflowed into the top
    // 16 bits back into the lower 16 bits. Repeat this while there are still
    // carry bits set in the upper 16 bits.
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // the checksum is actually the one's compliment of the calculation above.
    return ~sum;
}

/************************************************************************************/

int newICMPsocket( const char * interface )
{
    int result = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    if ( result < 0 ) {
        if ( errno == EPERM ) {
            logError( "%s needs to create a raw network socket, but doesn't have permission to do so.\n"
                      "Please either run %s as root, or grant it the CAP_NET_RAW capability (preferred).\n",
                      g.my.name, g.my.name );
            return -errno;
        } else perror( location " newICMPsocket" );
    } else {
        int on = 1;
        if ( setsockopt( result,
                         IPPROTO_IP, IP_HDRINCL,
                         &on, sizeof(on)) < 0 )
        {
            perror( location );
        } else if (setsockopt( result,
                               SOL_SOCKET, SO_BINDTODEVICE,
                               interface, strlen(interface)) < 0 )
        {
            perror( location );
        } //else logDebug( "socket fd for interface %s is %d\n", interface, result );
    }

    return result;
}


size_t makeIPv4header( struct iphdr * iph, int protocol, int ttl, uSockAddr * srcAddr, uSockAddr * dstAddr )
{
    int length = -1;
    if (srcAddr->family == AF_INET && dstAddr->family == AF_INET)
    {
        length        = 20;
        iph->version  = IPVERSION;
        iph->ihl      = length / 4;
        iph->tos      = 0;                        // default QOS class
        iph->id       = htons(g.seq++);  // monotonically-increasing sequence ID
        iph->frag_off = htons(IP_DF);    // don't fragment
        iph->ttl      = ttl;
        iph->protocol = protocol;
        memcpy( &iph->saddr, &srcAddr->in.sin_addr, sizeof(iph->saddr) );
        memcpy( &iph->daddr, &dstAddr->in.sin_addr, sizeof(iph->daddr) );

        // checksum field must be zero when the checksum calculation is done,
        // We can't calculate the checksum until the rest of the packet has been built and the length is known.
        iph->check = 0;
    }

    return length;
}

size_t makeICMPpacket( struct icmphdr * icmpPkt, uint8_t type, uint8_t code, void * body, size_t bodyLen )
{
    size_t length = sizeof( struct icmphdr ) + bodyLen;
    icmpPkt->type       = type;
    icmpPkt->code       = code;
    icmpPkt->checksum   = 0;
    icmpPkt->un.echo.id = g.my.pid;
    icmpPkt->un.echo.sequence = g.seq;
    memcpy(((uint8_t *)icmpPkt) + sizeof(struct icmphdr), body, bodyLen);

    icmpPkt->checksum = headerChecksum( icmpPkt, length );
    return length;
}

void makeEchoRequest( tICMPpacket * pkt,  uSockAddr * srcAddr, uSockAddr * dstAddr, int ttl )
{
    const char * payload = "connectivity check";

    size_t ipHdrLen   = makeIPv4header( &pkt->ip,
                                        IPPROTO_ICMP, ttl, srcAddr, dstAddr );
    size_t icmpHdrLen = makeICMPpacket( &pkt->icmp,
                                        ICMP_ECHO, 0,
                                        (void *)payload, strlen(payload) + 1 );
    pkt->ip.tot_len   = ipHdrLen + icmpHdrLen;
    pkt->ip.check     = headerChecksum( pkt, pkt->ip.tot_len );
}

tWANroute * allocWANroute( void )
{
    tWANroute * result = calloc( 1, sizeof(tWANroute) );
    if ( result != NULL ) {
        result->next = g.wanList;
        g.wanList = result;
    }

    return result;
}

in_addr_t getIPv4Addr( const struct nl_addr * addrObj )
{
    uint8_t * addr = nl_addr_get_binary_addr( addrObj );
    unsigned int len = nl_addr_get_len( addrObj );

//    logDebug( "source in memory: " );
//    dumpDec( source, len );

    in_addr_t s_addr = 0;
    for ( int i = 0; i < len; i++ ) {
        s_addr = (s_addr << 8) + *addr++;
    }
    return s_addr;
}

in_addr_t getIPv4Mask( const struct nl_addr * addrObj )
{
    /* calculate the subnet mask */
    unsigned int prefix = nl_addr_get_prefixlen( addrObj );
    unsigned int bitWidth = nl_addr_get_len( addrObj ) * 8;

    in_addr_t mask = ~((1 << (bitWidth - prefix)) - 1);
    logDebug( "mask 0x%08x\n", mask );
    return mask;
}

/* look for addresses associated with the given tWANroute object passed in arg */
void forEachAddrObj( struct nl_object * nlObj, void * arg )
{
    // we know it's an address object, since this callback is only ever used with the address cache
    struct rtnl_addr * addrObj = (struct rtnl_addr *) nlObj;
    tWANroute * wan = arg;

    /* this address object is associated with the interface of interest */
    if ( rtnl_addr_get_ifindex( addrObj ) == wan->intf.index )
    {
        // nl_object_dump( nlObj, &g.dp);

        /* if we have not yet found a source address with the
         * same subnet as the gateway, and this address is IPv4 */
        if ( wan->source.family == AF_UNSPEC )
        {
            struct nl_addr * localAddr = rtnl_addr_get_local( addrObj );

            socklen_t sockLen = sizeof( wan->source );
            nl_addr_fill_sockaddr( localAddr, &wan->source.common, &sockLen);

#ifdef DEBUG
            char ipAddrAsStr[256];
            nl_addr2str( localAddr, ipAddrAsStr, sizeof(ipAddrAsStr) );
            char sockAddrAsStr[256];
            sockAddrToStr( &wan->source, sockAddrAsStr, sizeof(sockAddrAsStr) );
            logDebug( "source: %s (ip: %s)\n", sockAddrAsStr, ipAddrAsStr );
#endif

            /* If this source address isn't in the same subnet as the gateway
             * address, undo what we just did.
             * This should not be common, but may occur if there are multiple IPv4
             * addresses associated with the same interface ('multi-homed') */
            if ( !isSameSubnet( &wan->source, &wan->gateway, nl_addr_get_prefixlen( localAddr)) )
            {
                /* This source address won't reach the gateway. So keep looking. */
                wan->source.family = AF_UNSPEC;
                logDebug( "subnet doesn't match\n" );
            }

            logDebug( "----\n" );
        }
    }
}

void forEachRouteObj( struct nl_object * nlObj, void * arg )
{
    // we know it's a route object, since this callback is only ever used with the route cache
    struct rtnl_route * routeObj = (struct rtnl_route *) nlObj;

    const struct nl_addr * nlAddr = rtnl_route_get_dst( routeObj );
    /* is it a default route? */
    if ( nl_addr_iszero( nlAddr ) )
    {
        struct rtnl_nexthop * nextHopObj = rtnl_route_nexthop_n( routeObj, 0 );
        if ( nextHopObj != NULL )
        {
            // nl_object_dump( nlObj, &dp );
            // rtnl_route_nh_dump( nextHopObj, &dp );

            tWANroute * wan = allocWANroute();
            if (wan != NULL)
            {
                wan->intf.index = rtnl_route_nh_get_ifindex( nextHopObj );
                struct rtnl_link * linkObj = rtnl_link_get( g.linkCache, wan->intf.index);

                wan->intf.name = strdup( rtnl_link_get_name ( linkObj ) );
                logDebug( "link name: %s\n", wan->intf.name );

                wan->intf.socketFD = newICMPsocket( wan->intf.name );
                /* if we can't open a raw ICMP socket, nothing will work... */
                if (wan->intf.socketFD >= 0 )
                {
                    /* API calls it 'priority', CLI calls it 'metric'. Not confusing at all... */
                    wan->metric = rtnl_route_get_priority( routeObj );
                    logDebug( "metric %d\n", wan->metric );

                    const struct nl_addr * gatewayAddr = rtnl_route_nh_get_gateway( nextHopObj );
                    if ( gatewayAddr == NULL) {
                        logDebug( "error: gatewayAddr is undefined\n" );
                    } else {
                        socklen_t sockLen = sizeof( wan->gateway );
                        nl_addr_fill_sockaddr( gatewayAddr, &wan->gateway.common, &sockLen);
#ifdef DEBUG
                        char str[256];
                        nl_addr2str( gatewayAddr, str, sizeof(str));
                        char sockAddrAsStr[256];
                        sockAddrToStr( &wan->gateway, sockAddrAsStr, sizeof(sockAddrAsStr) );

                        logDebug( "gateway: %s (%s)\n", sockAddrAsStr, str );
#endif
                    }

                    // nl_object_dump( (struct nl_object *) linkObj, &g.dp );

                    /* now scan through the address cache, looking for the source address to use */
                    nl_cache_foreach( g.addrCache, forEachAddrObj, wan );
                }
            }
        }
    }
}

int setup( int argc, char * argv[] )
{
    g.my.pid = getpid();

    /* basename() would be simpler, but its definition is way too vague about possible side-effects */
    g.my.name = strrchr( argv[0], '/' );
    if ( g.my.name++ == NULL ) {
        g.my.name = argv[0];
    }

    memset( &g.dp, 0 , sizeof(g.dp));
    g.dp.dp_type = NL_DUMP_DETAILS;
    g.dp.dp_ivar = NH_DUMP_FROM_DETAILS;
    g.dp.dp_fd   = stderr;
    g.dp.dp_dump_msgtype = 1;

    g.netlink.socket = nl_socket_alloc();
    if (g.netlink.socket != NULL) {
        nl_connect( g.netlink.socket, NETLINK_ROUTE );

        int err = rtnl_route_alloc_cache( g.netlink.socket, AF_UNSPEC, 0, &g.routeCache );
        if ( err < 0 ) {
            logDebug( "error: route cache: %d: %s\n", err, nl_geterror( err ));
        } else {
            err = rtnl_link_alloc_cache( g.netlink.socket, AF_UNSPEC, &g.linkCache );
            if ( err < 0 ) {
                logDebug( "error: link cache: %d: %s\n", err, nl_geterror(err) );
            } else {
                err = rtnl_addr_alloc_cache( g.netlink.socket, &g.addrCache );
                if ( err < 0 ) {
                    logDebug( "error: source cache: %d: %s\n", err, nl_geterror(err) );
                } else {
                    /* forEachRouteObj() is where the majority of setup occurs */
                    nl_cache_foreach( g.routeCache, forEachRouteObj, NULL );
                }
            }
        }
    }

    return 0;
}

/*
 * ToDo: periodically refresh the WANroute objects, in case the routing table is changed by other
 *       processes, e.g. DHCP. If a link starts failing, it should trigger this immediately too,
 *       since the link itself may still be up, but we're still probing stale addresses.
 */
int mainLoop( void )
{
    if (g.wanList == NULL) {
        logError("%s: no default network routes found to monitor.\n", g.my.name);
        return -1;
    }
    tICMPpacket * packet = calloc(1, sizeof( tICMPpacket ) );
    if (packet == NULL ) {
        return -ENOMEM;
    }

    uSockAddr target;
    target.family = AF_INET;
    inet_pton( target.family, "8.8.8.8", &target.in.sin_addr );
    ssize_t rc;
    g.seq = 1;
    for (tWANroute * wan = g.wanList; wan != NULL; wan = wan->next )
    {
        logDebug ( "interface %s\n", wan->intf.name );
        for (int ttl = 1; ttl < 20; ttl++)
        {
            makeEchoRequest( packet, &wan->source, &target, ttl);

            struct timeval timeout = {2, 0}; // wait max 2 seconds for a reply

            rc = sendto( wan->intf.socketFD,
                         packet, packet->ip.tot_len, 0,
                         &target.common, sizeof(target) );

            if ( rc <= 0 ) {
                perror( location );
                break;
            } else {
                char sockAddrAsStr[256];
                sockAddrToStr( &target, sockAddrAsStr, sizeof(sockAddrAsStr) );
                logDebug( "ICMP 'Echo Request' to %s, seq = %d, ttl %d\n", sockAddrAsStr, g.seq, ttl );
            }

            fd_set read_set;
            memset( &read_set, 0, sizeof( read_set ) );
            FD_SET( wan->intf.socketFD, &read_set );

            // wait for a reply with a timeout
            rc = select( wan->intf.socketFD + 1, &read_set, NULL, NULL, &timeout );
            if ( rc == 0 ) {
                logDebug( "timeout: no response received\n" );
                continue;
            } else if ( rc < 0 ) {
                perror( location );
                break;
            }

            unsigned char data[2048];
            uSockAddr srcAddr;
            socklen_t srcAddrLen = sizeof( srcAddr );
            rc = recvfrom( wan->intf.socketFD,
                           data, sizeof( data ), 0,
                           &srcAddr.common, &srcAddrLen );
            if ( rc < 0 ) {
                perror( location );
                break;
            } else if ( rc < sizeof( struct icmphdr ) ) {
                logDebug( "Error: truncated ICMP response (only %ld bytes long)\n", rc );
                break;
            } else {
                const tICMPpacket * rcvdPkt = (tICMPpacket *) data;

                char sockAddrAsStr[256];
                sockAddrToStr( &srcAddr, sockAddrAsStr, sizeof(sockAddrAsStr) );

                int type = rcvdPkt->icmp.type;
                if (type == ICMP_TIME_EXCEEDED) {

                }
#if DEBUG
                const char * typeString = NULL;
                if (type < ICMP_MAXTYPE) {
                    typeString = icmpTypeAsString[type];
                }
                if (typeString == NULL) {
                    typeString = "<error>";
                }

                logDebug( "ICMP \'%s\' from %s, seq = %d, id=%d\n",
                          typeString,
                          sockAddrAsStr,
                          rcvdPkt->icmp.un.echo.sequence, rcvdPkt->icmp.un.echo.id );

                if (type == ICMP_ECHOREPLY && isSameAddr( &srcAddr, &target ))
                {
                    logDebug("reached target\n\n");
                    break;
                }
#endif
            }
        }
    }

    return 0;
}


int teardown( int exitCode )
{
    if ( g.netlink.socket != NULL ) {
        nl_socket_free( g.netlink.socket );
        g.netlink.socket = NULL;
    }
    return exitCode;
}

int main(int argc, char * argv[])
{
    int exitCode = setup( argc, argv );

    if ( exitCode == 0 )
    {
        exitCode = mainLoop();

        exitCode = teardown( exitCode );
    }
    exit( exitCode );
}
