/*
    Created by Paul Chambers on 11/5/23.
*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <memory.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

/* /usr/include/libnl3 */
#include <libnl3/netlink/addr.h>
#include <libnl3/netlink/cache.h>
#include <libnl3/netlink/errno.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/object.h>
#include <libnl3/netlink/route/addr.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/route.h>
#include <libnl3/netlink/socket.h>

#include "multiwand.h"

typedef struct {
    struct iphdr ip;
    struct icmphdr icmp;
    uint8_t body[384];
} tICMPpacket;

typedef struct sICMPsocket {
    struct sICMPsocket * next;
    ;
} tICMPSocket;

typedef struct sWANroute {
    struct sWANroute * next;

    struct {
        int             socketFD;
        int             index;
        const char *    name;
    } intf;
    struct {
        in_addr_t       ipv4Addr;
        const char *    address;
    } gateway;
    struct {
        in_addr_t       ipv4Addr;
        in_addr_t       ipv4Mask;
        const char *    address;
        int             prefix;
    } source;

    uint32_t    metric;
} tWANroute;

typedef struct {
    pid_t           pid;
    uint16_t        seq;
    tICMPSocket *   socketList;
    tWANroute *     wanList;

    struct nl_cache * routeCache;
    struct nl_cache * linkCache;
    struct nl_cache * addrCache;

    // libnl3 configuration for dumping structures
    struct nl_dump_params dp;
} tGlobals;

tGlobals g;

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

int newICMPsocket( const char * interface )
{
    int result = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    if ( result < 0 ) {
        perror( location " newICMPsocket" );
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
        } else logDebug( "socket fd for interface %s is %d\n", interface, result );
    }

    return result;
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

size_t makeIPv4header( struct iphdr * iph, int protocol, int ttl, in_addr_t srcIPaddr, in_addr_t dstIPaddr )
{
    const int length = 20;
    iph->version  = IPVERSION;
    iph->ihl      = length / 4;
    iph->tos      = 0;                        // default QOS class
    iph->id       = htons(g.seq++);  // monotonically-increasing sequence ID
    iph->frag_off = htons(IP_DF);    // don't fragment
    iph->ttl      = ttl;
    iph->protocol = protocol;
    iph->saddr    = htonl(srcIPaddr);
    iph->daddr    = htonl(dstIPaddr);

    // checksum must be zero when the checksum calculation is done, which
    // has to wait until the packet has been built and the length is known.
    iph->check = 0;

    return length;
}

size_t makeICMPpacket( struct icmphdr * icmpPkt, uint8_t type, uint8_t code, void * body, size_t bodyLen )
{
    size_t length = sizeof( struct icmphdr ) + bodyLen;
    icmpPkt->type       = type;
    icmpPkt->code       = code;
    icmpPkt->checksum   = 0;
    icmpPkt->un.echo.id = g.pid;
    icmpPkt->un.echo.sequence = g.seq;
    memcpy(((uint8_t *)icmpPkt) + sizeof(struct icmphdr), body, bodyLen);

    icmpPkt->checksum = headerChecksum( icmpPkt, length );
    return length;
}

void makeEchoRequest( tICMPpacket * pkt, in_addr_t srcIPaddr, in_addr_t dstIPaddr )
{
    const char * payload = "connectivity check";

    size_t ipHdrLen = makeIPv4header( &pkt->ip, IPPROTO_ICMP, 64, srcIPaddr, dstIPaddr );
    size_t icmpHdrLen = makeICMPpacket( &pkt->icmp, ICMP_ECHO, 0, (void *)payload, strlen(payload) + 1 );
    pkt->ip.tot_len = ipHdrLen + icmpHdrLen;
    pkt->ip.check = headerChecksum( pkt, pkt->ip.tot_len );
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

    logDebug( "addr in memory: " );
    dumpHex( addr, len );

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
    int bitWidth = nl_addr_get_len( addrObj ) * 8;

    in_addr_t mask = ~((1 << (bitWidth - prefix)) - 1);
    logDebug( "mask 0x%08x\n", mask );
    return mask;
}

const char * getIPv4string( const struct nl_addr * addrObj )
{
    char ipAddr[1024];
    nl_addr2str( addrObj, ipAddr, sizeof(ipAddr) );
    logDebug( "as string: %s\n", ipAddr );

    return strdup(ipAddr);
}

void forEachAddrObj( struct nl_object * nlObj, void * arg )
{
    // we know it's an address object, since this callback is only ever used with the address cache
    struct rtnl_addr * addrObj = (struct rtnl_addr *) nlObj;
    tWANroute * wan = arg;

    if ( rtnl_addr_get_ifindex( addrObj ) == wan->intf.index )
    {
        // nl_object_dump( nlObj, &g.dp);

        if ( rtnl_addr_get_family( addrObj ) == AF_INET
          && wan->source.ipv4Addr == 0 ) {

            struct nl_addr * localAddr = rtnl_addr_get_local( addrObj );
            wan->source.ipv4Addr = getIPv4Addr( localAddr );
            wan->source.ipv4Mask = getIPv4Mask( localAddr );
            wan->source.address  = getIPv4string( localAddr );

            in_addr_t subnet = wan->source.ipv4Addr & wan->source.ipv4Mask;


            if ( (wan->gateway.ipv4Addr & wan->source.ipv4Mask) != subnet )
            {
                /* this isn't the source address to use to reach the gateway */
                logDebug( "subnet mismatch\n" );
                wan->source.ipv4Addr = 0;
                wan->source.ipv4Mask = 0;
            }


            fprintf( stderr, "\n" );
        }
    }
}

void forEachRouteObj( struct nl_object * nlObj, void * arg )
{
    char str[1024];

    // we know it's a route object, since this callback is only ever used with the route cache
    struct rtnl_route * routeObj = (struct rtnl_route *) nlObj;

    const struct nl_addr * nlAddr = rtnl_route_get_dst( routeObj );
    if ( nl_addr_iszero( nlAddr ) )
    {
        struct rtnl_nexthop * nextHopObj = rtnl_route_nexthop_n( routeObj, 0 );
        if ( nextHopObj != NULL ) {

            // nl_object_dump( nlObj, &dp );
            // rtnl_route_nh_dump( nextHopObj, &dp );

            tWANroute * wan = allocWANroute();
            if (wan != NULL) {

                wan->intf.index = rtnl_route_nh_get_ifindex( nextHopObj );
                struct rtnl_link * linkObj = rtnl_link_get( g.linkCache, wan->intf.index);

                wan->intf.name = strdup( rtnl_link_get_name ( linkObj ) );
                logDebug( "link name: %s\n", wan->intf.name );

                wan->intf.socketFD = newICMPsocket( wan->intf.name );

                wan->metric = rtnl_route_get_priority( routeObj );
                logDebug( "metric %d\n", wan->metric );

                const struct nl_addr * gatewayAddrObj = rtnl_route_nh_get_gateway( nextHopObj );
                if ( gatewayAddrObj == NULL) {
                    logDebug( "error: gatewayAddrObj is %p\n", gatewayAddrObj );
                } else {
                    if ( nl_addr_get_family( gatewayAddrObj ) == AF_INET ) {
                        wan->gateway.ipv4Addr = getIPv4Addr( gatewayAddrObj );

                        nl_addr2str( gatewayAddrObj, str, sizeof(str));
                        wan->gateway.address = strdup( str );
                        logDebug( "gateway: %s\n", wan->gateway.address );
                    }
                }

                // nl_object_dump( (struct nl_object *) linkObj, &g.dp );

                nl_cache_foreach( g.addrCache, forEachAddrObj, wan );
            }
        }
    }
}


void ping_it( void )
{
    tICMPpacket * packet = calloc(1, sizeof( tICMPSocket ) );
    if (packet == NULL ) {
        return;
    }
    makeEchoRequest( packet, g.wanList->source.ipv4Addr, g.wanList->gateway.ipv4Addr);

    ssize_t rc;
    unsigned int sequence = 1;
    do {
        struct timeval timeout = {3, 0}; //wait max 3 seconds for a reply

        tWANroute * wan = g.wanList;
        struct sockaddr dest;
        dest.sa_family = AF_INET;
        memcpy( dest.sa_data, &wan->gateway.ipv4Addr, sizeof( in_addr_t ) );
        rc = sendto( wan->intf.socketFD, packet, packet->ip.tot_len, 0, &dest, sizeof(dest) );
        if ( rc <= 0 ) {
            perror( location );
            break;
        } else logDebug( "Sent ICMP\n" );


        fd_set read_set;
        memset( &read_set, 0, sizeof read_set );
        FD_SET( wan->intf.socketFD, &read_set );

        // wait for a reply with a timeout
        rc = select( wan->intf.socketFD + 1, &read_set, NULL, NULL, &timeout );
        if ( rc == 0 ) {
            logDebug( "no response\n" );
            continue;
        } else if ( rc < 0 ) {
            perror( location );
            break;
        }

        // we don't care about the sender address in this example..
        socklen_t slen = 0;
        unsigned char data[2048];
        rc = recvfrom( wan->intf.socketFD, data, sizeof data, 0, NULL, &slen );
        if ( rc <= 0 ) {
            perror( location );
            break;
        } else if ( rc < sizeof( struct icmphdr ) ) {
            logDebug( "Error: truncated ICMP response, only %ld bytes long\n", rc );
            break;
        }

        const tICMPpacket * rcvdPkt = (tICMPpacket *) data;

        if ( rcvdPkt->icmp.type == ICMP_ECHOREPLY ) {
            logDebug( "ICMP Reply, id=0x%x, sequence =  %d\n",
                      rcvdPkt->icmp.un.echo.id, rcvdPkt->icmp.un.echo.sequence );
        } else {
            logDebug( "unexpected ICMP packet (type 0x%x)\n", rcvdPkt->icmp.type );
        }
    } while ( sequence++ < 20 );
}


int main(int argc, char * argv[])
{
    g.pid = getpid();

    memset( &g.dp, 0 , sizeof(g.dp));
    g.dp.dp_type = NL_DUMP_DETAILS;
    g.dp.dp_ivar = NH_DUMP_FROM_DETAILS;
    g.dp.dp_fd   = stderr;
    g.dp.dp_dump_msgtype = 1;

    struct nl_sock * nlSocket = nl_socket_alloc();
    if (nlSocket != NULL) {
        nl_connect( nlSocket, NETLINK_ROUTE );

        int err = rtnl_route_alloc_cache( nlSocket, AF_UNSPEC, 0, &g.routeCache );
        if ( err < 0 ) {
            logDebug( "error: route cache: %d: %s\n", err, nl_geterror( err ));
        } else {
            err = rtnl_link_alloc_cache( nlSocket, AF_UNSPEC, &g.linkCache );
            if ( err < 0 ) {
                logDebug( "error: link cache: %d: %s\n", err, nl_geterror(err) );
            } else {
                err = rtnl_addr_alloc_cache( nlSocket, &g.addrCache );
                if ( err < 0 ) {
                    logDebug( "error: addr cache: %d: %s\n", err, nl_geterror(err) );
                } else {
                    nl_cache_foreach( g.routeCache, forEachRouteObj, NULL );
                }
            }
        }
    }

    ping_it();

    exit( 0 );
}
