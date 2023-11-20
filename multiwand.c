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


#define stringify(x) #x
#define tostring(x) stringify(x)
#define location __FILE__ ":" tostring(__LINE__)
#define logDebug( ... ) fprintf( stderr, location " " __VA_ARGS__ )

#define PACKED __attribute__((packed))
#define PACKED_STRUCT(...) struct __VA_ARGS__ PACKED

typedef struct {
    PACKED_STRUCT( iphdr ip );
    PACKED_STRUCT( icmphdr icmp );
    uint8_t * payload;
} tICMPpacket;

#include "multiwand.h"

typedef struct {
    struct nl_cache * routeCache;
    struct nl_cache * linkCache;
    struct nl_cache * addrCache;
    int               ifIndex;
    char *            ifName;
} tCallbackArg;

typedef struct sICMPsocket {
    struct sICMPsocket * next;
    int fd;
} tICMPSocket;

typedef struct {
    pid_t         pid;
    uint16_t      seq;
    tICMPSocket * socketList;
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

tICMPSocket * newICMPsocket(void)
{
    tICMPSocket * result = calloc(1, sizeof(tICMPSocket));
    if ( result == NULL ) {
        perror( location );
    } else {
        result->fd = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
        if ( result->fd >= 0 ) {
            logDebug( "socket fd = %d\n", result->fd );
            result->next = g.socketList;
            g.socketList = result;
        } else {
            perror( location " newICMPsocket");
            free( result );
            result = NULL;
        }
    }
    return result;
}

uint32_t convertIPaddr( const char * ipAddr )
{
    uint32_t result = 0;

    return result;
}

unsigned int headerChecksum( void * header, size_t length )
{
    register uint32_t sum = 0;
    uint16_t * word = (uint16_t *)header;

    // Sum up 2-byte values until none or only one byte left.
    while ( length > 1) {
        sum += *word++;
        length -= 2;
    }

    if (length > 0) {
        sum += *(uint8_t *)word;
    }

    // Fold 32-bit sum into 16 bits;
    // we lose information by doing this, increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // the checksum is actually the one's compliment of the calculation above.
    return ~sum;
}

void makeIPv4header( struct iphdr * iph, int protocol, int ttl, const char * srcIPaddr, const char * dstIPaddr )
{
    iph->version  = IPVERSION;
    iph->ihl      = 20 / 4;
    iph->tos      = 0;                        // default DHSC class
    iph->id       = htons(g.seq++);
    iph->frag_off = htons(IP_DF);    // don't fragment
    iph->ttl      = ttl;
    iph->protocol = protocol;
    iph->saddr    = convertIPaddr( srcIPaddr );
    iph->daddr    = convertIPaddr( dstIPaddr );

    iph->check = 0; // must be zero for the checksum calculation
    iph->check = headerChecksum( iph, sizeof( struct iphdr ) ); // populate header checksum

}

void makeEchoRequest( tICMPpacket * pkt, const char * srcIPaddr, const char * dstIPaddr )
{
    makeIPv4header( &pkt->ip, IPPROTO_ICMP, 64, srcIPaddr, dstIPaddr );

    // pkt->ip.tot_len  = 0;    // total packet length
    pkt->icmp.type = ICMP_ECHO;
    pkt->icmp.code = 0;
    //pkt->icmp.echo.id = 1234; //arbitrary id
}

void forEachAddrObj( struct nl_object * nlObj, void * arg )
{
    struct rtnl_addr * addrObj = (struct rtnl_addr *) nlObj;
    tCallbackArg * cbArg = arg;

    if ( rtnl_addr_get_ifindex( addrObj ) == cbArg->ifIndex )
    {
        nl_object_dump( nlObj, &g.dp);

        int family = rtnl_addr_get_family( addrObj );
        struct nl_addr * localAddr = rtnl_addr_get_local( addrObj );

        logDebug( "prefix length: %d bits\n", nl_addr_get_prefixlen( localAddr ));
        uint8_t * addr = nl_addr_get_binary_addr( localAddr );
        unsigned int len = nl_addr_get_len( localAddr );
        logDebug( "binary addr: " );
        dumpHex( addr, len );
        char ipAddr[1024];
        nl_addr2str( localAddr, ipAddr, sizeof(ipAddr) );

        logDebug( "%s addr: (%d) %s\n", cbArg->ifName, family, ipAddr );
    }
}

void forEachRouteObj( struct nl_object * nlObj, void * arg )
{
    char str[1024];
    tCallbackArg * cbArg = arg;

    struct rtnl_route * routeObj = (struct rtnl_route *) nlObj;

    const struct nl_addr * nlAddr = rtnl_route_get_dst( routeObj );
    if ( nl_addr_iszero( nlAddr ) )
    {
        struct rtnl_nexthop * nextHopObj = rtnl_route_nexthop_n( routeObj, 0);
        if ( nextHopObj != NULL ) {

            // nl_object_dump( nlObj, &dp );
            // rtnl_route_nh_dump( nextHopObj, &dp );

            cbArg->ifIndex = rtnl_route_nh_get_ifindex( nextHopObj );
            struct rtnl_link * linkObj = rtnl_link_get( cbArg->linkCache, cbArg->ifIndex);

            cbArg->ifName = rtnl_link_get_name ( linkObj );
            logDebug( "link name: %s\n", cbArg->ifName );

            uint32_t prio = rtnl_route_get_priority( routeObj );
            logDebug( "metric %d\n", prio );

            const struct nl_addr * gatewayAddrObj = rtnl_route_nh_get_gateway( nextHopObj );
            if ( gatewayAddrObj == NULL) {
                logDebug( "error: gatewayAddrObj is %p\n", gatewayAddrObj );
            } else {
                int family = nl_addr_get_family( gatewayAddrObj );
                nl_addr2str( gatewayAddrObj, str, sizeof(str));
                logDebug( "gateway: %s (%d)\n", str, family );
            }

            // nl_object_dump( (struct nl_object *) linkObj, &g.dp );

            nl_cache_foreach( cbArg->addrCache, forEachAddrObj, cbArg );
        }
    }
}



void ping_it( const char * destination )
{
    const tICMPSocket * sock = newICMPsocket();
    if (sock == NULL) {
        return;
    }

    struct sockaddr_in addr;
    memset( &addr, 0, sizeof addr );
    addr.sin_family = AF_INET;
    if ( inet_aton( destination, &addr.sin_addr ) == 0 ) {

        perror( location );
        logDebug( "\'%s\' isn't a valid IP address\n", destination );
        return;
    }


    ssize_t rc;
    unsigned int sequence = 1;
    do {
        unsigned char data[2048];
        struct timeval timeout = {3, 0}; //wait max 3 seconds for a reply
        fd_set read_set;
        socklen_t slen;
        struct icmphdr rcv_hdr;

#if 0
        icmp_hdr.un.echo.sequence = sequence;
        memcpy( data, &icmp_hdr, sizeof icmp_hdr );
        memcpy( data + sizeof icmp_hdr, "hello", 5 ); //icmp payload

        rc = sendto( sock->fd, data, sizeof icmp_hdr + 5,
                             0, (struct sockaddr *) &addr, sizeof(addr));
        if ( rc <= 0 ) {
            perror( location );
            break;
        } else logDebug( "Sent ICMP\n" );
#endif

        memset( &read_set, 0, sizeof read_set );
        FD_SET( sock->fd, &read_set );

        // wait for a reply with a timeout
        rc = select( sock->fd + 1, &read_set, NULL, NULL, &timeout );
        if ( rc == 0 ) {
            logDebug( "no response\n" );
            continue;
        } else if ( rc < 0 ) {
            perror( location );
            break;
        }

        // we don't care about the sender address in this example..
        slen = 0;
        rc = recvfrom( sock->fd, data, sizeof data, 0, NULL, &slen );
        if ( rc <= 0 ) {
            perror( location );
            break;
        } else if ( rc < sizeof rcv_hdr ) {
            logDebug( "Error: truncated ICMP response, only %ld bytes long\n", rc );
            break;
        }

        memcpy( &rcv_hdr, data, sizeof rcv_hdr );

        if ( rcv_hdr.type == ICMP_ECHOREPLY ) {
#if 0
            logDebug( "ICMP Reply, id=0x%x, sequence =  %d\n",
                    icmp_hdr.un.echo.id, icmp_hdr.un.echo.sequence );
#endif
        } else {
            logDebug( "unexpected ICMP packet (type 0x%x)\n", rcv_hdr.type );
        }
    } while ( sequence++ < 100 );
}


int main(int argc, char * argv[])
{
    tCallbackArg cbArg;

    g.pid = getpid();

    memset( &g.dp, 0 , sizeof(g.dp));
    g.dp.dp_type = NL_DUMP_DETAILS;
    g.dp.dp_ivar = NH_DUMP_FROM_DETAILS;
    g.dp.dp_fd   = stderr;
    g.dp.dp_dump_msgtype = 1;

    struct nl_sock * nlSocket = nl_socket_alloc();
    if (nlSocket != NULL) {
        nl_connect( nlSocket, NETLINK_ROUTE );

        int err = rtnl_route_alloc_cache( nlSocket, AF_UNSPEC, 0, &cbArg.routeCache );
        if ( err < 0 ) {
            logDebug( "error: route cache: %d: %s\n", err, nl_geterror( err ));
        } else {
            err = rtnl_link_alloc_cache( nlSocket, AF_UNSPEC, &cbArg.linkCache );
            if ( err < 0 ) {
                logDebug( "error: link cache: %d: %s\n", err, nl_geterror(err) );
            } else {
                err = rtnl_addr_alloc_cache( nlSocket, &cbArg.addrCache );
                if ( err < 0 ) {
                    logDebug( "error: addr cache: %d: %s\n", err, nl_geterror(err) );
                } else {
                    nl_cache_foreach( cbArg.routeCache, forEachRouteObj, &cbArg );
                }
            }
        }
    }


    ping_it( "8.8.8.8" );

#if 0
    pingobj_t * pingObj[10];
    for (unsigned int i = 0; i < 10; i++ )
    {
        int ttl = i + 1;
        pingObj[i] = ping_construct();
        if ( pingObj[i] != NULL ) {
            ping_setopt( pingObj[i], PING_OPT_TTL, &ttl);
            ping_host_add( pingObj[i], "8.8.8.8");
            int err = ping_send( pingObj[i] );
            logDebug( "ping send %d. %s\n", err, ping_get_error( pingObj[i] ) );
            pingobj_iter_t * pingIter = ping_iterator_get ( pingObj[i] );
            char buffer[1024];
            size_t length = sizeof(buffer);
            ping_iterator_get_info( pingIter, PING_INFO_ADDRESS, buffer, &length );
            logDebug( "%2d: address: %s\n", i, buffer);
        }
    }
#endif

    exit( 0 );
}
