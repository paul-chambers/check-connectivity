/*
    Created by Paul Chambers on 11/5/23.
*/

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <memory.h>

/* generic Linux network stuff */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
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


typedef union {
    sa_family_t family;
    struct sockaddr common;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr_nl nl;
} uSockAddr;

typedef union {
    struct {
        struct iphdr hdr;
        struct icmphdr icmp;
        union {
            struct iphdr timeExceeded;
        } ext;
    } v4;
    struct {
        struct ip6_hdr hdr;
        union {
            struct icmphdr hdr;
        } icmp;
    } v6;
    byte * raw;
} tRawPacket;

typedef struct sV4List {
    struct sV4List *    next;
    struct sockaddr_in  addr;
} tV4Entry;

typedef struct sV6List {
    struct sV6List *    next;
    struct sockaddr_in6 addr;
} tV6Entry;

typedef struct sAddrList {
    tV4Entry * v4;
    tV6Entry * v6;
} tAddrList;

typedef struct sWANroute {
    struct sWANroute *  next;

    sa_family_t         family;
    struct nl_addr *    source;
    struct nl_addr *    gateway;

    uint32_t    metric;
    int         scope;
} tWANroute;

typedef struct sWANinterface {
    struct sWANinterface * next;

    int           socketFD;
    int           index;
    const char *  name;

    tAddrList     source;

    tWANroute *   wanRoutes;
} tWANinterface;

typedef struct {
    struct {
        pid_t           pid;
        const char *    name;
    } my;

    struct {
        struct nl_sock * socket;
    } netlink;

    uint16_t            seq;
    tRawPacket *       packetList;
    tWANinterface *     wanList;

    struct nl_cache *   addrCache;
    struct nl_cache *   linkCache;
    struct nl_cache *   routeCache;

    // libnl3 configuration for dumping structures
    struct nl_dump_params dp;
} tGlobals;

tGlobals g;

/************************************************************************************/

void dumpHex( void *ptr, size_t len )
{
    const char *sep;
    unsigned int offset = 0;

    if ( ptr == NULL || len == 0 ) return;
    do {
        switch ( offset % 16 ) {
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
        fprintf( stderr, "%02x%s", ((uint8_t *) ptr)[offset], sep );
        offset++;
        len--;
    } while ( len > 0 );

    fprintf( stderr, "\n" );
}

void dumpDec( void *ptr, size_t len )
{
    const char *sep;
    unsigned int offset = 0;

    if ( ptr == NULL || len == 0 ) return;
    do {
        switch ( offset % 16 ) {
        case 15:
            sep = (len > 1) ? "\n" : "";
            break;

        default:
            sep = " ";
            break;
        }
        fprintf( stderr, "%d%s", ((uint8_t *) ptr)[offset], sep );
        offset++;
        len--;
    } while ( len > 0 );

    fprintf( stderr, "\n" );
}

void ipv6ToStr( const byte *p, char *str, size_t strSize )
{
    uint16_t word;
    bool doneDouble = false;
    int size = snprintf( str, strSize, "IPv6: " );
    str += size;
    strSize -= size;

    for ( int i = 0; i < 8 && strSize > 5; i++ ) {
        word = (p[0] << 8) | p[1];
        p += 2;

        if ( word == 0 && doneDouble == false ) {
            *str++ = ':';
            --strSize;
            while ( p[0] == 0 && p[1] == 0 ) {
                p += 2;
                i++;
            }
            doneDouble = true;
        } else {
            size = snprintf( str, strSize, "%x", word );
            str += size;
            strSize -= size;
            if ( i < 7 ) {
                *str++ = ':';
                --strSize;
            }
        }
    }
}

/**
 * Populate a string with a representation of the sockaddr provided.
 * Only handles IPv4 and IPv6 for now.
 */
char *sockAddrToStr( struct sockaddr * sockAddr, char *dest, size_t destSize )
{
    byte *p;

    switch ( sockAddr->sa_family ) {
    case AF_UNSPEC:
        snprintf( dest, destSize,
                  "<address family not specified>" );
        break;

    case AF_INET:
        p = (byte *) &((struct sockaddr_in *)sockAddr)->sin_addr;
        snprintf( dest, destSize,
                  "IPv4: %d.%d.%d.%d",
                  p[0], p[1], p[2], p[3] );
        break;

    case AF_INET6:
        ipv6ToStr((byte *) &((struct sockaddr_in6 *)sockAddr)->sin6_addr, dest, destSize );
        break;

    default:
        snprintf( dest, destSize,
                  "<unsupported socket address family (%s)>",
                  familyAsString[sockAddr->sa_family] );
        break;
    }
    return dest;
}

/**
 * Generic test to see if two socket addresses are the same
 */
bool isSameAddr( uSockAddr *a, uSockAddr *b )
{
    char aAsStr[128];
    char bAsStr[128];
    sockAddrToStr( &a->common, aAsStr, sizeof(aAsStr));
    sockAddrToStr( &b->common, bAsStr, sizeof(bAsStr));
    logDebug( "a %s, b%s\n", aAsStr, bAsStr);

    if ( a->family != b->family ) {
        return false;
    } else {
        byte *pa;
        byte *pb;
        size_t len;
        switch ( a->family ) {
        case AF_INET:
            pa = (byte *) &a->in.sin_addr;
            pb = (byte *) &b->in.sin_addr;
            len = 4;
            break;

        case AF_INET6:
            pa = (byte *) &a->in6.sin6_addr;
            pb = (byte *) &b->in6.sin6_addr;
            len = 16;
            break;

        default:
            return false;
        }

        return memcmp( pa, pb, len ) == 0;
    }
}

/* generic test to see if two socket addresses are on the same subnet */
bool isSameSubnet( uSockAddr *a, uSockAddr *b, unsigned int maskBitLen )
{
    if ( a->family != b->family ) {
        logDebug( "family doesn't match (%d,%d)\n", a->family, b->family );
    } else {
        byte *pa;
        byte *pb;
        switch ( a->family ) {
        case AF_INET:
            pa = (byte *) &a->in.sin_addr;
            pb = (byte *) &b->in.sin_addr;

            for ( int len = (int) maskBitLen; len > 0; len -= 8 ) {
                byte mask = ~(0xff >> len);
                // logDebug( "0x%02x 0x%02x 0x%02x %d\n", *pa, *pb, mask, len);
                if ((*pa++ & mask) != (*pb++ & mask)) {
                    return false;
                }
            }
            return true;

        case AF_INET6:
            // pa = (byte *)&a->in6.sin6_addr;
            // pb = (byte *)&b->in6.sin6_addr;
            return true;
        }
    }
    return false;
}

/*
 * RFC 1071 checksum calculation
 */
unsigned int headerChecksum( void *header, size_t length )
{
    register uint16_t *word = (uint16_t *) header;
    register uint32_t sum = 0;

    // Sum adjacent 16 bit words
    while ( length > 1 ) {
        sum += *word++;
        length -= 2;
    }

    // if length was odd, there's one more byte to add. Assume upper 8 bits are zero.
    if ( length > 0 ) {
        sum += *(uint8_t *) word;
    }

    // deferred carry processing: dd the carry bits that overflowed into the top
    // 16 bits back into the lower 16 bits. Repeat this while there are still
    // carry bits set in the upper 16 bits.
    while ( sum >> 16 ) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // the checksum is actually the one's compliment of the calculation above.
    return ~sum;
}

void addSockAddrToList( struct sockaddr * addr, tAddrList * addrList )
{
    switch ( addr->sa_family ) {
    case AF_INET:
        {
            tV4Entry * v4Entry = calloc( 1, sizeof( tV4Entry ));
            memcpy( &v4Entry->addr, addr, sizeof(v4Entry->addr));
            v4Entry->next = addrList->v4;
            addrList->v4 = v4Entry;
        }
        break;

    case AF_INET6:
        {
            tV6Entry * v6Entry = calloc( 1, sizeof( tV6Entry ));
            memcpy( &v6Entry->addr, addr, sizeof(v6Entry->addr));
            v6Entry->next = addrList->v6;
            addrList->v6 = v6Entry;
        }
        break;

    default:
        logDebug( "unsupported address family (%s)\n", familyAsString[addr->sa_family] );
        break;
    }
}

/************************************************************************************/

int newICMPsocket( const char *interface )
{
    int result = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    if ( result < 0 ) {
        if ( errno == EPERM ) {
            logError( "%s needs to create a raw network socket, but doesn't have permission to do so.\n"
                      "Please either run %s as root, or grant it the CAP_NET_RAW capability (preferred).\n",
                      g.my.name, g.my.name );
            return -errno;
        } else { perror( location " newICMPsocket" ); }
    } else {
        int on = 1;
        if ( setsockopt( result,
                         IPPROTO_IP, IP_HDRINCL,
                         &on, sizeof(on)) < 0 ) {
            perror( location );
        } else if ( setsockopt( result,
                                SOL_SOCKET, SO_BINDTODEVICE,
                                interface, strlen( interface )) < 0 ) {
            perror( location );
        } //else logDebug( "socket fd for interface %s is %d\n", interface, result );
    }

    return result;
}


size_t makeIPv4header( struct iphdr *iph, int protocol, int ttl,
                       struct sockaddr_in * srcAddr,
                       struct sockaddr_in * dstAddr )
{
    int length = -1;
    length = 20;
    iph->version = IPVERSION;
    iph->ihl = length / 4;
    iph->tos = 0;                        // default QOS class
    iph->id = htons(  (0x06 << 8) | (g.seq++ & 0xFF) );  // monotonically-increasing sequence ID
    iph->frag_off = htons( IP_DF );    // don't fragment
    iph->ttl = ttl;
    iph->protocol = protocol;
    if ( srcAddr != NULL && srcAddr->sin_family == AF_INET ) {
        memcpy( &iph->saddr, &srcAddr->sin_addr, sizeof(iph->saddr));
    }
    if ( dstAddr != NULL && dstAddr->sin_family == AF_INET ) {
        memcpy( &iph->daddr, &dstAddr->sin_addr, sizeof(iph->daddr));
    }
    // checksum field must be zero when the checksum calculation is done,
    // We can't calculate the checksum until the rest of the packet has been built and the length is known.
    iph->check = 0;

    return length;
}

size_t makeICMPv4packet( struct icmphdr *icmpHdr, uint8_t type, uint8_t code, void *body, size_t bodyLen )
{
    size_t length = sizeof( struct icmphdr ) + bodyLen;
    icmpHdr->type = type;
    icmpHdr->code = code;
    icmpHdr->checksum = 0;
    icmpHdr->un.echo.id = g.my.pid;
    icmpHdr->un.echo.sequence = g.seq;
    memcpy( ((uint8_t *) icmpHdr) + sizeof( struct icmphdr ), body, bodyLen );

    icmpHdr->checksum = headerChecksum( icmpHdr, length );
    return length;
}

void makeEchoRequestV4( tRawPacket *pkt, struct sockaddr_in * srcAddr, struct sockaddr_in * dstAddr, int ttl )
{
    const char *payload = "connectivity check";

    size_t ipHdrLen = makeIPv4header( &pkt->v4.hdr,
                                      IPPROTO_ICMP, ttl, srcAddr, dstAddr );
    size_t icmpHdrLen = makeICMPv4packet( &pkt->v4.icmp,
                                          ICMP_ECHO, 0,
                                          (void *) payload, strlen( payload ) + 1 );
    pkt->v4.hdr.tot_len = ipHdrLen + icmpHdrLen;
    pkt->v4.hdr.check = headerChecksum( pkt, pkt->v4.hdr.tot_len );
}

#if 0
tWANinterface * getWANinterface( unsigned int intfIndex, const char *intfName )
{
    tWANinterface *result = NULL;
    for ( result = g.wanList; result != NULL; result = result->next ) {
        if ( result->index == intfIndex ) {
            return result;
        }
    }

    /* only reach this point if we con't already have a WANinterface
     * object for this intfIndex. So construct one. */
    result = calloc( 1, sizeof( tWANinterface ));
    if ( result != NULL) {
        result->socketFD = newICMPsocket( intfName );
        if ( result->socketFD <= 0 ) {
            /* if we can't open a raw ICMP socket, can't do anything useful... */
            logError( "unable to open raw socket for interface %s", intfName );
            free( result );
            result = NULL;
        } else {
            logDebug( "---- link name: %s (%d)\n", intfName, intfIndex );
            result->index = intfIndex;
            result->name = strdup( intfName );

            result->next = g.wanList;
            g.wanList = result;
        }
    }

    return result;
}
#endif

/* look for addresses associated with the given tWANinterface object passed in arg */
void forEachAddrObj( struct nl_object *nlObj, void *arg )
{
    // we know it's an address object, since this callback is only ever used with the address cache
    struct rtnl_addr * addrObj = (struct rtnl_addr *) nlObj;


    for ( tWANinterface * wan = g.wanList; wan != NULL; wan = wan->next ) {
        /* this address object is associated with the interface of interest */
        if ( rtnl_addr_get_ifindex( addrObj ) == wan->index ) {

#ifdef DEBUG
            int intfIndex = rtnl_addr_get_ifindex( addrObj );
            char intfName[128];
            rtnl_link_i2name( g.linkCache, intfIndex, intfName, sizeof(intfName) );
            logDebug( "---- Address: %s\n", intfName );
            // nl_object_dump( nlObj, &g.dp);
#endif

            struct nl_addr * sourceAddr = rtnl_addr_get_local( addrObj );
            struct sockaddr srcAddr;
            socklen_t srcLen = sizeof(srcAddr);
            nl_addr_fill_sockaddr( sourceAddr, &srcAddr, &srcLen );
            addSockAddrToList( &srcAddr, &wan->source );

#ifdef DEBUG
            char sourceAsStr[128];
            nl_addr2str( sourceAddr, sourceAsStr, sizeof(sourceAsStr));

            int scope = rtnl_addr_get_scope( addrObj );
            char scopeAsStr[128];
            rtnl_scope2str( scope, scopeAsStr, sizeof(scopeAsStr));

            unsigned int flags = rtnl_addr_get_flags( addrObj );
            char flagsAsStr[256];
            rtnl_addr_flags2str( flags, flagsAsStr, sizeof( flagsAsStr ));

            logDebug( "%s source: %s scope: %s flags: %s\n", wan->name, sourceAsStr, scopeAsStr, flagsAsStr );
#endif
            for ( tWANroute * route = wan->wanRoutes; route != NULL; route = route->next ) {
#ifdef DEBUG
                char gatewayAsStr[256];
                nl_addr2str( route->gateway, gatewayAsStr, sizeof(gatewayAsStr));
                const char * match = "does not match";
                if ( nl_addr_cmp_prefix( sourceAddr, route->gateway ) == 0 )
                {
                    match = "matches";
                }
                logDebug( " - %s %s gateway: %s\n", match, wan->name, gatewayAsStr );
#endif
            }
            break;
        }
    }


#if 0

        tWANinterface * route = NULL;
        switch ( nl_addr_get_family( sourceAddr))
        {
        case AF_INET:
            route = &wan->route.v4;
            break;

        case AF_INET6:
            route = &wan->route.v6;
            break;
        }
        if ( route->gateway != NULL && nl_addr_cmp_prefix( route->gateway, sourceAddr) == 0 )
        {
            /* remember the interface source address */
            route->source = nl_addr_clone( sourceAddr );
        }

        uSockAddr sourceAddr;
        socklen_t sourceLen = sizeof( sourceAddr );
        nl_addr_fill_sockaddr( sourceAddr, &sourceAddr.common, &sourceLen);


        int prefixLen = nl_addr_get_prefixlen( sourceAddr );
        logDebug("prefix len: %d\n", prefixLen );

        switch( nl_addr_get_family( sourceAddr ) )
        {
        case AF_INET:
            /* If this IPv4 source address isn't in the same subnet as the gateway address, ignore it.
             * This should not be common, but may occur if there are multiple IPv4 addresses associated
             * with the same interface (i.e. it is 'multi-homed') */
            if ( isSameSubnet( &sourceAddr,
                               &wan->ip.v4.gateway,
                               prefixLen))
            {
                memcpy( &wan->ip.v4.source, &sourceAddr, sourceLen );
            } else {
                /* This source address can't reach the gateway. So keep looking. */
                logDebug( "not in same subnet as gateway - ignored\n" );
            }
            break;

        case AF_INET6:
            memcpy( &wan->ip.v6.source, &sourceAddr, sourceLen );
            break;

        default:
            logError( "family of source address is not supported - ignored" );
            break;
        }
#endif
}

tWANinterface * getInterface( int intfIndex )
{
    tWANinterface * interface;

    for ( interface = g.wanList; interface != NULL; interface = interface->next ) {
        if ( interface->index == intfIndex ) {
            /* we found an existing tWANinterface */
            break;
        }
    }
    if ( interface == NULL) {
        logDebug( "create a new interface for index %d\n", intfIndex );
        /* we didn't find an existing matching tWANinterface for this intfIndex, so construct one. */
        interface = calloc( 1, sizeof( tWANinterface ));
        if ( interface == NULL) {
            goto error;
        }

        struct rtnl_link * linkObj = rtnl_link_get( g.linkCache, intfIndex );
        const char *      intfName = rtnl_link_get_name( linkObj );
        if ( intfName == NULL) {
            free( interface );
            interface = NULL;
            goto error;
        }

        interface->socketFD = newICMPsocket( intfName );
        if ( interface->socketFD <= 0 ) {
            /* if we can't open a raw ICMP socket, can't do anything useful... */
            logError( "unable to open raw socket for interface %s\n", intfName );
            free( interface );
            interface = NULL;
            goto error;
        } else {
            logDebug( "link name: %s (%d)\n", intfName, intfIndex );
            interface->index = intfIndex;
            interface->name = strdup( intfName );

            interface->next = g.wanList;
            g.wanList = interface;
        }
    }
error:
    return interface;
}

void forEachNexthopObj( struct rtnl_nexthop * nextHopObj, void * arg )
{
    logDebug("---- NextHop\n");
    rtnl_route_nh_dump( nextHopObj, &g.dp );
    fputc('\n', stderr);

    struct rtnl_route * routeObj = (struct rtnl_route *)arg;

    struct nl_addr * gatewayAddr = rtnl_route_nh_get_gateway( nextHopObj );

    if ( gatewayAddr == NULL) {
        // logError( "gateway is undefined\n" );
        return;
    }

    int intfIndex = rtnl_route_nh_get_ifindex( nextHopObj );

    tWANinterface * interface = getInterface( intfIndex );
    if (interface == NULL) {
        logDebug( "couldn't find interface for index %d\n", intfIndex );
        return;
    }

    /* at this point, we have a populated tWANinterface, so add a route to wanRoutes */
    tWANroute * route = calloc(1, sizeof( tWANroute ));
    if ( route != NULL )
    {
        route->gateway  = nl_addr_clone( gatewayAddr );
        /* API calls it 'priority', CLI calls it 'metric'. Not confusing at all... */
        route->metric   = rtnl_route_get_priority( routeObj );

#ifdef DEBUG
        char gatewayAddrAsStr[128];
        nl_addr2str( gatewayAddr, gatewayAddrAsStr, sizeof(gatewayAddrAsStr));
        char scopeAsStr[128];
        rtnl_scope2str( route->scope, scopeAsStr, sizeof(scopeAsStr));
        logDebug( " - via: %s %s scope: %s metric: %d\n",
                  interface->name, gatewayAddrAsStr, scopeAsStr, route->metric );
#endif

        /* add route to the wanRoute list of the interface */
        route->next = interface->wanRoutes;
        interface->wanRoutes = route;
    }
}

void forEachRouteObj( struct nl_object * nlObj, void * arg )
{
    // we know it's a route object, since this callback is only ever used with the route cache
    struct rtnl_route * routeObj = (struct rtnl_route *) nlObj;

    const struct nl_addr * dstAddr = rtnl_route_get_dst( routeObj );

    /* ignore it if it isn't a default route */

    if ( nl_addr_iszero( dstAddr ) ) {
#ifdef DEBUG
        fprintf(stderr,"\n");
        logDebug("-- Route\n");
#endif
        nl_object_dump( nlObj, &g.dp );
        rtnl_route_foreach_nexthop( routeObj, forEachNexthopObj, routeObj );
    }
}

int probeRoutes( void )
{
    int err;
    err = rtnl_addr_alloc_cache( g.netlink.socket, &g.addrCache );
    if ( err < 0 ) {
        logDebug( "error: source cache: %d: %s\n", err, nl_geterror( err ));
        return -err;
    }

    err = rtnl_link_alloc_cache( g.netlink.socket, AF_UNSPEC, &g.linkCache );
    if ( err < 0 ) {
        logDebug( "error: link cache: %d: %s\n", err, nl_geterror( err ));
        return -err;
    }

    err = rtnl_route_alloc_cache( g.netlink.socket, AF_UNSPEC, 0, &g.routeCache );
    if ( err < 0 ) {
        logDebug( "error: route cache: %d: %s\n", err, nl_geterror( err ));
        return -err;
    }

    /* callbacks are where the majority of setup occurs */
    nl_cache_foreach( g.routeCache, forEachRouteObj, NULL);

    if ( g.wanList != NULL) {
#ifdef DEBUG
        fprintf(stderr, "\n");
        logDebug( "-- Addresses\n" );
#endif
        nl_cache_foreach( g.addrCache, forEachAddrObj, NULL);
    }
    return 0;
}

/*
 * ToDo: periodically refresh the WANinterface objects, in case the routing table is changed by other
 *       processes, e.g. DHCP. If a link starts failing, it should trigger this immediately too,
 *       since the link itself may still be up, but we're still probing stale addresses.
 */
struct {
    const char * name;
    const char * host;
    tAddrList    addresses;
} targets[] = {
        {"Google Public DNS", "dns.google"      },
        {"Cloudflare DNS",    "one.one.one.one" },
        {"OpenDNS",           "dns.opendns.com" },
        {"NextDNS",           "dns.nextdns.io"  },
        {"Apple",             "www.apple.com"   },
        {NULL}
};

void probeTargets( void )
{
    struct addrinfo request;
    memset( &request, 0, sizeof(request));
    request.ai_socktype = SOCK_RAW;

    logDebug( "---- Targets\n" );
    for ( int i = 0; targets[i].name != NULL; i++ ) {
        logDebug( " target: %s (%s)\n", targets[i].name, targets[i].host );

        struct addrinfo * addrInfo = NULL;
        if ( getaddrinfo( targets[i].host, NULL, &request, &addrInfo ) == 0 ) {
            for ( ; addrInfo != NULL; addrInfo = addrInfo->ai_next ) {
                addSockAddrToList( addrInfo->ai_addr, &targets[i].addresses );
#ifdef DEBUG
                char addressStr[256];
                sockAddrToStr( addrInfo->ai_addr, addressStr, sizeof(addressStr) );
                logDebug( "address: %s\n", addressStr );
#endif
            }
        }
    }
}


int setup( int argc, char *argv[] )
{
    g.my.pid = getpid();

    /* basename() would be simpler, but its definition is way too vague about possible side effects */
    g.my.name = strrchr( argv[0], '/' );
    if ( g.my.name++ == NULL) {
        g.my.name = argv[0];
    }

    memset( &g.dp, 0, sizeof(g.dp));
    g.dp.dp_type = NL_DUMP_DETAILS;
    g.dp.dp_ivar = NH_DUMP_FROM_DETAILS;
    g.dp.dp_prefix = 16;
    g.dp.dp_fd = stderr;
    g.dp.dp_dump_msgtype = 1;

    g.netlink.socket = nl_socket_alloc();
    if ( g.netlink.socket != NULL) {
        nl_connect( g.netlink.socket, NETLINK_ROUTE );

        probeRoutes();

        probeTargets();
    }

    return 0;
}


int mainLoop( void )
{
    if ( g.wanList == NULL) {
        logError( "%s: no default network routes found to monitor.\n", g.my.name );
        return -1;
    }

    tRawPacket *packet = calloc( 1, sizeof( tRawPacket ));
    if ( packet == NULL) {
        return -ENOMEM;
    }

    uSockAddr target;

    target.family = AF_INET;
    inet_pton( AF_INET, "1.1.1.1", &target.in.sin_addr );

    ssize_t rc;
    g.seq = 1;
    for ( tWANinterface * interface = g.wanList; interface != NULL; interface = interface->next )
    {
        logDebug ( "interface %s\n", interface->name );
        for (int ttl = 1; ttl < 20; ttl++)
        {
            makeEchoRequestV4( packet, &interface->source.v4->addr, &target.in, ttl );

            struct timeval timeout = {1, 0}; // wait max 1 seconds for a reply

            rc = sendto( interface->socketFD,
                         packet, packet->v4.hdr.tot_len, 0,
                         &target.common, sizeof(target) );

            if ( rc <= 0 ) {
                perror( location );
                break;
            } else {
                char sockAddrAsStr[256];
                sockAddrToStr( &target.common, sockAddrAsStr, sizeof(sockAddrAsStr) );
                logDebug( "ICMP 'Echo Request' to %s, seq = %d, ttl %d\n", sockAddrAsStr, g.seq, ttl );
                dumpHex( packet, packet->v4.hdr.tot_len );
            }

            fd_set read_set;
            memset( &read_set, 0, sizeof( read_set ) );
            FD_SET( interface->socketFD, &read_set );

            // wait for a reply with a timeout
            rc = select( interface->socketFD + 1, &read_set, NULL, NULL, &timeout );
            if ( rc == 0 ) {
                logDebug( "timeout: no response received\n" );
                continue;
            } else if ( rc < 0 ) {
                perror( location );
                break;
            }

            tRawPacket receivedPkt;

            uSockAddr senderAddr;
            socklen_t senderAddrLen = sizeof( senderAddr );
            rc = recvfrom( interface->socketFD,
                           &receivedPkt, sizeof( receivedPkt ), 0,
                           &senderAddr.common, &senderAddrLen );
            if ( rc < 0 ) {
                perror( location );
                break;
            } else if ( rc < sizeof( struct icmphdr ) ) {
                logDebug( "Error: truncated ICMP response (only %ld bytes long)\n", rc );
                break;
            } else {
                int type = receivedPkt.v4.icmp.type;
                if (type == ICMP_TIME_EXCEEDED) {
                    /* remember this hop */
                }
#ifdef DEBUG
                const char * typeString = NULL;
                if (type < ICMP_MAXTYPE) {
                    typeString = icmpTypeAsString[type];
                }
                if (typeString == NULL) {
                    typeString = "<error>";
                }
                char senderAddrAsStr[256];
                sockAddrToStr( &senderAddr.common, senderAddrAsStr, sizeof(senderAddrAsStr) );

                logDebug( "ICMP \'%s\' from %s, seq = %d, id=%d\n",
                          typeString,
                          senderAddrAsStr,
                          receivedPkt.v4.icmp.un.echo.sequence, receivedPkt.v4.icmp.un.echo.id );
#ifdef DEBUG
                if (type == ICMP_TIME_EXCEEDED) {
                    unsigned int id = ntohs( receivedPkt.v4.ext.timeExceeded.id );
                    logDebug( "original id = %04x\n", id );
#if 0
                    dumpHex( &receivedPkt, rc );
                    byte * p = (byte *)&receivedPkt.v4;
                    for ( int i = 0; i < rc; i++) {
                        if ( p[i] == 0x45 ) logDebug( "offset %d\n", i );
                    }
                    size_t offset = offsetof(tRawPacket, v4.ext.timeExceeded);
                    logDebug( "original: %lu\n", offset );
                    dumpHex( &receivedPkt.v4.ext.timeExceeded, rc - offset);
#endif
                }
#endif
                if (type == ICMP_ECHOREPLY && isSameAddr( &senderAddr, &target ) == 0)
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
    if ( g.netlink.socket != NULL) {
        nl_socket_free( g.netlink.socket );
        g.netlink.socket = NULL;
    }
    return exitCode;
}


int main( int argc, char *argv[] )
{
    int exitCode = setup( argc, argv );

    if ( exitCode == 0 ) {
        exitCode = mainLoop();

        exitCode = teardown( exitCode );
    }
    exit( exitCode );
}
