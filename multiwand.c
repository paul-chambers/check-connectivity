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

#define stringify(x) #x
#define tostring(x) stringify(x)
#define location __FILE_NAME__ ":" tostring(__LINE__)

#define logDebug( ... ) if (g.debug > 0) fprintf( stderr, location " " __VA_ARGS__ )
#define logError( ... ) fprintf( stderr, "Error: " __VA_ARGS__ )

const char kPathSeparator =
#ifdef _WIN32
    '\\';
#else
    '/';
#endif

typedef unsigned char byte;

/* it's heck of a lot easier to handle socket addresses if they are bundled together as a union */
typedef union {
    sa_family_t family;     /* all structures start with the family, to identify which structure it is */
    struct sockaddr         sockaddr;   /* to minimize casting */
    struct sockaddr_in      in;         /* IPv4 */
    struct sockaddr_in6     in6;        /* IPv6 */
    struct sockaddr_nl      nl;         /* netlink */
    struct sockaddr_storage storage;    /* official structure which defines size to allocate */
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
} tRawICMPpacket;

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

    unsigned int        debug;

    struct {
        struct nl_sock * socket;
    } netlink;

    uint16_t            seq;
    tRawICMPpacket *    packetList;
    tWANinterface *     interfaceList;

    struct nl_cache *   addrCache;
    struct nl_cache *   linkCache;
    struct nl_cache *   routeCache;

    // libnl3 configuration for dumping structures
    struct nl_dump_params dp;
} tGlobals;

tGlobals g;

/************************************************************************************/
#ifdef DEBUG

void dumpHex( void *ptr, size_t len )
{
    unsigned int offset = 0;

    if ( ptr == NULL || len == 0 ) return;
    do {
        if ( offset % 16 == 0 ) {
            fprintf( stderr, "%04x: ", offset );
        }
        fprintf( stderr, "%02x ", ((uint8_t *) ptr)[offset] );
        if ( (offset % 16) == 15 || len == 0 ) {
            fputc( '\n', stderr );
        } else if ((offset % 4) == 3) {
            fputc( ' ', stderr );
        }
        offset++;
        len--;
    } while ( len > 0 );
}

void dumpDec( void *ptr, size_t len )
{
    unsigned int offset = 0;

    if ( ptr == NULL || len == 0 ) return;
    do {
        fprintf( stderr, "%d", ((uint8_t *) ptr)[offset] );
        if ( (offset % 16) == 15 || len == 0 ) {
            fputc( '\n', stderr );
        } else {
            fputc(' ', stderr);
        }
        offset++;
        len--;
    } while ( len > 0 );
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

#endif

/**
 * Generic test to see if two socket addresses are the same
 */
bool isSameAddr( uSockAddr *a, uSockAddr *b )
{
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
            logError("family not supported\n");
            return false;
        }

        return (memcmp( pa, pb, len ) == 0);
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
            /* ToDo: figure out what this means for IPv6 */
            // pa = (byte *)&a->in6.sin6_addr;
            // pb = (byte *)&b->in6.sin6_addr;
            return true;
        }
    }
    return false;
}

 /**
  * checksum calculation according to RFC 1071
  *
  * @param header
  * @param length
  * @return
  */
unsigned int RFC1071Checksum( void *header, size_t length )
{
    register uint16_t *word = (uint16_t *) header;
    register uint32_t sum = 0;

    // Sum adjacent 16 bit words
    while ( length > 1 ) {
        sum += *word++;
        length -= 2;
    }

    // if length was odd, there's one more byte to add.
    if ( length > 0 ) {
        sum += *(uint8_t *) word;
    }

    /* Deferred carry processing: add the carry bits that overflowed into the
       top 16 bits back into the lower 16 bits. Repeat while there are still
       carry bits set in the upper 16 bits. */
    while ( (sum >> 16) != 0 ) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    /* the final RFC1071 checksum is the one's compliment of the result of the calculation above. */
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
        logDebug( "unsupported address family (%d: %s)\n", addr->sa_family, familyAsString[addr->sa_family] );
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

    icmpHdr->checksum = RFC1071Checksum( icmpHdr, length );
    return length;
}

void makeEchoRequestV4( tRawICMPpacket *pkt, struct sockaddr_in * srcAddr, struct sockaddr_in * dstAddr, int ttl )
{
    const char *payload = "connectivity check";

    size_t ipHdrLen     = makeIPv4header( &pkt->v4.hdr, IPPROTO_ICMP,
                                          ttl, srcAddr, dstAddr );
    size_t icmpHdrLen   = makeICMPv4packet( &pkt->v4.icmp, ICMP_ECHO, 0,
                                            (void *) payload, strlen( payload ) + 1 );
    pkt->v4.hdr.tot_len = ipHdrLen + icmpHdrLen;
    pkt->v4.hdr.check   = RFC1071Checksum( pkt, pkt->v4.hdr.tot_len );
}

#if 0
tWANinterface * getWANinterface( unsigned int intfIndex, const char *intfName )
{
    tWANinterface *result = NULL;
    for ( result = g.interfaceList; result != NULL; result = result->next ) {
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

            result->next = g.interfaceList;
            g.interfaceList = result;
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


    for ( tWANinterface * interface = g.interfaceList; interface != NULL; interface = interface->next ) {
        /* this address object is associated with the interface of interest */
        if ( rtnl_addr_get_ifindex( addrObj ) == interface->index ) {

            struct nl_addr *sourceAddr = rtnl_addr_get_local( addrObj );
            char sourceAsStr[128];
            nl_addr2str( sourceAddr, sourceAsStr, sizeof(sourceAsStr));
            if (g.debug) {
                int intfIndex = rtnl_addr_get_ifindex( addrObj );
                char intfName[64];
                rtnl_link_i2name( g.linkCache, intfIndex, intfName, sizeof(intfName));
                logDebug( "---- Address: %s, %s\n", intfName, sourceAsStr );
                // nl_object_dump( nlObj, &g.dp);
            }

            socklen_t srcLen = sizeof( uSockAddr );
            struct sockaddr * srcAddr = calloc( 1, srcLen );
            int err = nl_addr_fill_sockaddr( sourceAddr, srcAddr, &srcLen );
            if (err != 0) {
                logError( "fill_sockaddr: %d\n", err );
            }
            srcAddr = realloc( srcAddr, srcLen );
            // char srcAsStr[128];
            // sockAddrToStr( srcAddr, srcAsStr, sizeof(srcAsStr) );
            // logDebug( "srcAddr: %s\n", srcAsStr );
            // dumpHex( srcAddr, srcLen );

            if (g.debug > 0) {
                int scope = rtnl_addr_get_scope( addrObj );
                char scopeAsStr[128];
                rtnl_scope2str( scope, scopeAsStr, sizeof(scopeAsStr));

                unsigned int flags = rtnl_addr_get_flags( addrObj );
                char flagsAsStr[256];
                rtnl_addr_flags2str( flags, flagsAsStr, sizeof( flagsAsStr ));

                logDebug( "%s source: %s scope: %s flags: %s\n", interface->name, sourceAsStr, scopeAsStr, flagsAsStr );

                for ( tWANroute * route = interface->wanRoutes; route != NULL; route = route->next ) {

                    char gatewayAsStr[256];
                    nl_addr2str( route->gateway, gatewayAsStr, sizeof(gatewayAsStr));
                    if ( nl_addr_cmp_prefix( sourceAddr, route->gateway ) == 0 ) {
                        logDebug( " - matches %s gateway: %s\n", interface->name, gatewayAsStr );
                        addSockAddrToList( srcAddr, &interface->source );
                    }
                }
            }
            break;
        }
    }
}

tWANinterface * getInterface( int intfIndex )
{
    tWANinterface * interface;

    for ( interface = g.interfaceList; interface != NULL; interface = interface->next ) {
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

            interface->next = g.interfaceList;
            g.interfaceList = interface;
        }
    }
error:
    return interface;
}

void forEachNexthopObj( struct rtnl_nexthop * nextHopObj, void * arg )
{
    struct rtnl_route * routeObj = (struct rtnl_route *)arg;

    struct nl_addr * gatewayAddr = rtnl_route_nh_get_gateway( nextHopObj );

    if ( gatewayAddr == NULL) {
        // logError( "no gateway defined\n" );
        return;
    }

    int intfIndex = rtnl_route_nh_get_ifindex( nextHopObj );

#ifdef DEBUG
    struct rtnl_link * linkObj = rtnl_link_get( g.linkCache, intfIndex );
    const char *      intfName = rtnl_link_get_name( linkObj );
    logDebug("---- NextHop for %s\n", intfName );
    rtnl_route_nh_dump( nextHopObj, &g.dp );
    fputc('\n', stderr);
#endif

    tWANinterface * interface = getInterface( intfIndex );
    if (interface == NULL) {
        logDebug( "couldn't find interface for index %d\n", intfIndex );
        return;
    }

    /* at this point, we have either a new or existing tWANinterface, so add a route to its wanRoutes */
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

    bool isDefaultRoute = nl_addr_iszero( dstAddr );

    /* ignore it if it isn't a default route */
    if ( isDefaultRoute )
    {
#ifdef DEBUG
        fprintf(stderr,"\n");
        logDebug("-- default route\n" );
        nl_object_dump( nlObj, &g.dp );
#endif
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

    /* now scan through the addresses of interfaces, looking for the source address to use for each gateway */
    if ( g.interfaceList != NULL) {
#ifdef DEBUG
        fprintf(stderr, "\n");
        logDebug( "-- Addresses\n" );
#endif
        nl_cache_foreach( g.addrCache, forEachAddrObj, NULL);
    }

#ifdef DEBUG
    /* dump out the WAN interfaces we found, and their associated addresses */
    fprintf(stderr,"\n");
     logDebug("-- Interfaces\n");
     for ( tWANinterface * interface = g.interfaceList; interface != NULL; interface = interface->next )
     {
         char addrAsStr[64];
         logDebug( "interface %s\n", interface->name );
         logDebug( "  index: %d, socket: %d\n", interface->index, interface->socketFD );
         for ( tV4Entry * entry = interface->source.v4; entry != NULL; entry = entry->next ) {
             sockAddrToStr( (struct sockaddr *)&entry->addr, addrAsStr, sizeof(addrAsStr));
             logDebug( "  address: %s\n", addrAsStr );
         }
         for ( tV6Entry * entry = interface->source.v6; entry != NULL; entry = entry->next ) {
             sockAddrToStr( (struct sockaddr *)&entry->addr, addrAsStr, sizeof(addrAsStr));
             logDebug( "  address: %s\n", addrAsStr );
         }
     }
#endif

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

#ifdef DEBUG
    fprintf( stderr, "\n" );
    logDebug( "---- Targets\n" );
#endif
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


/**
 * A simple, non-destructive, and portable equivalent of the standard basename() library function.
 *
 * The official definition of basename() is way too vague about potential side effects of
 * different library implementations.
 */

const char * myBasename( const char * path )
{
    const char * result = strrchr( path, kPathSeparator );
    if ( result++ == NULL) {
        result = path;
    }
    return result;
}

int setup( int argc, char *argv[] )
{
#ifdef DEBUG
    g.debug = 1;
#else
    g.debug = 0;
#endif

    g.my.pid = getpid();

    g.my.name = myBasename( argv[0] );

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
    if ( g.interfaceList == NULL) {
        logError( "%s: no default network routes found to monitor.\n", g.my.name );
        return -1;
    }

    tRawICMPpacket *packet = calloc( 1, sizeof( tRawICMPpacket ));
    if ( packet == NULL) {
        return -ENOMEM;
    }

    uSockAddr target;

    target.family = AF_INET;
    inet_pton( AF_INET, "8.8.8.8", &target.in.sin_addr );

    ssize_t rc;
    g.seq = 1;
    for ( tWANinterface * interface = g.interfaceList; interface != NULL; interface = interface->next )
    {
        if (g.debug > 0) {
            fprintf( stderr, "\n" );
            logDebug ( "interface %s\n", interface->name );
        }

        for (int ttl = 1; ttl < 20; ttl++)
        {
            makeEchoRequestV4( packet, &interface->source.v4->addr, &target.in, ttl );

            struct timeval timeout = {1, 0}; // wait max 1 seconds for a reply

            if (g.debug > 0) {
                char srcAsStr[256];
                sockAddrToStr((struct sockaddr *) &interface->source.v4->addr, srcAsStr, sizeof(srcAsStr));
                char destAsStr[256];
                sockAddrToStr( &target.sockaddr, destAsStr, sizeof(destAsStr));
                logDebug( "Sent ICMP Echo Request    from %s to %s, seq = %d, ttl %d\n",
                          srcAsStr,
                          destAsStr,
                          g.seq,
                          ttl );
            }

            rc = sendto( interface->socketFD,
                         packet, packet->v4.hdr.tot_len, 0,
                         &target.sockaddr, sizeof(target) );

            if ( rc <= 0 ) {
                perror( location );
                break;
            } else {
                 //dumpHex( packet, packet->v4.hdr.tot_len );
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

            tRawICMPpacket receivedPkt;

            uSockAddr senderAddr;
            socklen_t senderAddrLen = sizeof( senderAddr );
            rc = recvfrom( interface->socketFD,
                           &receivedPkt, sizeof( receivedPkt ), 0,
                           &senderAddr.sockaddr, &senderAddrLen );
            if ( rc < 0 ) {
                perror( location );
                break;
            } else if ( rc < sizeof( struct icmphdr ) ) {
                logDebug( "Error: truncated ICMP response (only %ld bytes long)\n", rc );
                break;
            } else {
                int type = receivedPkt.v4.icmp.type;

                if (g.debug > 0) {
                    const char *typeString = NULL;
                    if ( type < ICMP_MAXTYPE ) {
                        typeString = icmpTypeAsString[type];
                    }
                    if ( typeString == NULL) {
                        typeString = "<error>";
                    }
                    char senderAddrAsStr[256];
                    sockAddrToStr( &senderAddr.sockaddr, senderAddrAsStr, sizeof(senderAddrAsStr));

                    logDebug( "Rcvd ICMP %-15s from %s, seq = %d, id=%d, orig id=%04x\n",
                              typeString,
                              senderAddrAsStr,
                              receivedPkt.v4.icmp.un.echo.sequence,
                              receivedPkt.v4.icmp.un.echo.id,
                              ntohs( receivedPkt.v4.ext.timeExceeded.id ));
                }

                switch ( type ) {
                case ICMP_TIME_EXCEEDED:
                    /* remember this hop */
                    break;

                case ICMP_ECHOREPLY:
                    if (isSameAddr( &senderAddr, &target ))
                    {
                        logDebug("reached target\n\n");
                        /* short-circuit the loop */
                        ttl = 64;
                    }
                    break;

                default:
                    break;
                }
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
