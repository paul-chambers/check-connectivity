/*
    Created by Paul Chambers on 11/5/23.
*/

#include <stdlib.h>
#include <stdio.h>
// #include <unistd.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <memory.h>
// #include <arpa/inet.h>

/* /usr/include/libnl3 */
#include <libnl3/netlink/addr.h>
#include <libnl3/netlink/cache.h>
#include <libnl3/netlink/errno.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/object.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/route.h>
#include <libnl3/netlink/socket.h>


struct rtnl_nexthop {
    uint8_t rtnh_flags;
    uint8_t rtnh_flag_mask;
    uint8_t rtnh_weight;
    /* 1 byte spare */
    uint32_t rtnh_ifindex;
    struct nl_addr *rtnh_gateway;
    uint32_t ce_mask; /* HACK to support attr macros */
    struct nl_list_head rtnh_list;
    uint32_t rtnh_realms;
    struct nl_addr *rtnh_newdst;
    struct nl_addr *rtnh_via;
    struct rtnl_nh_encap *rtnh_encap;
};

#define NLHDR_COMMON                \
    int                     ce_refcnt;    \
    struct nl_object_ops *  ce_ops;        \
    struct nl_cache *       ce_cache;    \
    struct nl_list_head     ce_list;    \
    int                     ce_msgtype;    \
    int                     ce_flags;    \
    uint64_t                ce_mask;

struct rtnl_route {
    NLHDR_COMMON

            uint8_t rt_family;
    uint8_t rt_dst_len;
    uint8_t rt_src_len;
    uint8_t rt_tos;
    uint8_t rt_protocol;
    uint8_t rt_scope;
    uint8_t rt_type;
    uint8_t rt_nmetrics;
    uint8_t rt_ttl_propagate;
    uint32_t rt_flags;
    struct nl_addr *rt_dst;
    struct nl_addr *rt_src;
    uint32_t rt_table;
    uint32_t rt_iif;
    uint32_t rt_prio;
    uint32_t rt_metrics[RTAX_MAX];
    uint32_t rt_metrics_mask;
    uint32_t rt_nr_nh;
    struct nl_addr *rt_pref_src;
    struct nl_list_head rt_nexthops;
    struct rtnl_rtcacheinfo rt_cacheinfo;
    uint32_t rt_flag_mask;
};

// #include "multiwand.h"

typedef struct {
    struct nl_cache * nlLinkCache;
} tCallbackArg;

void eachRouteObj(struct nl_object * nlObj, void * arg )
{
    char str[8192];

    struct rtnl_route *routeObj = (struct rtnl_route*) nlObj;

    struct nl_addr * nlAddr = rtnl_route_get_dst( routeObj );
    if ( nl_addr_iszero( nlAddr ) )
    {
        struct rtnl_nexthop * nlNexthop = rtnl_route_nexthop_n( routeObj, 0);
        if (nlNexthop  != NULL ) {
#if 0
            struct nl_dump_params nlDumpParams;
            nlDumpParams.dp_buf = str;
            nlDumpParams.dp_buflen = sizeof(str);
            nlDumpParams.dp_type = NL_DUMP_DETAILS;
            nlDumpParams.dp_ivar = NH_DUMP_FROM_DETAILS;
            rtnl_route_nh_dump( nlNexthop, &nlDumpParams );
            printf( "nexthop: %s\n", str );
#endif
            const struct nl_addr * gatewayAddr = rtnl_route_nh_get_gateway( nlNexthop );
            if ( gatewayAddr == NULL) {
                printf( "error: gatewayAddr is %p\n", gatewayAddr );
            } else {
                nl_addr2str( gatewayAddr, str, sizeof(str));
                printf( "gateway: %s\n", str );
            }

            int ifidx = rtnl_route_nh_get_ifindex( nlNexthop );
            char interfaceName[32];
            rtnl_link_i2name( ((tCallbackArg *)arg)->nlLinkCache, ifidx, interfaceName, sizeof(interfaceName) );
            printf( "%2d- %s\n", ifidx, interfaceName );

            uint32_t prio = rtnl_route_get_priority( routeObj );
            printf( "metric %d\n", prio );
        }
        // printf( "%u %u\n", ifidx, ifmetric );
    }
}

int main(int argc, char * argv[])
{
    tCallbackArg cbArg;
    struct nl_cache * nlRouteCache;

    struct nl_sock * nlSocket = nl_socket_alloc();
    if (nlSocket != NULL) {
        nl_connect( nlSocket, NETLINK_ROUTE );

        int err = rtnl_link_alloc_cache( nlSocket, AF_UNSPEC, &cbArg.nlLinkCache );
        if ( err < 0 ) {
            printf( "error: link cache: %d: %s\n", err, nl_geterror( err ));
        } else {
            char interfaceName[32];
            for ( int i = 1; rtnl_link_i2name( cbArg.nlLinkCache, i, interfaceName, sizeof(interfaceName) ) != NULL; i++ ) {
                printf( "%2d: %s\n", i, interfaceName );
            }
        }
        err = rtnl_route_alloc_cache( nlSocket, AF_UNSPEC, 0, &nlRouteCache );
        if ( err < 0 ) {
            printf( "error: route cache: %d: %s\n", err, nl_geterror(err) );
        } else {
            nl_cache_foreach( nlRouteCache, eachRouteObj, &cbArg);
        }
    }

    exit( 0 );
}
