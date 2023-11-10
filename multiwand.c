//
// Created by paul on 11/5/23.
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <memory.h>
#include <arpa/inet.h>

/* /usr/include/libnl3 */
#include <libnl3/netlink/addr.h>
#include <libnl3/netlink/object.h>
#include <libnl3/netlink/cache.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/route.h>
#include <libnl3/netlink/errno.h>

#include "multiwand.h"

void eachRouteObj(struct nl_object * nlObj, void * arg )
{
    char str[8192];

    struct rtnl_route *routeObj = (struct rtnl_route*) nlObj;
    /* do what you need to do with rtnl_route object */
    struct nl_addr * nlAddr = rtnl_route_get_dst( routeObj );
    if ( nl_addr_iszero( nlAddr ) )
    {
        nl_object_dump_buf( nlObj, str, sizeof(str) );
        printf( "%s (%d): %s", nl_object_get_type(nlObj), nl_object_get_msgtype(nlObj), str );
    }
}

int main(int argc, char * argv[])
{
    struct nl_cache * nlLinkCache;
    struct nl_cache * nlRouteCache;

    struct nl_sock * nlSocket = nl_socket_alloc();
    if (nlSocket != NULL) {
        nl_connect( nlSocket, NETLINK_ROUTE );

        int err = rtnl_link_alloc_cache( nlSocket, AF_UNSPEC, &nlLinkCache );
        if ( err < 0 ) {
            printf( "error: link cache: %d: %s\n", err, nl_geterror( err ));
        } else {
            char interfaceName[32];
            for ( int i = 1; rtnl_link_i2name( nlLinkCache, i, interfaceName, sizeof(interfaceName) ) != NULL; i++ ) {
                printf( "%d: %s\n", i, interfaceName );
            }
        }
        err = rtnl_route_alloc_cache( nlSocket, AF_UNSPEC, 0, &nlRouteCache );
        if ( err < 0 ) {
            printf( "error: route cache: %d: %s\n", err, nl_geterror(err) );
        } else {
            nl_cache_foreach( nlRouteCache, eachRouteObj, NULL);
        }
    }

    exit( 0 );
}
