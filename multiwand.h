//
// Created by paul on 11/5/23.
//

#ifndef MULTIWAND_MULTIWAND_H
#define MULTIWAND_MULTIWAND_H

#define ALIGN(bytes) __attribute__ ((aligned(bytes)))
#define PACKED __attribute__ ((packed))

#ifdef DEBUG

const char *icmpTypeAsString[] = {
        [ICMP_ECHOREPLY]         = "Echo Reply",
        [ICMP_DEST_UNREACH]      = "Dest Unreach",
        [ICMP_SOURCE_QUENCH]     = "Source Quench",
        [ICMP_REDIRECT]          = "Redirect",
        [ICMP_ECHO]              = "Echo Request",
        [ICMP_TIME_EXCEEDED]     = "Time Exceeded",
        [ICMP_PARAMETERPROB]     = "Parameter Prob",
        [ICMP_TIMESTAMP]         = "Timestamp Rqst",
        [ICMP_TIMESTAMPREPLY]    = "Timestamp Rply",
        [ICMP_INFO_REQUEST]      = "Info Rqst",
        [ICMP_INFO_REPLY]        = "Info Rply",
        [ICMP_ADDRESS]           = "Addr Mask Rqst",
        [ICMP_ADDRESSREPLY]      = "Addr Mask Rply"
};

/* map a socket 'family' ID to a string for debugging messages */
const char *familyAsString[] = {
        [AF_UNSPEC]      = "Unspecified",
        [AF_LOCAL]       = "Local",
        [AF_INET]        = "IPv4",
        [AF_AX25]        = "Amateur Radio AX.25",
        [AF_IPX]         = "Novell Internet Protocol",
        [AF_APPLETALK]   = "Appletalk DDP",
        [AF_NETROM]      = "Amateur Radio NetROM",
        [AF_BRIDGE]      = "Multi-protocol bridge",
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


#ifdef DEBUG
// NOTE: these are private to libnl3, but copied here because
// it's very helpful to have them defined when sourceV4 debugging

// !!!! OPAQUE: DO NOT REFERENCE IN SOURCE CODE !!!!

struct nl_addr {
    int a_family;
    unsigned int a_maxsize;
    unsigned int a_len;
    int a_prefixlen;
    int a_refcnt;
    char a_addr[0];
};

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
    int                     ce_refcnt;   \
    struct nl_object_ops *  ce_ops;      \
    struct nl_cache *       ce_cache;    \
    struct nl_list_head     ce_list;     \
    int                     ce_msgtype;  \
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
#endif


#endif //MULTIWAND_MULTIWAND_H
