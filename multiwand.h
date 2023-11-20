//
// Created by paul on 11/5/23.
//

#ifndef MULTIWAND_MULTIWAND_H
#define MULTIWAND_MULTIWAND_H

#ifdef DEBUG
// NOTE: these are private to libnl3, but it's very handy to have them defined when debugging
// DO NOT USE IN SOURCE CODE!

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
