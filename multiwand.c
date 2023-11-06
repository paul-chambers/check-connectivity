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

#include "multiwand.h"

// buffer to hold the RTNETLINK request
struct {
    struct nlmsghdr nl;
    struct rtmsg    rt;
    char            buf[8192];
} req;

// variables used for
// socket communications
int                fd;
struct sockaddr_nl la;
struct sockaddr_nl pa;
struct msghdr      msg;
struct iovec       iov;
int                rtn;

// buffer to hold the RTNETLINK reply(ies)
char buf[8192];

// RTNETLINK message pointers & lengths
// used when processing messages
struct nlmsghdr * nlp;
int nll;
struct rtmsg * rtp;
int rtl;
struct rtattr * rtap;


void send_request()
{
    // create the remote address
    // to communicate
    memset(&pa, 0, sizeof(pa));
    pa.nl_family = AF_NETLINK;

    // initialize & create the struct msghdr supplied
    // to the sendmsg() function
    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = (void *) &pa;
    msg.msg_namelen = sizeof(pa);

    // place the pointer & size of the RTNETLINK
    // message in the struct msghdr
    iov.iov_base   = (void *) &req.nl;
    iov.iov_len    = req.nl.nlmsg_len;
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    // send the RTNETLINK message to kernel
    rtn = sendmsg(fd, &msg, 0);
}

// And, here's the recv_reply():

void recv_reply()
{
    char * p;

    // initialize the socket read buffer
    memset( buf, 0, sizeof(buf));

    p   = buf;
    nll = 0;

    // read from the socket until the NLMSG_DONE is
    // returned in the type of the RTNETLINK message
    // or if it was a monitoring socket
    do {
        rtn = recv(fd, p, sizeof(buf) - nll, 0);

        nlp = (struct nlmsghdr *) p;

        if ( nlp->nlmsg_type == NLMSG_DONE ) {
            break;
        }

        // increment the buffer pointer to place
        // next message
        p += rtn;

        // increment the total size by the size of
        // the last received message
        nll += rtn;

        if ((la.nl_groups & RTMGRP_IPV4_ROUTE) == RTMGRP_IPV4_ROUTE ) {
            break;
        }
    } while ( 1 );
}

/*
 * The above functions and the following ones use a set of globally defined variables .These are
 * used for all the socket operations as well as for forming and processing RTNETLINK messages:
*/

// The get_routing_table sample retrieves the main routing table of the IPv4 environment.

void form_request()
{
    // initialize the request buffer
    memset( &req, 0, sizeof(req));

    // set the NETLINK header
    req.nl.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nl.nlmsg_type  = RTM_GETROUTE;

    // set the routing message header
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_table  = RT_TABLE_MAIN;
}

// The received message for the RTNETLINK request in the buf variable to retrieve the routing
// table is processed by the read_reply() function. Here is the code of this function:

void read_reply()
{
    // string to hold content of the route
    // table (i.e. one entry)
    char dsts[24];
    char gws[24];
    char ifs[16];
    char ms[24];

    // outer loop: loops thru all the NETLINK
    // headers that also include the route entry
    // header
    nlp = (struct nlmsghdr *) buf;
    for ( ; NLMSG_OK(nlp, nll); nlp = NLMSG_NEXT(nlp, nll)) {

        // get route entry header
        rtp = (struct rtmsg *) NLMSG_DATA(nlp);

        // we are only concerned about the
        // main route table
        if ( rtp->rtm_table != RT_TABLE_MAIN ) {
            continue;
        }

        // init all the strings
        memset(dsts, 0, sizeof(dsts));
        memset(gws,  0, sizeof(gws));
        memset(ifs,  0, sizeof(ifs));
        memset(ms,   0, sizeof(ms));

        // inner loop: loop thru all the attributes of
        // one route entry
        rtap = (struct rtattr *) RTM_RTA(rtp);
        rtl  = RTM_PAYLOAD(nlp);
        for ( ; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
            switch ( rtap->rta_type ) {
                // destination IPv4 address
            case RTA_DST:
                inet_ntop(AF_INET, RTA_DATA(rtap), dsts, 24);
                break;

                // next hop IPv4 address
            case RTA_GATEWAY:
                inet_ntop(AF_INET, RTA_DATA(rtap), gws, 24);
                break;

                // unique ID associated with the network interface
            case RTA_OIF:
                sprintf(ifs, "%d", *((int *) RTA_DATA(rtap)));
                break;

            default:
                break;
            }
        }
        sprintf(ms, "%d", rtp->rtm_dst_len);

        printf("dst %s/%s gw %s if %s\n", dsts, ms, gws, ifs );
    }
}


/*
    The set_routing_table sample sends an RTNETLINK request to insert an entry to the routing table.
    The route entry that is inserted is a host route (32-bit network prefix) to a private IP address
    (192.168.0.100) through interface number 2. These values are defined in the variables dsts
    (destination IP address), ifcn (interface number) and pn (prefix length). You can run the
    get_routing_table sample to get an idea about the interface numbers and the IP network in
    your system. Here's the form_request():
*/

#if 0
void form_request()
{
    // attributes of the route entry
    char dsts[24] = "192.168.0.100";
    int  ifcn     = 2, pn = 32;

    // initialize RTNETLINK request buffer
    memset( &req, 0, sizeof(req));

    // compute the initial length of the
    // service request
    rtl = sizeof(struct rtmsg);

    // add first attrib:
    // set destination IP addr and increment the
    // RTNETLINK buffer size
    rtap = (struct rtattr *) req.buf;
    rtap->rta_type = RTA_DST;
    rtap->rta_len  = sizeof(struct rtattr) + 4;
    inet_pton(AF_INET, dsts,
              ((char *) rtap) + sizeof(struct rtattr));
    rtl += rtap->rta_len;

    // add second attrib:
    // set ifc index and increment the size
    rtap = (struct rtattr *) (((char *) rtap)
                              + rtap->rta_len);
    rtap->rta_type = RTA_OIF;
    rtap->rta_len  = sizeof(struct rtattr) + 4;
    memcpy(((char *) rtap) + sizeof(struct rtattr),
           &ifcn, 4);
    rtl += rtap->rta_len;

    // setup the NETLINK header
    req.nl.nlmsg_len   = NLMSG_LENGTH(rtl);
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    req.nl.nlmsg_type  = RTM_NEWROUTE;

    // setup the service header (struct rtmsg)
    req.rt.rtm_family   = AF_INET;
    req.rt.rtm_table    = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_STATIC;
    req.rt.rtm_scope    = RT_SCOPE_UNIVERSE;
    req.rt.rtm_type     = RTN_UNICAST;
    // set the network prefix size
    req.rt.rtm_dst_len  = pn;
}
#endif

int main(int argc, char * argv[])
{
    printf("hello world\n");

    // open socket
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    // setup local address & bind using
    // this address
    memset(&la, 0, sizeof(la));
    la.nl_family = AF_NETLINK;
    la.nl_pid    = getpid();
    bind(fd, (struct sockaddr *) &la, sizeof(la));


    // sub functions to create RTNETLINK message,
    // send over socket, receive reply & process
    // message
    form_request();
    send_request();
    recv_reply();
    read_reply();

    // close socket
    close(fd);

    exit(0);
}
