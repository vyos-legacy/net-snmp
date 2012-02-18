/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/interface.h>
#include <net-snmp/data_access/route.h>
#include <net-snmp/data_access/ipaddress.h>

#include "ip-forward-mib/data_access/route_ioctl.h"
#include "ip-forward-mib/inetCidrRouteTable/inetCidrRouteTable_constants.h"
#include "if-mib/data_access/interface_ioctl.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define RCVBUF_SIZE 32768
#define SNDBUF_SIZE 512

static int
_addresstype_from_family(int family)
{
    switch (family) {
    case AF_INET:
        return INETADDRESSTYPE_IPV4;
    case AF_INET6:
        return INETADDRESSTYPE_IPV6;
    default:
        return INETADDRESSTYPE_UNKNOWN;
    }
}

static int
_type_from_rtm(const struct rtmsg *r)
{
    switch (r->rtm_type) {
    case RTN_UNREACHABLE:
        return INETCIDRROUTETYPE_REJECT;
    case RTN_BLACKHOLE:
        return INETCIDRROUTETYPE_BLACKHOLE;
    case RTN_LOCAL:
        return INETCIDRROUTETYPE_LOCAL;
    default:
        return INETCIDRROUTETYPE_OTHER;
    }
}

static netsnmp_route_entry *
entry_from_rtm(struct rtmsg *r, int rtcount, u_long *index)
{
    netsnmp_route_entry *entry;
    struct rtattr *rta  = RTM_RTA(r);
    u_char addresstype = _addresstype_from_family(r->rtm_family);

    entry = netsnmp_access_route_entry_create();
    entry->ns_rt_index = ++(*index);
    entry->rt_type = _type_from_rtm(r);
    entry->rt_proto = (r->rtm_flags & RTF_DYNAMIC)
        ? IANAIPROUTEPROTOCOL_ICMP : IANAIPROUTEPROTOCOL_LOCAL;

    DEBUGMSGTL(("access:route", "route index %u type %u proto %u\n",
                entry->ns_rt_index, entry->rt_type, entry->rt_proto));

    /* absence of destination, implies default route (all-zeros) */
    entry->rt_pfx_len = r->rtm_dst_len;
    entry->rt_nexthop_len = (r->rtm_family == AF_INET) ? 4 : 16;

    while (RTA_OK(rta, rtcount)) {
        size_t len = RTA_PAYLOAD(rta);
        char b[INET6_ADDRSTRLEN];

        switch (rta->rta_type) {
        case RTA_OIF:
            entry->if_index = *(int *)(RTA_DATA(rta));

            DEBUGMSGTL(("access:route","    dev %s\n",
                        if_indextoname(entry->if_index, b)));
            break;

        case RTA_DST:
            entry->rt_dest_type = addresstype;
            entry->rt_dest_len = len;
            memcpy(entry->rt_dest, RTA_DATA(rta), len);

            DEBUGMSGTL(("access:route","    to %s/%u\n",
                        inet_ntop(r->rtm_family, entry->rt_dest,
                                  b, sizeof(b)),
                        r->rtm_dst_len));
            break;

        case RTA_GATEWAY:
            entry->rt_nexthop_type = addresstype;
            entry->rt_nexthop_len = len;
            memcpy(entry->rt_nexthop, RTA_DATA(rta), len);

            DEBUGMSGTL(("access:route","    via %s\n",
                        inet_ntop(r->rtm_family, entry->rt_nexthop,
                                  b, sizeof(b))));
            break;

        case RTA_PRIORITY:
            entry->rt_metric1 = *(uint32_t *)RTA_DATA(rta);
            DEBUGMSGTL(("access:route","    metric %d\n",
                        entry->rt_metric1));
            break;
        }

        rta = RTA_NEXT(rta,len);
    }

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
    entry->rt_tos = r->rtm_tos;
    if (r->rtm_family == AF_INET)
        entry->rt_mask = ~0 << (32 - r->rtm_dst_len);
#endif

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
    /*
      inetCidrRoutePolicy OBJECT-TYPE
      SYNTAX     OBJECT IDENTIFIER
      MAX-ACCESS not-accessible
      STATUS     current
      DESCRIPTION
      "This object is an opaque object without any defined
      semantics.  Its purpose is to serve as an additional
      index which may delineate between multiple entries to
      the same destination.  The value { 0 0 } shall be used
      as the default value for this object."
    */
    /*
     * on linux, many routes all look alike, and would have the same
     * indexed based on dest and next hop. So we use the if index
     * routing protocol and metric as the policy,
     * to distinguise between them. Hopefully this is unique.
     */
    entry->rt_policy = calloc(3, sizeof(oid));
    entry->rt_policy[0] = entry->if_index;
    entry->rt_policy[1] = r->rtm_protocol;
    entry->rt_policy[2] = entry->rt_metric1;
    entry->rt_policy_len = sizeof(oid) * 3;
#endif

    return entry;
}

static int
_load_netlink(netsnmp_container* container, int family, u_long *index)
{
    int             nlsk;
    unsigned char rcvbuf[RCVBUF_SIZE];
    int rcvbuf_size = RCVBUF_SIZE;
    unsigned char sndbuf[SNDBUF_SIZE];
    struct nlmsghdr *hdr;
    struct rtmsg *rthdr;
    int count;
    int end_of_message = 0;
    int rc = 0;
    static int seq;

    DEBUGMSGTL(("access:route", "route_container_load %s\n",
                (family == AF_INET) ? "ipv4" : "ipv6"));

    netsnmp_assert(NULL != container);

    /*
     * Open a netlink socket
     */
    nlsk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (nlsk < 0) {
        snmp_log_perror("socket netlink");
        return -1;
    }

    if (setsockopt(nlsk, SOL_SOCKET, SO_RCVBUF,
                   &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        snmp_log_perror("setsockopt netlink rcvbuf");
        close(nlsk);
        return -1;
    }

    memset(sndbuf, 0, SNDBUF_SIZE);
    hdr = (struct nlmsghdr *)sndbuf;
    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    hdr->nlmsg_type = RTM_GETROUTE;
    hdr->nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
    hdr->nlmsg_seq = ++seq;

    rthdr = (struct rtmsg *)NLMSG_DATA(hdr);
    rthdr->rtm_table = RT_TABLE_MAIN;
    rthdr->rtm_family = family;

    /*
     * Send a request to the kernel to dump the routing table to us
     */
    count = send(nlsk, sndbuf, hdr->nlmsg_len, 0);
    if (count < 0) {
        snmp_log_perror("send netlink");
        close(nlsk);
        return -2;
    }

    /*
     * Now listen for response
     */
    do {
        struct nlmsghdr *n;

        /*
         * Get the message
         */
        count = recv(nlsk, rcvbuf, RCVBUF_SIZE, 0);
        if (count < 0) {
            snmp_log_perror("recv netlink");
            rc = -1;
            break;
        }

        /*
         * Walk all of the returned messages
         */
        for (n = (struct nlmsghdr *)rcvbuf; NLMSG_OK(n, count);
             n = NLMSG_NEXT(n, count)) {
            struct rtmsg *rtm;
            netsnmp_route_entry *entry;

            /*
             * Make sure the message is ok
             */
            if (n->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(n);
                if (n->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    snmp_log(LOG_ERR, "kernel netlink error truncated\n");
                else
                    snmp_log(LOG_ERR, "kernel netlink error %s\n",
                             strerror(-err->error));
                rc = -1;
                break;
            }

            /*
             * End of message, we're done
             */
            if (n->nlmsg_type & NLMSG_DONE) {
                end_of_message = 1;
                break;
            }

            if (n->nlmsg_type != RTM_NEWROUTE) {
                snmp_log(LOG_ERR, "unexpected message of type %d in nlmsg\n",
                         n->nlmsg_type);
                continue;
            }

            rtm = NLMSG_DATA(n);
            if (rtm->rtm_family != family) {
                snmp_log(LOG_ERR, "Wrong family in netlink response %d\n",
                         rtm->rtm_family);
                break;
            }

            if (rtm->rtm_table != RT_TABLE_MAIN)
                    continue;
            /*
             * insert into container
             */
            entry = entry_from_rtm(rtm, RTM_PAYLOAD(n), index);

            if (CONTAINER_INSERT(container, entry) < 0)
            {
                DEBUGMSGTL(("access:route:container",
                            "error with route_entry: insert into container failed.\n"));
                netsnmp_access_route_entry_free(entry);
                rc = -1;
                break;
            }
        }

        if (rc < 0)
            break;

    } while (!end_of_message);

    close(nlsk);
    return rc;
}

/** arch specific load
 * @internal
 *
 * @retval  0 success
 * @retval -1 no container specified
 * @retval -2 could not open data file
 */
int
netsnmp_access_route_container_arch_load(netsnmp_container* container,
                                         u_int load_flags)
{
    u_long          count = 0;
    int             rc;

    DEBUGMSGTL(("access:route:container",
                "route_container_arch_load (flags %x)\n", load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_route\n");
        return -1;
    }

    rc = _load_netlink(container, AF_INET, &count);
    
#ifdef NETSNMP_ENABLE_IPV6
    if((0 != rc) || (load_flags & NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY))
        return rc;

    rc = _load_netlink(container, AF_INET6, &count);
#endif

    return rc;
}

/*
 * create a new entry
 */
int
netsnmp_arch_route_create(netsnmp_route_entry *entry)
{
    if (NULL == entry)
        return -1;

    if (4 != entry->rt_dest_len) {
        DEBUGMSGT(("access:route:create", "only ipv4 supported\n"));
        return -2;
    }

    return _netsnmp_ioctl_route_set_v4(entry);
}

/*
 * create a new entry
 */
int
netsnmp_arch_route_delete(netsnmp_route_entry *entry)
{
    if (NULL == entry)
        return -1;

    if (4 != entry->rt_dest_len) {
        DEBUGMSGT(("access:route:create", "only ipv4 supported\n"));
        return -2;
    }

    return _netsnmp_ioctl_route_delete_v4(entry);
}


