/*
 *  Interface MIB architecture support
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
#include "ip-forward-mib/inetCidrRouteTable/inetCidrRouteTable_data_access.h"
#include "if-mib/data_access/interface_ioctl.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define RCVBUF_SIZE (32768)
#define SNDBUF_SIZE (512)

static int nlseq;

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
        return 0;
    }
}

static void
fillup_entry_info(netsnmp_route_entry *entry, struct rtmsg *r, int rtcount)
{
    struct rtattr  *rta;

    entry->rt_type = _type_from_rtm(r);
    entry->rt_proto = (r->rtm_flags & RTF_DYNAMIC)
        ? IANAIPROUTEPROTOCOL_ICMP : IANAIPROUTEPROTOCOL_LOCAL;

    DEBUGMSGTL(("access:route", "    ns_rt_index %u\n", entry->ns_rt_index));
    DEBUGMSGTL(("access:route", "    proto %u\n", entry->rt_proto));

#ifdef NETSNMP_ENABLE_IPV6
    if (r->rtm_family == AF_INET6) {
        entry->rt_dest_type = INETADDRESSTYPE_IPV6;
        entry->rt_dest_len = NETSNMP_ACCESS_ROUTE_ADDR_IPV6_BUF_SIZE;

        entry->rt_nexthop_type = INETADDRESSTYPE_IPV6;
        entry->rt_nexthop_len = NETSNMP_ACCESS_ROUTE_ADDR_IPV6_BUF_SIZE;
    } else
#endif
    {
        entry->rt_dest_type = INETADDRESSTYPE_IPV4;
        entry->rt_dest_len = NETSNMP_ACCESS_ROUTE_ADDR_IPV4_BUF_SIZE;

        entry->rt_nexthop_type = INETADDRESSTYPE_IPV4;
        entry->rt_nexthop_len = NETSNMP_ACCESS_ROUTE_ADDR_IPV4_BUF_SIZE;
    }
    entry->rt_pfx_len = r->rtm_dst_len;
    DEBUGMSGTL(("access:route", "    pfxlen %u\n", entry->rt_pfx_len));

    rta = RTM_RTA(r);
    while (RTA_OK(rta, rtcount)) {
        size_t          len = RTA_PAYLOAD(rta);
        char            b[INET6_ADDRSTRLEN];

        switch (rta->rta_type) {
        case RTA_OIF:
            entry->if_index = *(int *) (RTA_DATA(rta));

            DEBUGMSGTL(("access:route", "    dev %s\n",
                        if_indextoname(entry->if_index, b)));
            break;

        case RTA_DST:
            memcpy(entry->rt_dest, RTA_DATA(rta), len);
            DEBUGMSGTL(("access:route", "    to %s/%u\n",
                        inet_ntop(r->rtm_family, entry->rt_dest,
                                  b, sizeof(b)), r->rtm_dst_len));
            break;

        case RTA_GATEWAY:
            entry->rt_type = INETCIDRROUTETYPE_REMOTE;
            memcpy(entry->rt_nexthop, RTA_DATA(rta), len);
            DEBUGMSGTL(("access:route", "    via %s\n",
                        inet_ntop(r->rtm_family, entry->rt_nexthop,
                                  b, sizeof(b))));
            break;

        case RTA_PRIORITY:
            entry->rt_metric1 = *(uint32_t *) RTA_DATA(rta);
            DEBUGMSGTL(("access:route", "    metric %d\n",
                        entry->rt_metric1));
            break;

        default:
            DEBUGMSGTL(("access:route", "unhandled rta_type %u\n", rta->rta_type));
            break;
        }

        rta = RTA_NEXT(rta, len);
    }
    DEBUGMSGTL(("access:route", "    if_index %u\n", entry->if_index));
    DEBUGMSGTL(("access:route", "    type %u (rtm_type %u)\n", entry->rt_type, r->rtm_type));

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
    entry->rt_tos = r->rtm_tos;
    if (r->rtm_family == AF_INET)
        entry->rt_mask = ~0 << (32 - r->rtm_dst_len);
    DEBUGMSGTL(("access:route", "    mask 0x%x\n", entry->rt_mask));
    DEBUGMSGTL(("access:route", "    tos %u\n", entry->rt_tos));
#endif

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
    /*
     * inetCidrRoutePolicy OBJECT-TYPE
     * SYNTAX     OBJECT IDENTIFIER
     * MAX-ACCESS not-accessible
     * STATUS     current
     * DESCRIPTION
     * "This object is an opaque object without any defined
     * semantics.  Its purpose is to serve as an additional
     * index which may delineate between multiple entries to
     * the same destination.  The value { 0 0 } shall be used
     * as the default value for this object."
     */
    /*
     * on linux, many routes all look alike, and would have the same
     * indexed based on dest and next hop. So we use the if index,
     * routing protocol, and scope as the policy
     * to distinguise between them. Hopefully this is unique.
     */
    entry->rt_policy = calloc(3, sizeof(oid));
    entry->rt_policy[0] = entry->if_index;
    entry->rt_policy[1] = r->rtm_protocol;
    entry->rt_policy[2] = r->rtm_scope;
    entry->rt_policy_len = sizeof(oid) * 3;
    DEBUGMSGTL(("access:route", "    policy0 %u\n", entry->rt_policy[0]));
    DEBUGMSGTL(("access:route", "    policy1 %u\n", entry->rt_policy[1]));
    DEBUGMSGTL(("access:route", "    policy2 %u\n", entry->rt_policy[2]));
#endif
}


/**
 * @internal
 * Read all route information from netlink socket
 *
 * Used during initialization to read entire route table for the
 * specifed family.
 *
 * @param access Access structure
 * @param family Read route of the specifid address family
 *
 * @retval 0    : Success.
 * @retval -1   : Error.
 */
static int
_load_netlink(netsnmp_route_access* access, int family)
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
    netsnmp_container *container = access->magic;

    DEBUGMSGTL(("access:netlink:route", "%s %s called\n", __func__,
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
    hdr->nlmsg_seq = ++nlseq;

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
        return -1;
    }

    /*
     * Now listen for response
     */
    do {
        struct nlmsghdr *n;

        /*
         * Get the message
         */
        count = recv(nlsk, rcvbuf, sizeof(rcvbuf), MSG_DONTWAIT);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            snmp_log_perror("recv netlink");
            rc = -1;
            access->synchronized = 0;
            if (access->cache_expired != NULL)
                *access->cache_expired = 1;
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
	    entry = netsnmp_access_route_entry_create();
	    if (NULL == entry) {
		    DEBUGMSGTL(("access:netlink:route", "unable to allocate entry\n"));
		    break;
	    }

	    entry->ns_rt_index = ++(access->index);
	    fillup_entry_info(entry, rtm, RTM_PAYLOAD(n));
	    if (access->update_hook)
		    access->update_hook(access, entry);
	    else {
		    DEBUGMSGTL(("access:netlink:route",
				"no update hook: insert into container failed.\n"));
		    netsnmp_access_route_entry_free(entry);
		    rc = -1;
		    break;
	    }

	    DEBUGMSGTL(("access:netlink:route", "route inserted\n"));
        }

        if (rc < 0)
            break;

    } while (!end_of_message);

    close(nlsk);
    return rc;
}


/**
 * Load route cache from system
 *
 * @param access Pointer to data access structure
 *
 * @retval 0  : Success
 * @retval -1 : Error
 */
int netsnmp_access_route_load(netsnmp_route_access *access)
{
    int r;

    DEBUGMSGTL(("access:netlink:route:load", "load route cache\n"));

    if (NULL == access) {
        snmp_log(LOG_ERR, "invalid data access to load route cache\n");
        return -1;
    }

    if (access->synchronized) {
        DEBUGMSGTL(("access:netlink:route", "already synchronized\n"));
        return 0;
    }

    DEBUGMSGTL(("access:netlink:route", "synchronizing route table\n"));

    access->index = 0;
    access->synchronized = 0;
    r = _load_netlink(access, AF_INET);

#ifdef NETSNMP_ENABLE_IPV6
    if((0 != r) || (access->load_flags & NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY))
        return r;

    r = _load_netlink(access, AF_INET6);
#endif

    access->synchronized = 1;
    return r;
}

/**
 * Unload route cache
 *
 * @param access Pointer to data access structure
 *
 * @retval 0  : Always
 */
int netsnmp_access_route_unload(netsnmp_route_access *access)
{
    DEBUGMSGTL(("access:netlink:route:unload", "unload route cache\n"));
    access->synchronized = 0;
    return 0;
}

/**
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

/**
 * delete an entry
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
