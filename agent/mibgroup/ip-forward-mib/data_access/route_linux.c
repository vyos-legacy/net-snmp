/*
 *  Interface MIB architecture support
 *
 * $Id: route_linux.c 16381 2007-05-17 21:53:28Z hardaker $
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

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/*
 * Get routing table via netlink
 */

static void
_netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
	if (rta->rta_type <= max)
	    tb[rta->rta_type] = rta;
	rta = RTA_NEXT(rta,len);
    }
}


static int 
_get_route(struct nlmsghdr *n, void *arg1, void *arg2)
{
    struct rtmsg *r = NLMSG_DATA(n);
    netsnmp_container* container = arg1;
    u_long *index = arg2;
    netsnmp_route_entry *entry = NULL;
    int len = n->nlmsg_len;
    struct rtattr * tb[RTA_MAX+1];
    void *dest;
    void *gate;
    void *src = NULL;
    char anyaddr[16] = { 0 };
    
    if (n->nlmsg_type != RTM_NEWROUTE) {
	snmp_log(LOG_ERR, "netlink got wrong type %d response to get route\n",
		 n->nlmsg_type);
	return -1;
    }

    len -= NLMSG_LENGTH(sizeof(*r));
    if (len < 0) {
	snmp_log(LOG_ERR, "netlink got truncated response to get route\n");
	return -1;
    }

    if (r->rtm_flags & RTM_F_CLONED)
	return 0;

    _netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
    if (r->rtm_type != RTN_UNICAST)
	return 0;

    entry = netsnmp_access_route_entry_create();
    /*
     * arbitrary index
     */
    entry->ns_rt_index = ++(*index);

    if (tb[RTA_OIF])
	entry->if_index = *(unsigned int*)RTA_DATA(tb[RTA_OIF]);
    else
	entry->if_index = 0;

    if (tb[RTA_DST])
	dest = RTA_DATA(tb[RTA_DST]);
    else
	dest = anyaddr;

    if (tb[RTA_PREFSRC])
	src = RTA_DATA(tb[RTA_PREFSRC]);

    if (tb[RTA_GATEWAY]) {
	gate = RTA_DATA(tb[RTA_GATEWAY]);
	entry->rt_type = INETCIDRROUTETYPE_REMOTE;
    } else {
	entry->rt_type = INETCIDRROUTETYPE_LOCAL;
	gate = anyaddr;
    }

    entry->rt_proto = (r->rtm_protocol == RTPROT_REDIRECT)
	? IANAIPROUTEPROTOCOL_ICMP : IANAIPROUTEPROTOCOL_LOCAL;
	
    if (tb[RTA_PRIORITY])
	entry->rt_metric1 = *(int *) RTA_DATA(tb[RTA_PRIORITY]);

    if (r->rtm_family == AF_INET) {
	entry->rt_pfx_len = r->rtm_dst_len;
#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
	entry->rt_mask = ~0 << r->rtm_dst_len;
        /** entry->rt_tos = XXX; */
        /** rt info ?? */
#endif
        entry->rt_dest_type = INETADDRESSTYPE_IPV4;
        entry->rt_dest_len = 4;
        memcpy(entry->rt_dest, dest, 4);

	entry->rt_nexthop_type = INETADDRESSTYPE_IPV4;
        entry->rt_nexthop_len = 4;
        memcpy(entry->rt_nexthop, gate, 4);

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
         * on linux, default routes all look alike, and would have the same
         * indexed based on dest and next hop. So we use the if index
         * as the policy, to distinguise between them. Hopefully this is
         * unique.
         * xxx-rks: It should really only be for the duplicate case, but that
         *     would be more complicated thanI want to get into now. Fix later.
         */
        if (dest == anyaddr) {
            entry->rt_policy = &entry->if_index;
            entry->rt_policy_len = 1;
            entry->flags |= NETSNMP_ACCESS_ROUTE_POLICY_STATIC;
        }
#endif
    } 
#ifdef NETSNMP_ENABLE_IPV6
    if (r->rtm_family == AF_INET6) {
        entry->rt_pfx_len = r->rtm_dst_len;
        entry->rt_dest_type = INETADDRESSTYPE_IPV6;
        entry->rt_dest_len = 16;
	memcpy(entry->rt_dest, dest, 16);

        entry->rt_nexthop_type = INETADDRESSTYPE_IPV6;
        entry->rt_nexthop_len = 16;
	memcpy(entry->rt_nexthop, gate, 16);

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
         * on linux, default routes all look alike, and would have the same
         * indexed based on dest and next hop. So we use our arbitrary index
         * as the policy, to distinguise between them.
         */
        entry->rt_policy = &entry->ns_rt_index;
        entry->rt_policy_len = 1;
        entry->flags |= NETSNMP_ACCESS_ROUTE_POLICY_STATIC;
#endif
    }
#endif

    /*
     * insert into container
     */
    if (CONTAINER_INSERT(container, entry) < 0) {
	DEBUGMSGTL(("access:route:container", "error with route_entry: insert into container failed.\n"));
	netsnmp_access_route_entry_free(entry);

    }
    return 0;
}

static int
_netlink_open(int protocol)
{
    int fd;
    int rcvbuf = 32768;
    struct sockaddr_nl snl = { .nl_family = AF_NETLINK };

    fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (fd < 0) {
	snmp_log_perror("Cannot open netlink socket");
	return -1;
    }
	
    /* increase default rx buffer for performance */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
	snmp_log_perror("netlink SO_RCVBUF");
	close(fd);
	return -1;
    }

    if (bind(fd, (struct sockaddr*)&snl, sizeof(snl)) < 0) {
	snmp_log_perror("Cannot bind netlink socket");
	close(fd);
	return -1;
    }

    return fd;
}

static int 
_netlink_dump_request(int fd, int family, int type)
{
    struct {
	struct nlmsghdr nlh;
	struct rtgenmsg g;
    } req = {
	.nlh = {
	    .nlmsg_len  = sizeof(req),
	    .nlmsg_type = type,
	    .nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST,
	    .nlmsg_seq = time(NULL),
	},
	.g = { .rtgen_family = family },
    };

    return send(fd, &req, sizeof(req), 0);
}

static int 
_netlink_dump_filter(int fd, 
		     int (*filter)(struct nlmsghdr *, void *, void *),
		     void *arg1, void *arg2)
{
    int status;
    char buf[16384];

    do {
	struct nlmsghdr *h;

	status = recv(fd, buf, sizeof(buf), 0);
	if (status < 0) {
	    if (errno == EINTR || errno == EAGAIN)
		continue;

	    snmp_log_perror("netlink recv");
	    return -1;
	}

	if (status == 0) {
	    snmp_log(LOG_ERR, "EOF on netlink\n");
	    return -1;
	}

	for (h = (struct nlmsghdr*)buf;
	     NLMSG_OK(h, status);
	     h = NLMSG_NEXT(h, status)) {
	    int rc;

	    if (h->nlmsg_type == NLMSG_DONE)
		return 0;

	    if (h->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
		if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
		    snmp_log(LOG_ERR, "truncated message %u < %lu\n",
			     h->nlmsg_len, NLMSG_LENGTH(sizeof(struct nlmsgerr)));
		} else {
		    errno = -err->error;
		    snmp_log_perror("RTNETLINK answers");
		}
		return -1;
	    }

	    rc = filter(h, arg1, arg2);
	    if (rc < 0)
		return rc;

	}

    } while (status == 0);

    snmp_log(LOG_ERR, "!!!Remnant of size %d\n", status);
    return -1;
}


static int
_load_ipv4(netsnmp_container* container, u_long *index )
{
    int             fd;

    DEBUGMSGTL(("access:route:container",
		"route_container_arch_load ipv4\n"));

    netsnmp_assert(NULL != container);

    fd = _netlink_open(NETLINK_ROUTE);
    if (fd < 0)
	return -1;

    if (_netlink_dump_request(fd, AF_INET, RTM_GETROUTE) < 0) {
	snmp_log_perror("netlink send");
	close(fd);
	return -2;
    }

    if (_netlink_dump_filter(fd, _get_route, container, index) < 0) {
	close(fd);
	return -3;
    }

    close(fd);
    return 0;
}

#ifdef NETSNMP_ENABLE_IPV6
static int
_load_ipv6(netsnmp_container* container, u_long *index )
{
    int fd;

    fd = _netlink_open(NETLINK_ROUTE);
    if (fd < 0)
	return -1;

    if (_netlink_dump_request(fd, AF_INET6, RTM_GETROUTE) < 0) {
	snmp_log_perror("netlink send");
	close(fd);
	return -2;
    }

    if (_netlink_dump_filter(fd, _get_route, container, index) < 0) {
	close(fd);
	return -3;
    }

    close(fd);
    return 0;
}
#endif

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
                "route_container_arch_load (flags %p)\n", load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_route\n");
        return -1;
    }

    rc = _load_ipv4(container, &count);
    
#ifdef NETSNMP_ENABLE_IPV6
    if((0 != rc) || (load_flags & NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY))
        return rc;

    /*
     * load ipv6. ipv6 module might not be loaded,
     * so ignore -2 err (file not found)
     */
    rc = _load_ipv6(container, &count);
    if (-2 == rc)
        rc = 0;
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


