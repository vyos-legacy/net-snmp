/*
 *  Interface MIB architecture support
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/arp.h>
#include <net-snmp/data_access/interface.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <asm/types.h>

#ifdef HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>

static void
fillup_entry_info(netsnmp_arp_entry *entry, const struct ndmsg *r, int len)
{
    struct rtattr *rta;

    entry->if_index = r->ndm_ifindex;
    entry->arp_ipaddress_len = 0;
    entry->arp_physaddress_len = 0;

    for (rta  = RTM_RTA(r); RTA_OK(rta, len); rta = RTA_NEXT(rta,len)) {
        size_t len = RTA_PAYLOAD(rta);

        switch(rta->rta_type) {
        case NDA_DST:
            entry->arp_ipaddress_len = len;
            memcpy(entry->arp_ipaddress, RTA_DATA(rta), len);
            break;

        case NDA_LLADDR:
            entry->arp_physaddress_len = len;
            memcpy(entry->arp_physaddress, RTA_DATA(rta), len);
            break;
        }
    }

    switch (r->ndm_state) {
    case NUD_INCOMPLETE:
        entry->arp_state = INETNETTOMEDIASTATE_INCOMPLETE;
        break;
    case NUD_REACHABLE:
    case NUD_PERMANENT:
        entry->arp_state = INETNETTOMEDIASTATE_REACHABLE;
        break;
    case NUD_STALE:
        entry->arp_state = INETNETTOMEDIASTATE_STALE;
        break;
    case NUD_DELAY:
        entry->arp_state = INETNETTOMEDIASTATE_DELAY;
        break;
    case NUD_PROBE:
        entry->arp_state = INETNETTOMEDIASTATE_PROBE;
        break;
    case NUD_FAILED:
        entry->arp_state = INETNETTOMEDIASTATE_INVALID;
        break;
    case NUD_NONE:
        entry->arp_state = INETNETTOMEDIASTATE_UNKNOWN;
        break;
    default:
        snmp_log(LOG_ERR, "Unrecognized ARP entry state %d", r->ndm_state);
        break;
    }

    switch (r->ndm_state) {
    case NUD_INCOMPLETE:
    case NUD_FAILED:
    case NUD_NONE:
        entry->arp_type = INETNETTOMEDIATYPE_INVALID;
        break;
    case NUD_REACHABLE:
    case NUD_STALE:
    case NUD_DELAY:
    case NUD_PROBE:
        entry->arp_type = INETNETTOMEDIATYPE_DYNAMIC;
        break;
    case NUD_PERMANENT:
        entry->arp_type = INETNETTOMEDIATYPE_STATIC;
        break;
    default:
        entry->arp_type = INETNETTOMEDIATYPE_LOCAL;
        break;
    }
}

static int
_load_netlink(int sd, netsnmp_container *container, int family, u_long *index)
{
    struct {
                struct nlmsghdr n;
                struct ndmsg r;
    } req;
    int end_of_message = 0;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH (sizeof(struct ndmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.n.nlmsg_type = RTM_GETNEIGH;

    req.r.ndm_family = family;

    if(send(sd, &req, sizeof(req), 0) < 0) {
        snmp_log_perror("Sending request failed\n");
        return -1;
     }

    do {
        struct nlmsghdr *n;
        char rcvbuf[4096];
        int msglen;

        msglen = recv(sd, rcvbuf, sizeof(rcvbuf), 0);
        if (msglen < 0) {
            snmp_log_perror("Receiving netlink request failed\n");
            return -1;
       }

        if (msglen == 0) {
            snmp_log(LOG_ERR,"End of file\n");
            return -1;
        }

        /*
         * Walk all of the returned messages
         */
        for (n = (struct nlmsghdr *)rcvbuf; NLMSG_OK(n, msglen);
             n = NLMSG_NEXT(n, msglen)) {
                struct ndmsg *r;
                netsnmp_arp_entry *entry;

            if (n->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(n);
                if (n->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    snmp_log(LOG_ERR, "kernel netlink error truncated\n");
                else
                    snmp_log(LOG_ERR, "kernel netlink error %s\n",
                             strerror(-err->error));
                return -1;
            }

            if (n->nlmsg_type & NLMSG_DONE) {
                end_of_message = 1;
                break;
            }

            if (n->nlmsg_type != RTM_NEWNEIGH) {
                snmp_log(LOG_ERR, "unexpected message of type %d in nlmsg\n",
                         n->nlmsg_type);
                continue;
            }

            r = NLMSG_DATA(n);
            if (r->ndm_family != family) {
                snmp_log(LOG_ERR, "Wrong family in netlink response %d\n",
                         r->ndm_family);
                break;
            }

            if (r->ndm_state == NUD_NOARP)
                continue;

            entry = netsnmp_access_arp_entry_create();

            fillup_entry_info (entry, r, RTM_PAYLOAD(n));

            if (entry->arp_ipaddress_len == 0 ||
                entry->arp_physaddress_len == 0) {
                DEBUGMSGTL(("access:arp:load", "skipping netlink message that"
                            " did not contain valid ARP information\n"));
                netsnmp_access_arp_entry_free(entry);
                continue;
            }

            entry->ns_arp_index = *++index;
            if (CONTAINER_INSERT(container, entry) < 0) {
                DEBUGMSGTL(("access:arp:load",
                            "error arp insert into container failed.\n"));
                netsnmp_access_arp_entry_free(entry);
                return -1;
            }
        }
    } while (!end_of_message);

     return 0;
}

int
netsnmp_access_arp_container_arch_load(netsnmp_container *container)
{
    u_long          count = 0;
    int             sd, rc;

    DEBUGMSGTL(("access:arp:container", "load\n"));

    if((sd = socket (PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        snmp_log(LOG_ERR,"Unable to create netlink socket\n");
        return -2;
    }

    rc = _load_netlink(sd, container, AF_INET, &count);
 
#ifdef NETSNMP_ENABLE_IPV6
    if(rc == 0)
        rc = _load_netlink(sd, container, AF_INET6, &count);
#endif

    close(sd);
    return rc;
}
#else
/**
 */
int
netsnmp_access_arp_container_arch_load(netsnmp_container *container)
{
    int rc = 0, idx_offset = 0;
    FILE           *in;
    char            line[128];
    int             rc = 0;
    netsnmp_arp_entry *entry;
    char           arp[3*NETSNMP_ACCESS_ARP_PHYSADDR_BUF_SIZE+1];
    char           *arp_token;
    int             i;

    netsnmp_assert(NULL != container);

#define PROCFILE "/proc/net/arp"
    if (!(in = fopen(PROCFILE, "r"))) {
        snmp_log(LOG_DEBUG,"could not open " PROCFILE "\n");
        return -2;
    }

    /*
     * Get rid of the header line 
     */
    fgets(line, sizeof(line), in);

    /*
     * IP address | HW | Flag | HW address      | Mask | Device
     * 192.168.1.4  0x1  0x2   00:40:63:CC:1C:8C  *      eth0
     */
    while (fgets(line, sizeof(line), in)) {
        
        int             za, zb, zc, zd;
        unsigned int    tmp_flags;
        char            ifname[21];

        rc = sscanf(line,
                    "%d.%d.%d.%d 0x%*x 0x%x %96s %*[^ ] %20s\n",
                    &za, &zb, &zc, &zd, &tmp_flags, arp, ifname);
        if (7 != rc) {
            snmp_log(LOG_ERR, PROCFILE " data format error (%d!=12)\n", rc);
            snmp_log(LOG_ERR, " line ==|%s|\n", line);
            continue;
        }
        DEBUGMSGTL(("access:arp:container",
                    "ip addr %d.%d.%d.%d, flags 0x%X, hw addr "
                    "%s, name %s\n",
                    za,zb,zc,zd, tmp_flags, arp, ifname ));

        /*
         */
        entry = netsnmp_access_arp_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }

        /*
         * look up ifIndex
         */
        entry->if_index = netsnmp_access_interface_index_find(ifname);
        if(0 == entry->if_index) {
            snmp_log(LOG_ERR,"couldn't find ifIndex for '%s', skipping\n",
                     ifname);
            netsnmp_access_arp_entry_free(entry);
            continue;
        }

        /*
         * now that we've passed all the possible 'continue', assign
         * index offset.
         */
        entry->ns_arp_index = ++idx_offset;

        /*
         * parse ip addr
         */
        entry->arp_ipaddress[0] = za;
        entry->arp_ipaddress[1] = zb;
        entry->arp_ipaddress[2] = zc;
        entry->arp_ipaddress[3] = zd;
        entry->arp_ipaddress_len = 4;

        /*
         * parse hw addr
         */
        for (arp_token = strtok(arp, ":"), i=0; arp_token != NULL; arp_token = strtok(NULL, ":"), i++) {
            entry->arp_physaddress[i] = strtol(arp_token, NULL, 16);
        }
        entry->arp_physaddress_len = i;

        /*
         * what can we do with hw? from arp manpage:

         default  value  of  this  parameter is ether (i.e. hardware code
         0x01 for  IEEE  802.3  10Mbps  Ethernet).   Other  values  might
         include  network  technologies  such as ARCnet (arcnet) , PROnet
         (pronet) , AX.25 (ax25) and NET/ROM (netrom).
        */

        /*
         * parse mask
         */
        /* xxx-rks: what is mask? how to interpret '*'? */


        /*
         * process type
         */
        if(tmp_flags & ATF_PERM)
            entry->arp_type = INETNETTOMEDIATYPE_STATIC;
        else
            entry->arp_type = INETNETTOMEDIATYPE_DYNAMIC;

        /*
         * process status
         * if flags are 0, we can't tell the difference between
         * stale or incomplete.
         */
        if(tmp_flags & ATF_COM)
            entry->arp_state = INETNETTOMEDIASTATE_REACHABLE;
        else
            entry->arp_state = INETNETTOMEDIASTATE_UNKNOWN;

        /*
         * add entry to container
         */
        if (CONTAINER_INSERT(container, entry) < 0)
        {
            DEBUGMSGTL(("access:arp:container","error with arp_entry: insert into container failed.\n"));
            netsnmp_access_arp_entry_free(entry);
            continue;
        }
    }

    fclose(in);
    return rc;
}
#endif
