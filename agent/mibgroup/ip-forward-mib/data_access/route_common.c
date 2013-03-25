/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/route.h>

/**---------------------------------------------------------------------*/
/*
 * external per-architecture functions prototypes
 *
 * These shouldn't be called by the general public, so they aren't in
 * the header file.
 */
extern int
netsnmp_arch_route_create(netsnmp_route_entry *entry);
extern int
netsnmp_arch_route_delete(netsnmp_route_entry *entry);


/**---------------------------------------------------------------------*/
/*
 * access functions
 */

/**
 * Create and initialize route access structure
 *
 * @param init_flags Initialization flags
 * @param update_hook Callback to update cache
 * @param gc_hook Callback to clean out old cache data
 * @param cache_flags Initialize cache flags (optional)
 * @param cache_expired Initial cache expired flag
 *
 * @remark
 * Called from inetCidrRouteTable_container_init()
 *
 * @retval !NULL  : pointer to created route access structure.
 * @retval NULL   : error.
 */
netsnmp_route_access *
netsnmp_access_route_create(u_int init_flags,
                            NetsnmpAccessRouteUpdate *update_hook,
                            int *cache_flags,
                            char *cache_expired)
{
    netsnmp_route_access *access;

    DEBUGMSGTL(("access:route:create", "create route access\n"));

    access = SNMP_MALLOC_TYPEDEF(netsnmp_route_access);
    if (NULL == access) {
        snmp_log(LOG_ERR,"malloc error in %s\n", __func__);
        return NULL;
    }

    access->magic = NULL;
    access->arch_magic = NULL;
    access->update_hook = update_hook;
    access->synchronized = 0;

    if (init_flags & NETSNMP_ACCESS_ROUTE_CREATE_IPV4_ONLY)
	    access->load_flags |= NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY;

    if (cache_flags != NULL)
        *cache_flags |= NETSNMP_CACHE_RESET_TIMER_ON_USE;
    access->cache_expired = cache_expired;

    return access;
}


/**
 * Delete route access structure and accociated memory
 *
 * @param access Pointer to data access structure to delete
 *
 * @retval 0 : Always
 */
int netsnmp_access_route_delete(netsnmp_route_access *access)
{
    DEBUGMSGTL(("access:netlink:route:delete", "delete route access\n"));

    if (NULL == access)
        return 0;

    netsnmp_access_route_unload(access);
    free(access);

    return 0;
}


/**---------------------------------------------------------------------*/
/*
 * route entry functions
 */
/** create route entry
 *
 * @note:
 *  if you create a route for entry into a container of your own, you
 *  must set ns_rt_index to a unique index for your container.
 */
netsnmp_route_entry *
netsnmp_access_route_entry_create(void)
{
    netsnmp_route_entry *entry;

    DEBUGMSGTL(("entry:route:create", "create route entry\n"));

    entry = SNMP_MALLOC_TYPEDEF(netsnmp_route_entry);
    if(NULL == entry) {
        snmp_log(LOG_ERR, "could not allocate route entry\n");
        return NULL;
    }

    entry->oid_index.oids = &entry->ns_rt_index;
    entry->oid_index.len = 1;

    entry->rt_metric1 = -1;
    entry->rt_metric2 = -1;
    entry->rt_metric3 = -1;
    entry->rt_metric4 = -1;
    entry->rt_metric5 = -1;

    /** entry->row_status? */

    return entry;
}

/**
 */
void
netsnmp_access_route_entry_free(netsnmp_route_entry * entry)
{
    DEBUGMSGTL(("entry:route:free", "free route entry\n"));

    if (NULL == entry)
        return;

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
    if ((NULL != entry->rt_policy) &&
        !(entry->flags & NETSNMP_ACCESS_ROUTE_POLICY_STATIC))
        free(entry->rt_policy);
#endif
#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
    if (NULL != entry->rt_info)
        free(entry->rt_info);
#endif

    free(entry);
}


/**
 * update underlying data store (kernel) for entry
 *
 * @retval  0 : success
 * @retval -1 : error
 */
int
netsnmp_access_route_entry_set(netsnmp_route_entry * entry)
{
    int rc = SNMP_ERR_NOERROR;

    if (NULL == entry) {
        netsnmp_assert(NULL != entry);
        return -1;
    }
    
    /*
     *
     */
    if (entry->flags & NETSNMP_ACCESS_ROUTE_CREATE) {
        rc = netsnmp_arch_route_create(entry);
    }
    else if (entry->flags & NETSNMP_ACCESS_ROUTE_CHANGE) {
        /** xxx-rks:9 route change not implemented */
        snmp_log(LOG_ERR,"netsnmp_access_route_entry_set change not supported yet\n");
        rc = -1;
    }
    else if (entry->flags & NETSNMP_ACCESS_ROUTE_DELETE) {
        rc = netsnmp_arch_route_delete(entry);
    }
    else {
        snmp_log(LOG_ERR,"netsnmp_access_route_entry_set with no mode\n");
        netsnmp_assert(!"route_entry_set == unknown mode"); /* always false */
        rc = -1;
    }
    
    return rc;
}

/**
 * copy an  route_entry
 *
 * @retval -1  : error
 * @retval 0   : no error
 */
int
netsnmp_access_route_entry_copy(netsnmp_route_entry *lhs,
                                netsnmp_route_entry *rhs)
{
#if 0 /* no arch stuff in route (yet) */
    int rc;

    /*
     * copy arch stuff. we don't care if it changed
     */
    rc = netsnmp_arch_route_entry_copy(lhs,rhs);
    if (0 != rc) {
        snmp_log(LOG_ERR,"arch route copy failed\n");
        return -1;
    }
#endif

    lhs->if_index = rhs->if_index;

    lhs->rt_dest_len = rhs->rt_dest_len;
    memcpy(lhs->rt_dest, rhs->rt_dest, rhs->rt_dest_len);
    lhs->rt_dest_type = rhs->rt_dest_type;

    lhs->rt_nexthop_len = rhs->rt_nexthop_len;
    memcpy(lhs->rt_nexthop, rhs->rt_nexthop, rhs->rt_nexthop_len);
    lhs->rt_nexthop_type = rhs->rt_nexthop_type;

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
    if (NULL != lhs->rt_policy) {
        if (NETSNMP_ACCESS_ROUTE_POLICY_STATIC & lhs->flags)
            lhs->rt_policy = NULL;
        else {
            SNMP_FREE(lhs->rt_policy);
        }
    }
    if (NULL != rhs->rt_policy) {
        if ((NETSNMP_ACCESS_ROUTE_POLICY_STATIC & rhs->flags) &&
            ! (NETSNMP_ACCESS_ROUTE_POLICY_DEEP_COPY & rhs->flags)) {
            lhs->rt_policy = rhs->rt_policy;
        }
        else {
            snmp_clone_mem((void **) &lhs->rt_policy, rhs->rt_policy,
                           rhs->rt_policy_len * sizeof(oid));
        }
    }
    lhs->rt_policy_len = rhs->rt_policy_len;
#endif

    lhs->rt_pfx_len = rhs->rt_pfx_len;
    lhs->rt_type = rhs->rt_type;
    lhs->rt_proto = rhs->rt_proto;

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
    SNMP_FREE(lhs->rt_info);
    if (NULL != rhs->rt_info)
        snmp_clone_mem((void **) &lhs->rt_info, rhs->rt_info,
                       rhs->rt_info_len * sizeof(oid));
    lhs->rt_info_len = rhs->rt_info_len;

    lhs->rt_mask = rhs->rt_mask;
    lhs->rt_tos = rhs->rt_tos;
#endif

    lhs->rt_age = rhs->rt_age;
    lhs->rt_nexthop_as = rhs->rt_nexthop_as;

    lhs->rt_metric1 = rhs->rt_metric1;
    lhs->rt_metric2 = rhs->rt_metric2;
    lhs->rt_metric3 = rhs->rt_metric3;
    lhs->rt_metric4 = rhs->rt_metric4;
    lhs->rt_metric5 = rhs->rt_metric5;

    lhs->flags = rhs->flags;
   
    return 0;
}
