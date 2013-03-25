/*
 * route data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_ROUTE_H
#define NETSNMP_ACCESS_ROUTE_H

# ifdef __cplusplus
extern          "C" {
#endif

/**---------------------------------------------------------------------*/
#define NETSNMP_ACCESS_ROUTE_ADDR_IPV6_BUF_SIZE (16)
#define NETSNMP_ACCESS_ROUTE_ADDR_IPV4_BUF_SIZE (4)
#if defined( NETSNMP_ENABLE_IPV6 )
#   define NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE NETSNMP_ACCESS_ROUTE_ADDR_IPV6_BUF_SIZE
#else
#   define NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE NETSNMP_ACCESS_ROUTE_ADDR_IPV4_BUF_SIZE
#endif


/**---------------------------------------------------------------------*/
/*
 * structure definitions
 */
/*
 * netsnmp_route_entry
 *   - primary route structure for both ipv4 & ipv6
 */
typedef struct netsnmp_route_s {

   netsnmp_index oid_index;   /* MUST BE FIRST!! for container use */
   oid           ns_rt_index; /* arbitrary index */

   int       flags; /* for net-snmp use */

   oid       if_index;

    /*
     * addresses, in network byte order
     */
   u_char    rt_dest[NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE];
   u_char    rt_nexthop[NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE];

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
   /*
    * define the maximum oid length for a policy, for use by the
    * inetCidrRouteTable. Must be at least 2, for default nullOid case.
    */
#define NETSNMP_POLICY_OID_MAX_LEN  3
   oid      *rt_policy;      /* NULL should be interpreted as { 0, 0 } */
   u_char    rt_policy_len;  /* 0-128 oids */
#endif

   u_char    rt_dest_len;    /* 4 | 16 since we only do ipv4|ipv6 */
   u_char    rt_dest_type;   /* InetAddressType 0-16 */
   u_char    rt_nexthop_len; /* 4 | 16 since we only do ipv4|ipv6*/
   u_char    rt_nexthop_type;/* InetAddressType 0-16 */
   u_char    rt_pfx_len;     /* 0-128 bits */
   u_char    rt_type;        /* ip(1-4) != inet(1-5) */
   u_char    rt_proto;       /* ip(enum 1-16) ?= inet(IANAipRouteProtocol 1-17) */

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
   /** rt_info != inet_policy, because that would have made sense */
   uint8_t   rt_info_len;    /* 0-128 oids */
   oid      *rt_info;        /* NULL should be interpreted as { 0, 0 } */

   uint32_t  rt_mask;        /* ipv4 only */
   uint32_t  rt_tos;         /* Integer32 (0..2147483647) */
#endif

   uint32_t  rt_age;         /* seconds (ip == inet) */
   int32_t   rt_nexthop_as;  /* ip(int32) == inet(InetAutonomousSystemNumber) */

   int32_t   rt_metric1;
   int32_t   rt_metric2;
   int32_t   rt_metric3;
   int32_t   rt_metric4;
   int32_t   rt_metric5;

} netsnmp_route_entry;

#define NETSNMP_ACCESS_ROUTE_ENTRY_FLAG_DELETE      (0x00000001)


/**---------------------------------------------------------------------*/
/*
 * ACCESS function prototypes
 */
struct netsnmp_route_access_s;
typedef struct netsnmp_route_access_s netsnmp_route_access;

typedef void (NetsnmpAccessRouteUpdate)(netsnmp_route_access *, netsnmp_route_entry*);

struct netsnmp_route_access_s {
    void *magic;      /* pointer to container */
    void *arch_magic; /* netlink socket fd */
    int synchronized;
    unsigned int generation;
    unsigned int load_flags;
    oid index;     /* arbitrary index number of the route */
    NetsnmpAccessRouteUpdate *update_hook;
    char *cache_expired;
};



netsnmp_route_access *
netsnmp_access_route_create(u_int init_flags,
                            NetsnmpAccessRouteUpdate *update_hook,
                            int *cache_flags,
                            char *cache_expired);
#define NETSNMP_ACCESS_ROUTE_CREATE_NOFLAGS               0x0000
#define NETSNMP_ACCESS_ROUTE_CREATE_IPV4_ONLY             0x0001

int netsnmp_access_route_delete(netsnmp_route_access *access);
int netsnmp_access_route_load(netsnmp_route_access *access);
int netsnmp_access_route_unload(netsnmp_route_access *access);

/*
 * route container load and free
 */
#define NETSNMP_ACCESS_ROUTE_LOAD_NOFLAGS               0x0000
#define NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY             0x0001


/*
 * create/copy/free a route entry
 */
netsnmp_route_entry *
netsnmp_access_route_entry_create(void);

void netsnmp_access_route_entry_free(netsnmp_route_entry * entry);

int
netsnmp_access_route_entry_copy(netsnmp_route_entry *lhs,
                                netsnmp_route_entry *rhs);

/*
 * find entry in container
 */
/** not yet */

/*
 * create/change/delete
 */
int
netsnmp_access_route_entry_set(netsnmp_route_entry * entry);

/*
 * route flags
 *   upper bits for internal use
 *   lower bits indicate changed fields. see FLAG_INETCIDRROUTE* definitions in
 *         inetCidrRouteTable_constants.h
 */
#define NETSNMP_ACCESS_ROUTE_CREATE                         0x80000000
#define NETSNMP_ACCESS_ROUTE_DELETE                         0x40000000
#define NETSNMP_ACCESS_ROUTE_CHANGE                         0x20000000
#define NETSNMP_ACCESS_ROUTE_POLICY_STATIC                  0x10000000
#define NETSNMP_ACCESS_ROUTE_POLICY_DEEP_COPY               0x08000000

/* 
 * mask for change flag bits
 */
#define NETSNMP_ACCESS_ROUTE_RESERVED_BITS                  0x000001ff



/**---------------------------------------------------------------------*/

# ifdef __cplusplus
}
#endif

#endif /* NETSNMP_ACCESS_ROUTE_H */
