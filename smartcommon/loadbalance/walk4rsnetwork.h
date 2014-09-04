#ifndef __walk4rsnetwork_h__
#define __walk4rsnetwork_h__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/strldef.h"
#include "common/list.h"

/* accessible network */
struct walk4rsnetwork {
	struct list_head list;		/* pointer to next network */

	char ipaddr[STR_IP_LEN];	/* interface name, eg: ETH0 */
	char netmask[STR_NETMASK_LEN];	/* interface name, eg: ETH0 */
};

extern int module_init_walk4rsnetwork(void);
/*
 * extern int config_snmp_merge(void);
 */
#endif
