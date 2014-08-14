

#ifndef __SMARTGRID_COMMON_POOL_H__
#define __SMARTGRID_COMMON_POOL_H__


#include <string.h>
#include "common/list.h"

#define VM_TYPE_VMWARE	"vmware"
#define VM_TYPE_XEN		"xenserver"
struct rserver {
	struct list_head list;
	//char address[64];		/* form: 192.168.10.7:8888 */
	struct sockaddr_storage address;
	char maxconn[10];
	char bandwidth[10];
	char maxreq[10];
	char weight[4];
	char healthcheck[32];		/* realserver healthcheck name */
	char enable[32];		/* yes,no/on,off */
	char id[32];			/* server id, used by bandwidth limit */
	/** Delete:  up -> draining -> (nil) 
	 *            + -> (nil)
	 *
	 *  Disable: up -> disabling -> off
	 *            + -> off
	 **/
	char state[16];			
	/* used for Elastic */
	struct {
		char rscenter[256];		/* Resource scheduling center */
		char vmdatacenter[256];	/* VCenter->rscenter */
		char vmxpath[256];		/* vmware path */
		char uuid[256];		/* xen uuid */
		char vmname[256];	/* used for vcenter */
		char vmstate[256];	/* used for vcenter */
	};

	/* 
	 * SNMP instance for snmpwalk get cpu and memory
	 * old added handle element for snmpwalk
	 * @zhangly2014.8.6
	 */
	struct {
		char snmp_check[32];	/* check snmp state:vilad,in- */
		char snmp_version[32];	/* snmp version of realserver */
		char name[32];			/* snmp name */
		char snmp_enable[32];	/* on, off */
		char community[32];		/* community */
		char securelevel[32];	/* noAuthNoPriv|authNoPriv|authPriv */
		char authProtocol[32];		/* SNMPv3 auth type, MD5 or SHA1 */
		char trap_enable[32];   /* control snmptrap */
		char trap_manager[32];  /* manager ip */
		char trap_v3_engineid[32];			/* trap v3 engine id */
		char trap_v3_username[32];			/* trap v3 username */
		char trap_v3_password[32];			/* trap v3 password */
		char trap_v3_privacy_protocol[32];	/* DES, AES */
		char trap_v3_privacy_password[32];	/* privacy password */
		char username[64];		/* authencation usm_name */
		char password[64];		/* authencation password */
		char cpu[32];			/* percent of cpu free */
		char memory[32];		/* percent of memory free */
	};
};

static inline int rserver_enable(struct rserver *rs)
{
	return strlen(rs->enable) && (!strcmp(rs->enable, "on")
				|| !strcmp(rs->enable, "yes"));
}
struct apppool {
	struct list_head list;

	char name[64];
	char type[64];			/** ipv4 or ipv6 **/
	struct list_head realserver_head;
	char healthcheck[64];		/* application pool healthcheck name */
	/*vmware stuff, we only support one vcenter. */
	struct {
		char vmtype[32];			/** vmware or xen **/
		char vmenable[32];		/* yes,no/on,off */
		char vmaddress[128];		/* form: https://192.168.10.208:8333/sdk */
		char vmusername[128];		/* vmware server username */
		char vmpassword[128];		/* vmware server password */

		char vminterval[32];
		char vmcount[32];
	};

	/* used for vcenter */
	struct {
		char vmvcenter[128];
		char vmdatacenter[128];	/* used for vcenter */
		char vmhost[128];		/* used for vcenter */
		char vmport[10];		/* used for vcenter */
	};
	char alive_vm[10]; /*used for Elastic*/
};

extern int module_init_apppool(void);
extern int add_realserver_to_apppool(const char *poolname, const char *value);
extern struct apppool * apppool_search(struct list_head *head, const char *name);
extern struct rserver * realserver_search(struct list_head *head, const char *name);
extern int update_pool_rserver_unknown_state(struct list_head *apppool_head);
extern struct apppool * apppool_copy(const struct apppool *src,  struct apppool **dst);
extern void apppool_free(struct list_head *list);


/** for vserver.c **/
extern struct list_head *apppool_malloc(void);



/**RETURN:
1: rserver is daining or disabling 
 **/
static inline int rserver_draining_or_disabling(struct rserver *rs)
{
	return strcmp(rs->state, "draining")==0 || 
		strcmp(rs->state, "disabling")==0;
}


#endif
