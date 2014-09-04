
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "strldef.h"

#include "common.h"
#include "module.h"

#include "walk4rsnetwork.h"



static struct list_head * network_malloc(void)
{
	struct walk4rsnetwork *network;

	if ((network = calloc(1, sizeof(*network))) == NULL)
		return NULL;

	return &network->list;
}

static void network_free(struct list_head *list)
{
	struct walk4rsnetwork *network = list_entry(list, struct walk4rsnetwork, list);
	free(network);
}

static int network_analyse(xmlNodePtr pnode, struct list_head *list)
{
	struct walk4rsnetwork *network = list_entry(list, struct walk4rsnetwork, list);

	m_analyse_common(pnode, network, ipaddr);
	m_analyse_common(pnode, network, netmask);

	return 0;
}

static int network_restore(xmlNodePtr pnode, struct list_head *list)
{
	struct walk4rsnetwork *network = list_entry(list, struct walk4rsnetwork, list);

	m_restore_common(pnode, network, ipaddr);
	m_restore_common(pnode, network, netmask);

	return 0;
}

static int network_set(struct list_head *list, 
		const char *name, 
		const char *attr, 
		const char *value)
{
	struct walk4rsnetwork *network = list_entry(list, struct walk4rsnetwork, list);
	char ip[STR_IP_LEN], netmask[STR_NETMASK_LEN];

	if (name[0] == 0) {
		return -EINVAL;
	}

	if (strcmp(name, "/") == 0) {
		return -EINVAL;
	}

	if  (network->ipaddr[0] == '\0') {
		get_ip_netmask2(name, ip, netmask);
		m_set_common(network, ipaddr, "ipaddr", ip);
		m_set_common(network, netmask, "netmask", netmask);
	}

	return 0;
}

static int network_compare(struct list_head *list, const char *name)
{
	struct walk4rsnetwork *network = list_entry(list, struct walk4rsnetwork, list);
	char ip[STR_IP_LEN], netmask[STR_NETMASK_LEN];

	get_ip_netmask2(name, ip, netmask);

	return strcmp(network->ipaddr, ip);
}

static struct module walk4rs_network_module = {
	.m_root		= "loadbalance",
	.m_desc 	= "walk4rsnetwork",
	.m_malloc 	= network_malloc,
	.m_free 	= network_free,
	.m_analyse 	= network_analyse,
	.m_restore 	= network_restore,
	.m_compare 	= network_compare,
	.m_set 		= network_set,
};


extern int module_init_walk4rsnetwork(void)
{
	module_register(NULL, &walk4rs_network_module);
	return 0;
}
#if 0
extern int config_snmp_merge(void)
{
	LIST_HEAD(head);
	struct list_head *list;
	struct snmp *snmp;

	module_get_queue(&head, "snmp", "smartsnmp");

	if (list_empty(&head)) {
		if ((list = snmp_malloc()) == NULL) {
			return 0;
		}
		snmp = list_entry(list, struct snmp, list);
		strcpy(snmp->name, "smartsnmp");
		strcpy(snmp->enable, "off");
		list_add_tail(list, &head);
		module_save_queue(&head, "snmp");
	}
	module_purge_queue(&head, "snmp");

	return 0;
}
#endif
