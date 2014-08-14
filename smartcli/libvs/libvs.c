

#include <arpa/inet.h>
#include <sys/stat.h>
#include <ctype.h>
#include <syslog.h>

#include "libvs.h"
#include "libpool.h"
#include "librule.h"

#include "license/license.h"
#include "common/module.h"
#include "common/common.h"
#include "common/base64.h"
#include "common/dependence.h"
#include "network/network.h"
#include "libnet/libinterface.h"

#include "libssl/libssl.h"
#include "loadbalance/apppool.h"
#include "loadbalance/vserver.h"
#include "loadbalance/rule.h"
#include "smartrule/smartrule.h"

#include "check/check.h"
#include "libcli/str_desc.h"
#include "libcli/libcli.h"
#include "network/floatip.h"

#include "gslb/gslb_listener.h"
int check_vm_limit(struct cli_def *cli, struct cli_command *c, char *str)
{
	long int val;
	
	if(check_num(cli, c, str) == CLI_ERROR){
		return CLI_ERROR;
	}
	
	val = atol(str);
	if(val <= 0) {
		return CLI_ERROR;
	}
	
	return CLI_OK;
}


int check_pool_type(struct cli_def *cli, struct cli_command *c, char *value)
{
	
	LIST_HEAD(vs_queue);
	LIST_HEAD(pool_queue);
	struct vserver *vserver;
	struct apppool *pool;
	
	module_get_queue(&vs_queue, "vserver", cli->folder->value);
	module_get_queue(&pool_queue, "apppool", value);

	if(list_empty(&vs_queue)){
		return CLI_ERROR;
	}
	
	if(list_empty(&pool_queue)){
		return CLI_ERROR;
	}

	vserver = list_entry(&vs_queue, struct vserver ,list);
	
	pool = list_entry(&pool_queue, struct apppool, list);
	

	if(strcmp(vserver->vm_enable, "on") == 0){
		if(strcmp(pool->vmenable, "on") != 0){
			printf("Can not add vm unenable pool to a vm enable vserver!\n");
			return CLI_ERROR;
		}
	} else{
		if(strcmp(pool->vmenable, "on") == 0){
			printf("Can not add vm enable pool to  a vm unenable vserver!\n");
			return CLI_ERROR;
		}
	}

	module_purge_queue(&vs_queue, "vserver");
	module_purge_queue(&pool_queue, "apppool");

	return CLI_OK;
	
}



static int get_vserver_protocol_address(char *vname, char *protocol, char *address)
{
	struct vserver *vserver;
	LIST_HEAD(queue);

	module_get_queue(&queue, "vserver", vname);

	list_for_each_entry(vserver, &queue, list) {
		strcpy(protocol, vserver->protocol);
		//strcpy(address, vserver->address);
		inet_sockaddr2address(&vserver->address, address);
	}
	module_purge_queue(&queue, "vserver");

	return 0;
}

static void show_alarm_information(struct vserver *vserver) 
{
#define _SHOW_ALARM(info) 								\
	do {										\
		printf("\n\n**************************************************\n");	\
		printf("%s\n\n", info);							\
		return;									\
	} while (0)

	/**  打印警告信息  Step1 **/
#define SHOW_ALARM1(arg, info) 								\
	do {										\
		if (vserver->arg[0] == 0) {						\
			_SHOW_ALARM("Please Set the \"" info "\" of vserver.");		\
		}									\
	} while (0)

	SHOW_ALARM1(sched, "scheduler");
	SHOW_ALARM1(protocol, "protocol");
	//SHOW_ALARM1(address, "address");
	char address[BUFSIZ];
	if (inet_sockaddr2address(&vserver->address, address) != 0) {
		_SHOW_ALARM("Please Set the \" address \" of vserver.");
		return;
	}

	/**  打印警告信息  Step2 **/
	if (strcmp(vserver->contentswitch, "on") != 0 && vserver->pool[0] == 0) {
		printf("\n\n**************************************************\n");
		printf("Please Set the \"pool\" of vserver.\n\n");
		return;
	}

	/**  打印警告信息  Step3 **/
#define SHOW_ALARM2(proto, arg, info) 							\
	do { 										\
		if (strcmp(vserver->protocol, proto) == 0 && vserver->arg[0] == 0) { 	\
			_SHOW_ALARM("Please Set the \"" info "\" of vserver."); 	\
		} 									\
	} while (0)

	SHOW_ALARM2("https", ssl_certificate, "ssl_certificate");
}




/** 重新整理vserver命令 **/
static int vserver_configure_commands(struct cli_def *cli, char *vsname);


int rule_add_get_values(struct cli_def *cli, char **values)
{
	int k = 0;
	struct rule *rule;
	LIST_HEAD(head);

	module_get_queue(&head, "rule", NULL);

	list_for_each_entry(rule, &head, list) {
		if (check_vserver_use_this_rule(rule->name, cli->folder->value) == 0) {
				values[k++] = strdup(rule->name);
		}
	}
	module_purge_queue(&head, "rule");

	return k;
}

static int rule_name_del_get_values(struct cli_def *cli, char **values)
{
	struct rule_name *rule_name;
	struct vserver *vserver;
	int k = 0;

	LIST_HEAD(queue);

	module_get_queue(&queue, "vserver", cli->folder->value);

	list_for_each_entry(vserver, &queue, list) {
		list_for_each_entry(rule_name, &vserver->rule_head, list) {
			values[k++] = strdup(rule_name->name);
		}
	}
	module_purge_queue(&queue, "vserver");

	return k;
}



static int check_rule_and_priority(struct cli_def *cli, struct cli_command *c, char *value)
{
	char *p;

	if (!value || !strlen(value))
		return CLI_ERROR;

	p = strchr(value, ' ');
	if (p) {
		if (*++p && strlen(p) > 8 && !strncmp("priority=", p, 9)) {
			p += 9;
			return check_postive_short(cli, c, p);
		}

		return CLI_ERROR;
	}

#if 0
	char protocol[16];
	char address[128];
	get_vserver_protocol_address(cli->folder->value, protocol, address);
#endif

        if (check_vserver_address_loops(cli->folder->value, NULL, NULL, value) != 0) {
		printf("Can't set this rule [%s] to vserver\n", value);
		return CLI_ERROR;
	}
#if 0
	if (check_busy_rule_address(address, value) < 0) {
		printf("Can't set this rule [%s] to vserver\n", value);
		return CLI_ERROR;
	}
#endif
	return CLI_OK;
}


// equal: return 0
static int gslb_listener_address_cmp(struct sockaddr_storage *tmp, 
					struct gslb_listener *listener)
{
	struct sockaddr_storage *tmp2 = &listener->ipaddr;
	struct sockaddr_in  *a41 = NULL, *a42 = NULL;
	struct sockaddr_in6 *a61 = NULL, *a62 = NULL;

	if (tmp->ss_family != tmp2->ss_family)
		goto out;

	if (tmp->ss_family == AF_INET) {
		a41 = (struct sockaddr_in *)tmp;
		a42 = (struct sockaddr_in *)tmp2;
		a42->sin_port = htons(atoi(listener->port));
		if (memcmp(&a41->sin_addr, &a42->sin_addr, sizeof(a41->sin_addr)) == 0
			&& a41->sin_port == a42->sin_port) 
			return 0;
	} else {
		a61 = (struct sockaddr_in6 *)tmp;
		a62 = (struct sockaddr_in6 *)tmp2;
		a62->sin6_port = htons(atoi(listener->port));
		if (memcmp(&a61->sin6_addr, &a62->sin6_addr, sizeof(a61->sin6_addr)) == 0
			&& a61->sin6_port == a62->sin6_port)
			return 0;
	}
out:
	return -1;
}

static int vserver_unused_check(struct cli_def *cli, char *ipstr)
{
	struct gslb_listener *listener = NULL;
	LIST_HEAD(head);
	struct sockaddr_storage tmp;
	int rc = CLI_OK;
	struct vserver *vserver = NULL;

	module_get_queue(&head, "vserver", cli->folder->value);
	list_for_each_entry(vserver, &head, list) {
		if (strcasecmp(vserver->protocol, "udp"))
			goto out;
		break;
	}

	memset(&tmp, 0, sizeof(tmp));
	inet_address2sockaddr(ipstr, &tmp);

	module_get_queue(&head, "gslb_listener", NULL);
	list_for_each_entry(listener, &head, list) {
		if (gslb_listener_address_cmp(&tmp, listener) == 0) {
			printf("Address [%s] is using by GSLB listener!\n", ipstr);
			rc = CLI_ERROR;
			goto err;
		}
	}
err:	
	module_purge_queue(&head, "gslb_listener");
out:
	module_purge_queue(&head, "vserver");
	return rc;
}

static int vserver_check_address(struct cli_def *cli, struct cli_command *c, char *value)
{	
	int ret = CLI_OK;
	struct vserver *vserver;
	LIST_HEAD(queue);

	char ip[STR_IP_LEN], port[STR_PORT_LEN];
	char ip1[STR_IP_LEN], port1[STR_PORT_LEN];
	char ip2[STR_IP_LEN], port2[STR_PORT_LEN];
	char mgmt_ip[STR_IP_LEN], mgmt_netmask[STR_NETMASK_LEN];

	if (vserver_unused_check(cli, value) == CLI_ERROR) 
		return CLI_ERROR;

	if (value[0] == '[') {
		return CLI_OK;
	}

	if (check_address_port(cli, c, value) != CLI_OK) {
		return CLI_ERROR;
	}

	sscanf(value, "%[^:] :%s", ip, port);
	if (check_static_ipaddr_on_vlan(ip, NULL) != 0 &&
			check_hb_enable() != 0) {
		printf("Can't set the IP address of VServer equals to the IP address of vlan when you open the HB.\n");
		return CLI_ERROR;
	}
	
	/** check mgmt ip **/
	get_interface_address("mgmt", mgmt_ip, mgmt_netmask);
	if (strcmp(mgmt_ip, ip)==0) {
		printf("ERROR: vserver's address can't be same to mgmt ip!\r\n");
	}
	
	module_get_queue(&queue, "vserver", NULL);
	list_for_each_entry(vserver, &queue, list) {
		//get_ip_port(vserver->address, ip1, port1);
		inet_sockaddr2ipport(&vserver->address, ip1, port1);
		get_ip_port(value, ip2, port2);

		if (strcasecmp(cli->folder->value, vserver->name) == 0) {
			if(strcmp(vserver->protocol, "http") == 0 ||
					strcmp(vserver->protocol, "https") == 0) {
				if (strcmp(port, "0") == 0 || strcmp(port, "*") == 0) {
					printf("ERROR : When vserver is seven layer, 0 port and full port is not be supported!\n");
					ret = CLI_ERROR;
					break;
				}
			}
		}

		if (strcmp(ip1, ip2) == 0 && strcmp(port1, port2) == 0
				&& strcasecmp(cli->folder->value, vserver->name) != 0) {
			printf("Existed IP address: %s:%s, please try another one\n",
					ip1, port1);
			ret = CLI_ERROR;
			break;
		}
	}
	module_purge_queue(&queue, "vserver");
	if (ret != CLI_OK) {
		return ret;
	}
	return CLI_OK;
}



static char *get_vserver_limit(struct vserver *vserver, char *desc)
{
	desc[0] = 0;

	if (vserver->maxconn[0] != 0) {
		sprintf(desc, "%smaxconn=%s,", desc, vserver->maxconn);
	}
	if (vserver->maxreq[0] != 0) {
		sprintf(desc, "%smaxreq=%s,", desc, vserver->maxreq);
	}
	if (vserver->bandwidth[0] != 0) {
		sprintf(desc, "%sbandwidth=%s,", desc, vserver->bandwidth);
	}

	return desc;
}

static char *get_rserver_desc_status(struct vserver *vserver, 
		struct rserver_desc *rserver_desc, char *desc)
{
	//strcpy(desc, rserver_desc->address);
	inet_sockaddr2address(&rserver_desc->address, desc);

	if (rserver_desc->alive_state[0] == 0 || 
			strcmp(rserver_desc->alive_state, "down") == 0) {
		strcat(desc, " down");
		return desc;
	}

	if (strcmp(rserver_desc->alive_state, "off") == 0) {
		strcat(desc, " off");
		return desc;
	}

	if (strcmp(rserver_desc->alive_state, "draining") == 0) {
		strcat(desc, " draining");
	} else if (strcmp(rserver_desc->alive_state, "disabling") == 0) {
		strcat(desc, " disabling");
	}

	strcat(desc, " => ");

	if (rserver_desc->connections[0] != 0) {
		sprintf(desc, "%sEC=%s,", desc, rserver_desc->connections);
	}
	if (rserver_desc->new_connections[0] != 0) {
		sprintf(desc, "%sNC=%s/s,", desc, rserver_desc->new_connections);
	}

	if (strncmp(vserver->protocol, "http", 4) == 0 && rserver_desc->requests[0] != 0) {
		sprintf(desc, "%sREQ=%s/s,", desc, rserver_desc->requests);
	}

	if (rserver_desc->flowin[0] != 0) {
		sprintf(desc, "%sFlowIN=%s/s,", desc, rserver_desc->flowin);
	}
	if (rserver_desc->flowout[0] != 0) {
		sprintf(desc, "%sFlowOUT=%s/s,", desc, rserver_desc->flowout);
	}


	return desc;
}

static char *get_vserver_status(struct vserver *vserver, char *desc)
{
	desc[0] = 0;

	if (vserver->alive_state[0] == 0 ||
			strcmp(vserver->alive_state, "down") == 0) {
		strcpy(desc, "down");
		return desc;
	}

	if (vserver->connections[0] != 0) {
		sprintf(desc, "%sEC=%s,", desc, vserver->connections);
	}
	if (vserver->new_connections[0] != 0) {
		sprintf(desc, "%sNC=%s/s,", desc, vserver->new_connections);
	}
	if (vserver->requests[0] != 0) {
		sprintf(desc, "%sREQ=%s/s,", desc, vserver->requests);
	}
	if (vserver->flowin[0] != 0) {
		sprintf(desc, "%sFlowIN=%s/s,", desc, vserver->flowin);
	}
	if (vserver->flowout[0] != 0) {
		sprintf(desc, "%sFlowOUT=%s/s,", desc, vserver->flowout);
	}
	if(strcpy(vserver->protocol, "fast-tcp") == 0 || strcpy(vserver->protocol, "udp") == 0) {	
		if (vserver->mode[0] != 0) {
			sprintf(desc, "%sMode=%s,",desc, vserver->mode);
		}
	}
	if (strcmp(vserver->protocol, "http") == 0
			|| strcmp(vserver->protocol, "https") == 0) {
		if (vserver->cache_num[0] != 0) {
			sprintf(desc, "%sCacheNum=%s,", desc, vserver->cache_num);
		}
		if (vserver->cache_lookup[0] != 0) {
			sprintf(desc, "%sCacheLookUp=%s,", desc, vserver->cache_lookup);
		}
		if (vserver->cache_hit[0] != 0) {
			sprintf(desc, "%sCacheHit=%s,", desc, vserver->cache_hit);
		}
	}

	return desc;
}
static char *get_vserver_cache(struct vserver *vserver, char *desc)
{
	desc[0] = 0;

	if (vserver->cache[0] == 0) {
		return desc;
	}

	if (vserver->cache_disksize[0] != 0) {
		sprintf(desc, "%scache_disksize=%s,", desc, vserver->cache_disksize);
	}
	if (vserver->cache_ramsize[0] != 0) {
		sprintf(desc, "%scache_ramsize=%s,", desc, vserver->cache_ramsize);
	}
	if (vserver->cache_objnum[0] != 0){
		sprintf(desc, "%scache_objnum=%s,", desc, vserver->cache_objnum);
	}
	if (vserver->cache_expire[0] != 0){
		sprintf(desc, "%scache_expire=%s,", desc, vserver->cache_expire);
	}
	if (vserver->cache_objsize[0] !=0){
		sprintf(desc, "%scache_objsize=%s,", desc, vserver->cache_objsize);
	}

	return desc;
}
static char *get_vserver_persistent(struct vserver *vserver, char *desc)
{
	desc[0] = 0;

	if (strcasecmp(vserver->protocol, "SSLBridge") == 0) {
		if (strcmp(vserver->persistent, "ip") == 0) {
			strcpy(desc, "IP+SSLID");
		} else {
			strcpy(desc, "SSLID");
		}
		return desc;
	} else if (strcasecmp(vserver->protocol, "RDPBridge") == 0) {
		if (strcmp(vserver->persistent, "ip") == 0) {
			strcpy(desc, "IP+RDPCookie");
		} else {
			strcpy(desc, "RDPCookie");
		}
		return desc;
	}

	if (vserver->persistent[0] == 0) {
		return desc;
	}

	sprintf(desc, "%s,", vserver->persistent);

	if (strcmp(vserver->persistent, "cookie") == 0 && vserver->persistent_cookie[0] != 0) {
		sprintf(desc, "%scookie_name=%s,", desc, vserver->persistent_cookie);
	}

	if (vserver->persistentgroup[0] != 0) {
		sprintf(desc, "%sgroup=%s,", desc, vserver->persistentgroup);
	}

	if (vserver->timeout[0] != 0) {
		sprintf(desc, "%stimeout=%s,", desc, vserver->timeout);
	}
	if (vserver->persistentnetmask[0] != 0) {
		sprintf(desc, "%snetmask=%s,", desc, vserver->persistentnetmask);
	}

	return desc;
}

static char *get_vserver_desc(struct vserver *vserver, char *desc)
{
	desc[0] = 0;

	/** Just for http/https **/
	if (strcmp(vserver->protocol, "http") != 0 &&
			strcmp(vserver->protocol, "https") != 0) {
		goto out;
	}

	if (strcmp(vserver->contentswitch, "on") == 0) {
		strcat(desc, "contentswitch=on,");
	}
	if (strcmp(vserver->gzip, "on") == 0) {
		strcat(desc, "gzip=on,");
	}
	if (strcmp(vserver->deflate, "on") == 0) {
		strcat(desc, "deflate=on,");
	}
	if (strcmp(vserver->cache, "on") == 0) {
		strcat(desc, "cache=on,");
	}
	if (strcmp(vserver->xforwardedfor, "on") == 0) {
		strcat(desc, "x-forwarded-for=on,");
	}
	if (strcmp(vserver->rfc2616_check, "on") == 0) {
		strcat(desc, "rfc2616-check=on,");
	}
	if (strcmp(vserver->connreuse, "on") == 0) {
		strcat(desc, "connreuse=on,");
	}

	/** ssl **/
	if (strcmp(vserver->protocol, "https") == 0){
		if(vserver->ssl_certificate[0] != 0){
			sprintf(desc, "%scertficate=%s,",
					desc, vserver->ssl_certificate);
		}
		if(vserver->ssl_offloading[0]!=0){
			sprintf(desc, "%sssl_offloading=%s,", 
					desc, vserver->ssl_offloading);
		}
		if(vserver->ssl_protocols[0]!=0){
			sprintf(desc, "%sssl_protocols=%s,", 
					desc, vserver->ssl_protocols);
		}
#if 0
		if(vserver->ssl_client_certificate[0]!=0){
			sprintf(desc, "%sssl_client_certificate=%s,", 
					desc, vserver->ssl_client_certificate);
		}
#endif
		if(vserver->ssl_verify_client[0]!=0){
			sprintf(desc, "%sssl_verify_client=%s,", 
					desc, vserver->ssl_verify_client);
		}
		if(vserver->ssl_crl[0]!=0){
			sprintf(desc, "%sssl_crl=%s,", 
					desc, vserver->ssl_crl);
		}
	}



out:
	/** for all protocols **/
	if (strcmp(vserver->transparent, "on") == 0) {
		strcat(desc, "transparent=on,");
	}

	if (strcmp(vserver->enable, "on") != 0) {
		strcat(desc, "enable=off,");
	}

	if (strcmp(vserver->waf_enable, "on") == 0) {
		strcat(desc, "waf_enable=on,");
	}

	if (strcasecmp(vserver->log_enable, "on") == 0 && vserver->log_format[0] != 0) {
		char code_buf[BUFSIZ];
		base64_decode((uint8_t *)code_buf,vserver->log_format, BUFSIZ - 1);;
		sprintf(desc, "%slog_format=%s,", desc, code_buf);
	}

	if (vserver->errpage[0] != 0) {
		sprintf(desc, "%serrpage=%s,", desc, vserver->errpage);
	}

	return desc;
}

static char *get_pool_desc(struct vserver *vserver, char *desc)
{
	desc[0] = 0;

	if (vserver->pool[0] != 0) {
		sprintf(desc, "pool=%s,", vserver->pool);
	}
	if (vserver->backpool[0] != 0) {
		sprintf(desc, "%sback-pool=%s,", desc, vserver->backpool);
	}
	return desc;
}


#define SHOW_INDEX_LINE printf(/** 16 **/ "+----------------"	\
		/** 10 **/ "+----------"			\
		/** 18 **/ "+------------------"		\
		/** 10 **/ "+----------"			\
		/** 10 **/ "+----------"			\
		/** 08 **/ "+--------"				\
		/** 00 **/ "+\r\n")

#define SHOW_DETAIL_LINE printf(/** 16 **/ "+----------------"	\
		/** 64 **/ "+------------------------------"	\
		/** -- **/ "------------------------------"	\
		/** 00 **/ "+\r\n")

static void vserver_print_index_title(void)
{
	struct show_fmt show_fmt[] = {
		{16, "VSName"},
		{10, "Protocol"},
		{18, "Address"},
		{10, "Sched"},
		{10, "Pool"},
		{8, "Enable"},
	};
	SHOW_INDEX_LINE;
	show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
	SHOW_INDEX_LINE;
}

static void vserver_print_index_content(struct vserver *vserver)
{
	char buff[BUFSIZ];
	char address[BUFSIZ];
	if (strcmp(vserver->type, "ipv6") == 0) {
		sprintf(buff, "%s (ipv6)", vserver->name);
	} else {
		strcpy(buff, vserver->name);
	}

	memset(address, 0, BUFSIZ);
	inet_sockaddr2address(&vserver->address, address);
	struct show_fmt show_fmt[] = {
		{16, buff},
		{10, vserver->protocol},
		{18, address},
		{10, vserver->sched},
		{10, vserver->pool},
		{8, vserver->enable},
	};

	show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
	SHOW_INDEX_LINE;
}


static void vserver_print_detail_content_line(const char *attr,
		const char *value) 
{
	struct show_fmt show_fmt[] = {
		{16, (char*)attr},
		{60, (char*)value},
	};
	show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
}


static void vserver_print_detail_content(struct vserver *vserver)
{
	char buff[BUFSIZ] = {0} ;
	int num = 0;
	struct apppool_desc *apppool_desc;
	struct rserver_desc *rserver_desc;
	struct rule_name *rule_name;
	struct rule *rule;
	char rname[64];
	char statements[4096];
	char address[BUFSIZ];

	SHOW_DETAIL_LINE;
	if (strcmp(vserver->type, "ipv6") == 0) {
		sprintf(buff, "%s (ipv6)", vserver->name);
	} else {
		strcpy(buff, vserver->name);
	}
	vserver_print_detail_content_line("SLB-VSName", buff);
	SHOW_DETAIL_LINE;
	vserver_print_detail_content_line("Enable", vserver->enable);
	SHOW_DETAIL_LINE;
	vserver_print_detail_content_line("Protocol", vserver->protocol);
	SHOW_DETAIL_LINE;

	memset(address, 0, sizeof(address));
	inet_sockaddr2address(&vserver->address, address);

	vserver_print_detail_content_line("Address", address);
	SHOW_DETAIL_LINE;
	vserver_print_detail_content_line("Sched", vserver->sched);
	SHOW_DETAIL_LINE;
	vserver_print_detail_content_line("Persistent", get_vserver_persistent(vserver, buff));
	SHOW_DETAIL_LINE;

	/* Use for Elastic */
	if(strcmp(vserver->vm_enable, "off") != 0 && vserver->vm_enable[0] != 0) {
		vserver_print_detail_content_line("VM conn_high", vserver->vm_conn_high);
		SHOW_DETAIL_LINE;
		vserver_print_detail_content_line("VM newconn_high", vserver->vm_newconn_high);
		SHOW_DETAIL_LINE;
		vserver_print_detail_content_line("VM band_high", vserver->vm_band_high);
		SHOW_DETAIL_LINE;
		vserver_print_detail_content_line("VM conn_low", vserver->vm_conn_low);
		SHOW_DETAIL_LINE;
		vserver_print_detail_content_line("VM newconn_low", vserver->vm_newconn_low);
		SHOW_DETAIL_LINE;
		vserver_print_detail_content_line("VM band_low", vserver->vm_band_low);
		SHOW_DETAIL_LINE;
	}
	vserver_print_detail_content_line("VM enable", vserver->vm_enable);
	SHOW_DETAIL_LINE;

	if (strcmp(vserver->contentswitch, "on") != 0) {
		vserver_print_detail_content_line("Pool", get_pool_desc(vserver, buff));
		SHOW_DETAIL_LINE;
	} 
	if (!list_empty(&vserver->rule_head)){
		/** TODO: add rule_name show here **/
		num = 0;
		rule_name = list_entry(vserver->rule_head.prev, struct rule_name, list);
		strcpy(rname, rule_name->name);
		list_for_each_entry(rule_name, &vserver->rule_head, list) {
			LIST_HEAD(head);
			module_get_queue(&head, "rule", rule_name->name);
			list_for_each_entry(rule, &head, list) {

				memset(statements, 0, 4096);
				memset(buff, 0, sizeof(buff));

				if (strlen(rule->statements)) {
					memset(buff, 0, sizeof(buff));
					base64_decode((uint8_t *)buff, rule->statements, 4095);
					strcpy(statements, buff);
				}

				struct show_fmt show_fmt[] = {
					{16, rule->name},
					{60, statements},
				};

				show_line_for_rule(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));

				SHOW_DETAIL_LINE;
			}
			module_purge_queue(&head, "rule");
		}
	}

	vserver_print_detail_content_line("Limits", get_vserver_limit(vserver, buff));
	SHOW_DETAIL_LINE;
	if (strcmp(vserver->cache, "on") == 0) {
		vserver_print_detail_content_line("Cache", get_vserver_cache(vserver, buff));
		SHOW_DETAIL_LINE;
	}
	vserver_print_detail_content_line("Notes", get_vserver_desc(vserver, buff));
	SHOW_DETAIL_LINE;
	vserver_print_detail_content_line("VS Status", get_vserver_status(vserver, buff));
	SHOW_DETAIL_LINE;
	list_for_each_entry(apppool_desc, &vserver->apppool_desc_head, list) {
		num = 0;

		if (list_empty(&apppool_desc->rserver_desc_head)) {
			char poolname[64+8];
			sprintf(poolname, "%s Status", apppool_desc->name);
			vserver_print_detail_content_line(poolname, "");
			SHOW_DETAIL_LINE;
			continue;
		}


		list_for_each_entry(rserver_desc, &apppool_desc->rserver_desc_head, list) {
			char poolname[64+8];
			if (num ++ == 0) {
				sprintf(poolname, "%s Status", apppool_desc->name);
				vserver_print_detail_content_line(poolname,
						get_rserver_desc_status(vserver, rserver_desc, buff));
			} else {
				vserver_print_detail_content_line("", 
						get_rserver_desc_status(vserver, rserver_desc, buff));
			}
		}
		SHOW_DETAIL_LINE;
	}
}

static int vserver_print_index(struct list_head *queue)
{
	struct vserver *vserver;
	vserver_print_index_title();
	list_for_each_entry(vserver, queue, list) {
		vserver_print_index_content(vserver);
	}
	return 0;
}


int vserver_print_detail(struct list_head *queue)
{
	struct vserver *vserver;
	list_for_each_entry(vserver, queue, list) {
		vserver_print_detail_content(vserver);
		show_alarm_information(vserver);
	}
	return 0;
}


static int vs_ipaddr_show(struct cli_def *cli, char *command, 
		char *argv[], int argc)
{

	struct vlan *vlan;
	struct ipaddr *ipaddr;
	LIST_HEAD(queue);
	char address[STR_IP_LEN];
	char buff[BUFSIZ];
	module_get_queue(&queue, "vlan", NULL);
	list_for_each_entry(vlan, &queue, list) {
		list_for_each_entry(ipaddr, &vlan->ipaddr_head, list) {
			inet_sockaddr2ip(&ipaddr->ipaddr, address);
			memset(buff, 0, BUFSIZ);
			sprintf(buff, "%s/%s", address, ipaddr->netmask);
			printf("ip: %s\n", buff);
		}
	}
	module_purge_queue(&queue, "vlan");

	struct ip * ip;
	struct floatip * floatip;
	char address2[STR_IP_LEN];
	LIST_HEAD(head);
	module_get_queue(&head, "floatip", "main");
	list_for_each_entry(floatip, &head, list) {
		list_for_each_entry(ip, &floatip->ip_head, list) {
			inet_sockaddr2ip(&ip->ip, address2);
			printf("ip: %s\n", address2);
		}
	}
	module_purge_queue(&head, "floatip");
	return CLI_OK;
}



#if 0
static int rule_name_show(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char *values[BUFSIZ] = { [ 0 ... BUFSIZ-1 ] = NULL };
	int ret, i;
	struct rule_name *p;

	ret = rule_name_get_values(cli, values);

#define SHOW_LINE 								\
	do { 									\
		printf("+------------+--------------------------------+\n"); \
	} while (0)


	SHOW_LINE;
	printf("|%-12s|%-32s|\n", "RuleName", "Priority");
	SHOW_LINE;

	for (i = 0; i < ret; i ++) { 

		p = (struct rule_name *)values[i];
		struct show_fmt show_fmt[] = {
			{12, p->name},
			{32, p->priority},
		};

		show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));

		SHOW_LINE;

	}

	default_free_values(values, ret);

	return CLI_OK;
}
#endif


static int vs_show(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	LIST_HEAD(queue);

	if (strcmp(command, "show") == 0) {
		cli_send_flush_state_command("vserver");
		module_get_queue(&queue, "vserver", cli->folder->value);
		vserver_print_detail(&queue);
	} else if (argc == 0) {
		/** 只打印vserver索引，不需要刷新vserver状态 **/
		module_get_queue(&queue, "vserver", NULL);
		vserver_print_index(&queue);
	} else {
		cli_send_flush_state_command("vserver");
		module_get_queue(&queue, "vserver", strtolower(argv[0]));
		vserver_print_detail(&queue);
	}
	module_purge_queue(&queue, "vserver");

	return CLI_OK;
}

static int vs_config_arg1(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char buff[BUFSIZ];
	char code_buf[BUFSIZ], resp[BUFSIZ]={0};
	int n;

	FILE *fp;

	if (strcmp(command, "cache_ramsize") == 0||
			strcmp(command, "cache_disksize") == 0) {
		n = strlen(argv[0]);
		if (isdigit(argv[0][n-1])) {
			strcat(argv[0], "M");
		}
	}
	if (argc != 1) {
		if (argc)
			fprintf(stderr, "Invalid argument \"%s\".\r\n", argv[0]);
		else
			fprintf(stderr, "\"%s\" requires an argument.\r\n", command);

		return CLI_ERROR;
	}

	if(strcmp(command, "log_format") == 0) {
		base64_encode(code_buf, BUFSIZ - 1, (const uint8_t *)argv[0], strlen(argv[0]));
		snprintf(buff, BUFSIZ, "script4 system vserver %s %s %s",
				cli->folder->value, command, code_buf);
	}else {
		snprintf(buff, BUFSIZ, "script4 system vserver %s %s %s",
				cli->folder->value, command, argv[0]);
	}

	if ((fp = popen(buff, "r")) == NULL) {
		fprintf(stderr, "Internel error!\n");
		return CLI_ERROR;
	}
	while (fgets(resp, BUFSIZ, fp) != NULL) {
		fprintf(stderr, "Invalid value! Error code:%s", resp);
		pclose(fp);
		return CLI_ERROR;
	}
	pclose(fp);

	system(buff);
	return CLI_OK;
}


/** TODO: Change to use vlan_ipaddr_should... function **/
#if 0
int get_interface_netmask_by_ipaddr(const char *ip, char *ifname, char *netmask)
{
	int found = -1;
	LIST_HEAD(iflist);

	struct ipaddr *ipaddr;
	struct interface *interface;

	module_get_queue(&iflist, "interface", NULL);

	list_for_each_entry(interface, &iflist, list) {
		list_for_each_entry(ipaddr, &interface->ipaddr_head, list) {
			if(!strcmp(ip,ipaddr->ipaddr)){
				strcpy(ifname, interface->name);
				strcpy(netmask, ipaddr->netmask);
				found = 1;
				break;
			}
		}
	}

	return found?0:-1;
}
#endif

static int vs_config_address(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	/* add address config.xml, but not add to interface */

	int ret=-1;
	char ip[STR_IP_LEN], port[STR_IP_LEN];
	char ifname[256];
	char netmask[STR_NETMASK_LEN];
	char protocol[16];
#if 0
	char address[128]; // not valid now
#endif

	if (argv[0][0] == '[') {
		return vs_config_arg1(cli, command, argv, argc);
	}

	get_ip_port(argv[0], ip, port);
#if 0
	get_vserver_protocol_address(cli->folder->value, protocol, address);
#endif

	/** layer7 support 0 or * port **/
	if (strcmp(protocol, "https") == 0 || strcmp(protocol, "http") == 0) {
		if (strcmp(port, "0") == 0 || strcmp(port, "*") == 0) {
			return CLI_ERROR;
		}
	}

	if ((ret=vlan_ipaddr_should_be_added(ifname, netmask, ip)) < 0) {
		printf("\n\n**************************************************\n");
		printf("Invalid \"address:%s\" of vserver.\n\n", argv[0]);
		return CLI_ERROR;
	}

	if (check_vserver_address_loops(cli->folder->value, argv[0], NULL, NULL) != 0) {
		printf("Can't set this address [%s] to vserver\n", argv[0]);
		return CLI_ERROR;
	}

#if 0
	if (check_busy_vserver_address(cli->folder->value, argv[0]) < 0) {
		printf("Can't set this address [%s] to vserver\n", argv[0]);
		return CLI_ERROR;
	}
#endif

	return vs_config_arg1(cli, command, argv, argc);
}

static int vs_uninit_https_cmd(struct cli_def *cli,
		struct cli_command *vserver)
{
	cli_unregister_command(cli, vserver, "ssl_offloading");
	cli_unregister_command(cli, vserver, "ssl_protocols");
	cli_unregister_command(cli, vserver, "ssl_certificate");
#if 0
	cli_unregister_command(cli, vserver, "ssl_client_certificate");
#endif
	cli_unregister_command(cli, vserver, "ssl_verify_client");
	cli_unregister_command(cli, vserver, "ssl_crl");
	return 0;
}

static int vs_config_arg(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char buff[BUFSIZ] = {0}, tmp[BUFSIZ] = {0};
	FILE *fp;

	if (argc == 1) {
		return vs_config_arg1(cli, command, argv, argc);
	}

	snprintf(buff, BUFSIZ, "script4 system vserver %s %s",
			cli->folder->value, command);

	fp = popen(buff, "r");
	if (fp == NULL) {
		fprintf(stderr, "Internal Error.\r\n");
		return CLI_ERROR;
	}

	while (fgets(tmp, BUFSIZ, fp)) {
		fprintf(stderr, "Invalid value! Error code:%s!", tmp);
		pclose(fp);
		return CLI_ERROR;
	}
	pclose(fp);

	if (strncmp(command, "contentswitch ", strlen("contentswitch ")) == 0) {
		vserver_configure_commands(cli, cli->folder->value);
	}

	if (strncmp(command, "persistent ", strlen("persistent ")) == 0) {
		vserver_configure_commands(cli, cli->folder->value);
	}

	return CLI_OK;
}

static int vs_config_sched(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	if (vs_config_arg(cli, command, argv, argc) != CLI_OK) {
		return CLI_ERROR;
	}

	return CLI_OK;
}

static int vs_pool_rs_snmp_check(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
#if 1
	struct vserver *vserver;
	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(queue);
	LIST_HEAD(pool_queue);
	char address[512] = {0};

	module_get_queue(&queue, "vserver", cli->folder->value);

	list_for_each_entry(vserver, &queue, list) {
		if (strlen(vserver->pool) == 0) {
			fprintf(stderr, "snmp need by set apppool and config real server\n");
			return CLI_ERROR;
		} else {
			module_get_queue(&pool_queue, "apppool", vserver->pool);
			list_for_each_entry(apppool, &pool_queue, list) {
				module_get_queue(&pool_queue, "apppool", vserver->pool);
				if (list_empty(&apppool->realserver_head)) {
						fprintf(stderr, "snmp need by set apppool and config real server\n");
				}
				list_for_each_entry(rserver, &apppool->realserver_head, list) {
					if (inet_sockaddr2address(&rserver->address, address) != 0) {
						fprintf(stderr, "snmp need by set apppool and config real server\n");
						return CLI_ERROR;
					}
				}
			}
		}
	}

	if (vs_config_sched(cli, command, argv, argc) != CLI_OK) {
		return CLI_ERROR;
	}
#endif
	return CLI_OK;
}
static int vs_config_verify_client(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char cmd[BUFSIZ];

	if (strcmp(command, "ssl_verify_client off") == 0 ||
			strcmp(command, "ssl_verify_client") == 0) {
		sprintf(cmd, "script4 system vserver %s ssl_verify_client ", 
				cli->folder->value);
	} else {
		/** argv[0] is 'CA' **/
		sprintf(cmd, "script4 system vserver %s ssl_verify_client useca %s", 
				cli->folder->value, argv[0]);

	}

	system(cmd);

	return CLI_OK;
}

static int vs_config_ssl_protocols(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char *pos, *pos1;
	if (strncasecmp(command, "ssl_protocols", strlen("ssl_protocols")) == 0) {
		pos = command + strlen("ssl_protocols") + 1;
		while ((pos1 = strchr(pos, ' ')) != NULL) {
			*pos1 = ',';
			pos = pos1 + 1;
		}
		vs_config_arg(cli, command, argv, argc);
	}
	return CLI_OK;
}

/** 添加参数为 on 或 off 的命令 **/
#define ADD_BOOL_COMMAND(arg, callback, desc, desc_on, desc_off) 						\
	do {													\
		struct cli_command *t = cli_register_command(cli, vserver, arg, NULL, 				\
				PRIVILEGE_PRIVILEGED, MODE_EXEC, desc);						\
		cli_register_command(cli, t, "on", callback, PRIVILEGE_PRIVILEGED, MODE_EXEC, desc_on);		\
		cli_register_command(cli, t, "off", callback, PRIVILEGE_PRIVILEGED, MODE_EXEC, desc_off);	\
	} while (0)

static int vs_init_ssl_protocols(struct cli_def *cli,
		struct cli_command *vserver)
{
	struct cli_command *t;
	/********** ssl_protocols <SSLv2/SSLv3/TLSv1> **********/
	t = cli_register_command(cli, vserver, "ssl_protocols", NULL,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_SSL_PROTOCOL);

#define ADD_SSL_PROTOCOL_1(arg11, arg12, desc11, desc12)		\
	do {									\
		struct cli_command *p;						\
		p = cli_register_command(cli, t, arg11, vs_config_ssl_protocols,\
				PRIVILEGE_PRIVILEGED, MODE_EXEC, desc11);	\
		cli_register_command(cli, p, arg12, vs_config_ssl_protocols,	\
				PRIVILEGE_PRIVILEGED, MODE_EXEC, desc12);	\
	} while (0)


#define ADD_SSL_PROTOCOL(arg1, arg2, desc1, desc2)		\
	do {							\
		ADD_SSL_PROTOCOL_1(arg1, arg2, desc1, desc2);	\
		ADD_SSL_PROTOCOL_1(arg2, arg1, desc2, desc1);	\
	} while (0)

	ADD_SSL_PROTOCOL("SSLv3", "TLSv1", LIBCLI_SSL_PROTOCOL_SSLV3,
			LIBCLI_SSL_PROTOCOL_TLSV1);
	return 0;
}




static int vs_init_https_cmd(struct cli_def *cli,
		struct cli_command *vserver)
{
	struct cli_command *t, *c;

	/********** ssl_offloading <on/off> **********/
	ADD_BOOL_COMMAND("ssl_offloading", vs_config_arg,
			LIBCLI_SSL_OFFLOADING, LIBCLI_SSL_OFFLOADING_ON,
			LIBCLI_SSL_OFFLOADING_OFF);

	/********** ssl_protocol <SSLv2/SSLv3/TLSv1> **********/
	vs_init_ssl_protocols(cli, vserver);

	/********** ssl_certificate <name> **********/
	t = cli_register_command(cli, vserver, "ssl_certificate",
			vs_config_arg1, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_SSL_CERTIFICATE);
	cli_command_add_argument(t, "<name>", NULL);
	cli_command_setvalues_func(t, ssl_get_values,
			default_free_values);

#if 0
	/********** ssl_client_certificate <name> **********/
	t = cli_register_command(cli, vserver, "ssl_client_certificate",
			vs_config_arg1, PRIVILEGE_PRIVILEGED,
			MODE_EXEC,
			LIBCLI_SSL_CLIENT_CERTIFICATE);
	cli_command_add_argument(t, "[name]", NULL);
	cli_command_setvalues_func(t, ssl_get_values,
			default_free_values);
#endif

	/********** ssl_verify_client useca <ca> **********/
	t = cli_register_command(cli, vserver, "ssl_verify_client",
			NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC,
			LIBCLI_SSL_VERIFY_CLIENT);
	c = cli_register_command(cli, t, "off",
			vs_config_verify_client, PRIVILEGE_PRIVILEGED,
			MODE_EXEC,
			LIBCLI_SSL_VERIFY_CLIENT_OFF);
	c = cli_register_command(cli, t, "useca",
			vs_config_verify_client, PRIVILEGE_PRIVILEGED,
			MODE_EXEC,
			LIBCLI_SSL_VERIFY_CLIENT_ON);
	cli_command_add_argument(c, "<CA_name>", NULL);
	cli_command_setvalues_func(c, CA_get_values,
			default_free_values);

#if 0
	ADD_BOOL_COMMAND("ssl_verify_client", vs_config_arg,
			LIBCLI_SSL_VERIFY_CLIENT, LIBCLI_SSL_VERIFY_CLIENT_ON,
			LIBCLI_SSL_VERIFY_CLIENT_OFF);
#endif

	/********** ssl_crl <name> **********/
	t = cli_register_command(cli, vserver, "ssl_crl", vs_config_arg,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_SSL_VSERVER_CRL);
	cli_command_add_argument(t, "[name]", NULL);
	cli_command_setvalues_func(t, crl_get_values,
			default_free_values);


	return 0;
}


static int vs_uninit_cache_cmd(struct cli_def *cli,
		struct cli_command *vserver)
{
	cli_unregister_command(cli, vserver, "cache_objsize");
	cli_unregister_command(cli, vserver, "cache_objnum");
	cli_unregister_command(cli, vserver, "cache_expire");
	cli_unregister_command(cli, vserver, "cache_ramsize");
	cli_unregister_command(cli, vserver, "cache_disksize");
	return 0;
}

int check_objnum(struct cli_def *cli, struct cli_command *c, char *value)
{
	if (check_num_range(cli, c, 1, 100000, value) != CLI_OK) {
		printf("range:<1-100000>\n");
		return CLI_ERROR;
	}

	return CLI_OK;
}

static int vs_init_cache_cmd(struct cli_def *cli,
		struct cli_command *vserver)
{
	struct cli_command *t;

	/********** cache_objsize <size> **********/
	t = cli_register_command(cli, vserver, "cache_objsize", vs_config_arg1,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_CACHE_OBJSIZE);
	cli_command_add_argument(t, "<num|k|m>", check_offset);

	/********** cache_objnum <num> **********/
	t = cli_register_command(cli, vserver, "cache_objnum", vs_config_arg1,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_CACHE_OBJNUM);
	cli_command_add_argument(t, "<num 1-100000>", check_objnum);

	/********** cache_inactive <num> **********/
	t = cli_register_command(cli, vserver, "cache_expire", vs_config_arg1,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_CACHE_EXPIRE);
	cli_command_add_argument(t, "<num|s|m|h|d>", check_second);

	/********** cache_ramsize <size> **********/
	t = cli_register_command(cli, vserver, "cache_ramsize", vs_config_arg1,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_CACHE_RAMSIZE);
	cli_command_add_argument(t, "<num|m|g>", check_ram_size);

	/********** cache_disksize <size> **********/
	t = cli_register_command(cli, vserver, "cache_disksize",
			vs_config_arg1, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_CACHE_DISKSIZE);
	cli_command_add_argument(t, "<num|m|g>", check_disk_size);

	return 0;
}

static int vserver_config_limit(struct cli_def *cli,
		char *command, char *argv[], int argc);
static int vserver_config_limit_for_vm(struct cli_def *cli,
		char *command, char *argv[], int argc);
static int vs_config_vm_limit(struct cli_def *cli,
		char *command, char *argv[], int argc);
static int vs_init_vmware_cmd(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *t;

	if(vs->vm_enable[0] == 0 || strcmp(vs->vm_enable, "off") == 0)	{
		return 0;
	}

	t = cli_register_command(cli, root, "vm_conn_high", /*vs_config_arg1*/vs_config_vm_limit,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VMWARE_CONNECTION_HIGH);
	cli_command_add_argument(t, "[num]", check_vm_limit);

	t = cli_register_command(cli, root, "vm_newconn_high", /*vs_config_arg1*/vs_config_vm_limit,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VMWARE_NEW_CONNECTION_HIGH);
	cli_command_add_argument(t, "[num]", check_vm_limit);

	t = cli_register_command(cli, root, "vm_band_high", /*vs_config_arg1*/vserver_config_limit_for_vm,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VMWARE_BANDWIDTH_HIGH);
	cli_command_add_argument(t, "[NUMkbps|mbps, eg 100mbps, between 1kbps and 2048mbps]", check_bandwidth);

	t = cli_register_command(cli, root, "vm_conn_low", /*vs_config_arg1*/vs_config_vm_limit,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VMWARE_CONNECTION_LOW);
	cli_command_add_argument(t, "[num]", check_vm_limit);

	t = cli_register_command(cli, root, "vm_newconn_low", /*vs_config_arg1*/vs_config_vm_limit,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VMWARE_NEW_CONNECTION_LOW);
	cli_command_add_argument(t, "[num]", check_vm_limit);

	t = cli_register_command(cli, root, "vm_band_low", /*vs_config_arg1*/vserver_config_limit_for_vm,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VMWARE_BANDWIDTH_LOW);
	cli_command_add_argument(t, "[NUMkbps|mbps, eg 100mbps, between 1kbps and 2048mbps]", check_bandwidth);

	return 0;
}


static int vs_config_cache(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	int ret;
	ret = vs_config_arg(cli, command, argv, argc);
	vserver_configure_commands(cli, cli->folder->value);
	return ret;
}


static int vs_print_confirm(int port, const char *pool)
{
	int ret = CLI_ERROR;
	char ch[BUFSIZ];
	printf("some realservers have port %d in your pool %s, do you confirm ? [Y/N] ",
			port, pool);
	set_normal_tty();
	if (fgets(ch, BUFSIZ, stdin) == NULL) {
		goto error;
	}

	if (strcasecmp(ch, "y\n") == 0 || strcasecmp(ch, "yes\n") == 0) {
		ret = CLI_OK;
	}

error:
	set_nonline_tty();
	return ret;
}

int vs_config_check_port(const char *protocol, const char *poolname)
{
	int port;

#if 0
	if(strcmp(protocol, "https") == 0 || strcmp(protocol, "http") == 0) {
		port = pool_search_port(poolname, 0);
		if(port != -1) {
			/** FIXME  --fanpf **/
			printf("ERROR: zero port is used by realserver\n");
			return CLI_ERROR;
		}
	}
#endif

	if (strcmp(protocol, "tcp") == 0 
			|| strcmp(protocol, "fast-tcp") == 0 
			|| strcmp(protocol, "http") == 0) {
		if ((port = pool_search_port(poolname, 443)) != -1) {
			if (vs_print_confirm(port, poolname) !=CLI_OK) {
				return CLI_ERROR;
			}
		} else if ((port = pool_search_port(poolname, 8443)) != -1) {
			if (vs_print_confirm(port, poolname) !=CLI_OK) {
				return CLI_ERROR;
			}
		}  
	}

	if (strcmp(protocol, "sslbridge") == 0 || strcmp(protocol, "https") == 0) {
		if ((port = pool_search_port(poolname, 80)) != -1) {
			if (vs_print_confirm(port, poolname) !=CLI_OK) {
				return CLI_ERROR;
			}
		} else if ((port = pool_search_port(poolname, 8080)) != -1) {
			if (vs_print_confirm(port, poolname) !=CLI_OK) {
				return CLI_ERROR;
			}
		} 
	}

	return CLI_OK;
}

static int gslb_listener_unused_check(struct vserver *vserver, char *protocol)
{
	struct gslb_listener *listener = NULL;
	LIST_HEAD(head);
	int rc = CLI_OK;

	module_get_queue(&head, "gslb_listener", NULL);
	list_for_each_entry(listener, &head, list) {
		if (gslb_listener_address_cmp(&vserver->address, listener) == 0) {
			fprintf(stderr, 
				"Error: Address and Protocol already used by GSLB Listener!\n");
			rc = CLI_ERROR;
			goto out;
		}
	}
out:
	module_purge_queue(&head, "gslb_listener");
	return rc;
}

static int vs_config_protocol(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char vsaddr[24], protocol[256];
	struct vserver *vserver;

	LIST_HEAD(head);
	module_get_queue(&head, "vserver", cli->folder->value);

	if (list_empty(&head)) {
		return CLI_OK;
	}


	vserver = list_first_entry(&head, struct vserver, list);
	//strcpy(vsaddr, vserver->address);
	inet_sockaddr2address(&vserver->address, vsaddr);

	sscanf(command, "%*s %s", protocol);
	if (vs_config_check_port(protocol, vserver->pool) != CLI_OK) {
		module_purge_queue(&head, "vserver");
		return CLI_ERROR;
	}

	if (strcasecmp(protocol, "udp") == 0) {
		if (gslb_listener_unused_check(vserver, protocol) == -1) {
			module_purge_queue(&head, "vserver");
			return CLI_ERROR;
		}
	}

	module_purge_queue(&head, "vserver");

	if (strcmp(protocol, "http") == 0 ||
			strcmp(protocol, "https") == 0) {
		char ip[256], port[256];
		if (vsaddr[0] == 0) {
			/** NOTE: 当没有配置address的时候，可以配置协议为http/s **/
			goto ok;
		}
		get_ip_port(vsaddr, ip, port);
		if (atoi(port) == 0) {
			printf("ERROR : The layer7 protocol does not support 0 port or full port!\n");
			return CLI_ERROR;
		}
	}

ok:
	vs_config_arg(cli, command, argv, argc);

	vserver_configure_commands(cli, cli->folder->value);

	return CLI_OK;
}


static int vs_config_pool(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char protocol[16];
	char address[128];
	get_vserver_protocol_address(cli->folder->value, protocol, address);

	if (vs_config_check_port(protocol, argv[0]) != CLI_OK) {
		return CLI_ERROR;
	}


	if (check_vserver_address_loops(cli->folder->value, NULL, argv[0], NULL) != 0) {
		printf("Can't set this pool [%s] to vserver\n", argv[0]);
		return CLI_ERROR;
	}

#if 0
	if (check_busy_pool_address(address, argv[0]) < 0) {
		printf("Can't set this pool [%s] to vserver\n", argv[0]);
		return CLI_ERROR;
	}
#endif
	/** set pool **/
	vs_config_arg1(cli, command, argv, argc);

	return CLI_OK;
}

static int vs_config_backpool(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	if (argc == 0) {
		vs_config_arg(cli, command, argv, argc);
	} else {
		vs_config_arg1(cli, command, argv, argc);
	}

	return CLI_OK;
}

static int vs_config_vm_limit(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	if (argc == 0) {
		vs_config_arg(cli, command, argv, argc);
	} else {
		vs_config_arg1(cli, command, argv, argc);
	}

	return CLI_OK;
}


static int backpool_get_values(struct cli_def *cli, char **values)
{
	int ret, count = 0, i;
	char *vals[BUFSIZ] = {[0 ... BUFSIZ - 1] = NULL };

	char *poolname = NULL;
	struct vserver *vserver;

	LIST_HEAD(queue);
	module_get_queue(&queue, "vserver", cli->folder->value);

	if (list_empty(&queue)) {
		return pool_get_values(cli, values);
	}

	if ((ret = pool_get_values(cli, vals)) == 0) {
		module_purge_queue(&queue, "vserver");
		return 0;
	}

	list_for_each_entry(vserver, &queue, list) {
		poolname = vserver->pool;
	}

	for (i = 0; i < ret; i++) {
		if (strcasecmp(poolname, vals[i]) == 0) {
			continue;
		}
		values[count] = strdup(vals[i]);
		count++;
	}

	default_free_values(vals, ret);

	module_purge_queue(&queue, "vserver");

	return count;
}

#if 0
static int vserver_config_cipheader(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char buff[BUFSIZ];
	sprintf(buff, "script4 system vserver %s cipheader %s",
			cli->folder->value, argc == 0 ? "" : argv[0]);
	system(buff);
	return CLI_OK;
}
#endif

static int vserver_config_limit_for_vm(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char buff[BUFSIZ];
	
	if (argc == 0) {
		vs_config_arg(cli, command, argv, argc);
	} else {
		
		if (strcmp(command, "vm_band_low") == 0) {
			sprintf(buff, "script4 system vserver %s vm_band_low %u",
					cli->folder->value, xbytes2bytes(argv[0]));
			system(buff);;
		} else if (strcmp(command, "vm_band_high") == 0) {
			sprintf(buff, "script4 system vserver %s vm_band_high %u",
					cli->folder->value, xbytes2bytes(argv[0]));
			system(buff);;
		}
	}
	return CLI_OK;
}
static int vserver_config_limit(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char buff[BUFSIZ];

	if (strcmp(command, "limit off") == 0) {	/** turn off the limits **/
		sprintf(buff, "script4 system vserver %s maxconn ",
				cli->folder->value);
		system(buff);;
		sprintf(buff, "script4 system vserver %s maxreq ",
				cli->folder->value);
		system(buff);;
		sprintf(buff, "script4 system vserver %s bandwidth ",
				cli->folder->value);
		system(buff);;
	} else if (strcmp(command, "limit maxconn") == 0) {
		sprintf(buff, "script4 system vserver %s maxconn %s",
				cli->folder->value, strcmp(argv[0],
					"0") == 0 ? "" : argv[0]);
		system(buff);;
	} else if (strcmp(command, "limit maxreq") == 0) {
		sprintf(buff, "script4 system vserver %s maxreq %s",
				cli->folder->value, strcmp(argv[0],
					"0") == 0 ? "" : argv[0]);
		system(buff);;
	} else if (strcmp(command, "limit bandwidth") == 0) {
		sprintf(buff, "script4 system vserver %s bandwidth %u",
				cli->folder->value, xbytes2bytes(argv[0]));
		system(buff);;
	} else {
		return CLI_ERROR;
	}


	return CLI_OK;
}


/* cmdarg form: vsname key value 
 * eg: vserver va add rule rulename priority=number
 * eg: vserver del rule rulename priority=number
 * eg: vserver va show rule_name
 */

static int vs_config_rule_name(struct cli_def *cli, char *command,
		char *argv[], int argc)
{
	char buff[BUFSIZ];
	FILE *fp;
	char *cmd = "script4 system vserver";

	if (!strcmp(command, "addrule")) {
		snprintf(buff, BUFSIZ, "%s %s %s %s", 
				cmd, cli->folder->value, "add rule", argv[0]);
	} 
	else if (!strcmp(command, "delrule")) {
		snprintf(buff, BUFSIZ, "%s %s %s %s", 
				cmd, cli->folder->value, "del rule", argv[0]);
	}
	else{
		return CLI_ERROR;
	}

	fp = popen(buff, "r");
	if (fp == NULL) {
		fprintf(stderr, "Internal Error.\r\n");
		return CLI_ERROR;
	}

	while (fgets(buff, BUFSIZ, fp)) {
		printf("%s", buff);
	}

	pclose(fp);

	return CLI_OK;
}


static int vs_config_persistent(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	struct vserver *vserver;
	LIST_HEAD(queue);

	/** **/
	if (strcmp(command, "persistent off") == 0) {
		vs_config_arg(cli, "persistent ", NULL, 0);
		goto do_nothing;
	}


	module_get_queue(&queue, "vserver", cli->folder->value);

	list_for_each_entry(vserver, &queue, list) {
		/** only https and sslbridge can set persistent ssl_id **/
		if (strcmp(command, "persistent ssl_id") == 0
				&& strcmp(vserver->protocol, "https") != 0) {
			goto do_nothing;
		}

		/** persistent cookie only can be set when protocol is http/https **/
		if (strcmp(command, "persistent cookie") == 0
				&& strcmp(vserver->protocol, "http") != 0
				&& strcmp(vserver->protocol, "https") != 0) {
			goto do_nothing;
		}
		break;
	}

	module_purge_queue(&queue, "vserver");

	vs_config_arg(cli, command, argv, argc);

	if (strncmp(command, "persistent cookie", strlen("persistent cookie")) == 0) {
		vserver_configure_commands(cli, cli->folder->value);
	}

	return CLI_OK;


do_nothing:
	module_purge_queue(&queue, "vserver");
	return CLI_OK;
}

static int vs_config_persistent_cookie(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	if (argc == 0) {
		return vs_config_arg(cli, command, argv, argc);
	}

	return vs_config_arg1(cli, command, argv, argc);
}

static int vs_config_persistent_group(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	if (argc == 0) {
		return vs_config_arg(cli, command, argv, argc);
	}

	return vs_config_arg1(cli, command, argv, argc);
}

static int vs_config_persistent_timeout(struct cli_def *cli,
		char *command, char *argv[],
		int argc)
{
	if (argc == 0) {
		return vs_config_arg(cli, "timeout", argv, argc);
	}

	return vs_config_arg1(cli, "timeout", argv, argc);
}


static int check_persistent_netmask(struct cli_def *cli, 
		struct cli_command *c, char *value)
{
	if (strlen(value) <= 3) {
		if (atoi(value) < 1 || atoi(value) > 128) {
			printf("\nBad Netmask bits\n");
			return CLI_ERROR;
		}
		return CLI_OK;
	}

	printf("\nBad Netmask\n");
	return CLI_ERROR;
}

static int vs_config_persistent_netmask(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	/** script4 system vserver va persistent-netmask 24 **/

	const char *vsname = cli->folder->value;
	char cmd[BUFSIZ];
	FILE *fp;

	if (strlen(argv[0]) > 3) {
		sprintf(cmd, "script4 system vserver %s persistent-netmask %d",
				vsname, mask2bits(argv[0]));
	} else {
		sprintf(cmd, "script4 system vserver %s persistent-netmask %s",
				vsname, argv[0]);
	}

	if ((fp = popen(cmd, "r")) == NULL) {
		return CLI_ERROR;
	}

	if (fgets(cmd, BUFSIZ, fp) != NULL && strncmp(cmd, "EINVAL", 6) == 0) {
		printf("Invalid Netmask [%s]\n", argv[0]);
		goto error;
	}

	pclose(fp);
	return CLI_OK;

error:
	pclose(fp);
	return CLI_ERROR;
}




/**
 * 获取会话保持组的列表
 **/
static int persistent_group_get_values(struct cli_def *cli, char **values)
{
	int pool_count = 0, count = 0;
	struct vserver *vserver, *tmp;
	struct list_head *list;
	int layer = 4;

	LIST_HEAD(vs_head);
	LIST_HEAD(pool_head);

	module_get_queue(&vs_head, "vserver", NULL);

	/** 查找当前的vserver **/
	if ((list = module_queue_search("vserver", &vs_head,
					cli->folder->value)) == NULL) {
		goto error;
	}
	vserver = list_entry(list, struct vserver, list);
	if (vserver->persistent[0]==0) {
		printf("\n\nERROR: plesse set vserver's persistent first!\n");
		goto error;
	}

	list_for_each_entry(tmp, &vs_head, list) {
		if (strcmp(tmp->name, vserver->name)==0) {
			continue;
		}

		if (strcmp(tmp->persistentgroup, vserver->name)==0) {
			printf("\n\nERROR: vserver %s is persistent-group's parent, can't be set!\n", vserver->name);
			goto error;
		}
	}

	if (vserver->pool[0] == 0) {
		goto error;
	}

	if (strncmp(vserver->protocol, "http", 4) == 0) {
		layer = 7;
	} else {
		layer = 4;
	}

	/** 获取当前的应用池中真实服务器个数 **/
	if ((count = pool_get_counts(cli, vserver->pool)) == 0) {
		goto error;
	}

	/** 扫描所有vserver **/
	list_for_each_entry(tmp, &vs_head, list) {
		if (tmp->pool[0] == 0) {
			continue;
		}

		if (vserver == tmp) {
			continue;
		}

		/** vserver layer4 ,  tmp  layer7 **/
		/** layer4 **/
		if ( (strncmp(tmp->protocol, "http", 4) != 0 && layer==7) ||
				(strncmp(tmp->protocol, "http",4)==0 && layer==4 ) ) {
			continue;
		}

		if (count == pool_get_counts(cli, tmp->pool)) {
			if (tmp->persistent[0]==0) {
				continue;
			}
			values[pool_count++] = strdup(tmp->name);
		}
	}

error:
	module_purge_queue(&vs_head, "vserver");

	return pool_count;
}

static int rule_name_configure_order (struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char cmd[BUFSIZ];
	if (strcmp(command, "setrule up") == 0) {
		sprintf(cmd, "script4 system vserver %s set rule %s up",
				cli->folder->value, argv[0]);
	} else if (strcmp(command, "setrule down") == 0) {
		sprintf(cmd, "script4 system vserver %s set rule %s down",
				cli->folder->value, argv[0]);
	} else if (strcmp(command, "setrule top") == 0) {
		sprintf(cmd, "script4 system vserver %s set rule %s top",
				cli->folder->value, argv[0]);
	} else if (strcmp(command, "setrule bottom") == 0) {
		sprintf(cmd, "script4 system vserver %s set rule %s bottom",
				cli->folder->value, argv[0]);
	}
	system(cmd);
	return CLI_OK;
}

/** 重新整理 SHOW 命令 **/
static int do_vserver_configure_show_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *c;

	cli_unregister_command(cli, root, "show");


	/********** show **********/
	c = cli_register_command(cli, root, "show", vs_show,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SHOW_INFO);
	cli_register_command(cli, c, "ipaddr", vs_ipaddr_show,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SHOW_IPADDR_INFO);
	pool_show_command(cli, c);

	if (strcmp(vs->protocol,  "http") == 0 ||
			strcmp(vs->protocol,  "https") == 0) {

		if (strcmp(vs->contentswitch, "on") == 0) {
			rule_show_command(cli, c);
		}

		if (strcmp(vs->protocol, "https") == 0) {
			ssl_show_command(cli, c);
		}
	}
	return 0;
}

/** 重新整理 sched 命令 **/
static int do_vserver_configure_sched_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *t;

	cli_unregister_command(cli, root, "sched");
	/*** sched ***/
	t = cli_register_command(cli, root, "sched", vs_config_sched,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_SCHED_ALG);
	cli_register_command(cli, t, "snmp", vs_pool_rs_snmp_check, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_RR);
	cli_register_command(cli, t, "rr", vs_config_sched, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_RR);
	cli_register_command(cli, t, "wrr", vs_config_sched, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_WRR);
	if (strcmp(vs->protocol, "http") == 0 ||
			strcmp(vs->protocol, "https") == 0) {
		cli_register_command(cli, t, "hash_ip", vs_config_sched,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_SCHED_HASHIP);
		cli_register_command(cli, t, "hash_url", vs_config_sched,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_SCHED_HASHURL);
		cli_register_command(cli, t, "lc", vs_config_sched, 
				PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_LC);
		cli_register_command(cli, t, "fair", vs_config_sched,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_SCHED_FAIR);
#if 0
		cli_register_command(cli, t, "cookie", vs_config_sched,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_SCHED_COOKIE);
#endif

	} else if (strcmp(vs->protocol, "udp") == 0) {
		cli_register_command(cli, t, "sh", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_SH);
		cli_register_command(cli, t, "sed", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_SED);
		cli_register_command(cli, t, "nq", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_NQ);
	} else {
		cli_register_command(cli, t, "wlc", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_WLC);
#if 0
		cli_register_command(cli, t, "lblc", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_LBLC);
		cli_register_command(cli, t, "lblcr", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_LBLCR);
#endif
		cli_register_command(cli, t, "sh", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_SH);
		cli_register_command(cli, t, "sed", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_SED);
		cli_register_command(cli, t, "nq", vs_config_sched, PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_NQ);
		cli_register_command(cli, t, "lc", vs_config_sched, 
				PRIVILEGE_PRIVILEGED,
				MODE_EXEC, LIBCLI_VSERVER_SET_SCHED_LC);
	}

	return 0;
}

static int do_vserver_configure_vmware_command(struct cli_def *cli, struct cli_command *root, struct vserver *vs)
{
	cli_unregister_command(cli, root, "vm_conn_high");
	cli_unregister_command(cli, root, "vm_newconn_high");
	cli_unregister_command(cli, root, "vm_band_high");
	cli_unregister_command(cli, root, "vm_conn_low");
	cli_unregister_command(cli, root, "vm_newconn_low");
	cli_unregister_command(cli, root, "vm_band_low");
	cli_unregister_command(cli, root, "vm_enable");
	vs_init_vmware_cmd(cli, root, vs);
	return 0;
}

/** 重新整理 address 命令 **/
static int do_vserver_configure_address_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *c;

	cli_unregister_command(cli, root, "address");

	c = cli_register_command(cli, root, "address", vs_config_address,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_ADDRESS);
	cli_command_add_argument(c, "<ipv4 address:port; ipv6 [address]:port>", vserver_check_address);

	return 0;
}

/** 重新整理 protocol 命令 **/
static int do_vserver_configure_protocol_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *c;
	cli_unregister_command(cli, root, "protocol");

	/********** protocol <tcp/udp/ssl-bridge/any/http/https> **********/
	c = cli_register_command(cli, root, "protocol", NULL,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_PROTOCOL);
	cli_register_command(cli, c, "tcp", vs_config_protocol,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_TCP);
	cli_register_command(cli, c, "fast-tcp", vs_config_protocol,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_FAST_TCP);
	cli_register_command(cli, c, "udp", vs_config_protocol,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_UDP);
	cli_register_command(cli, c, "sslbridge", vs_config_protocol,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_SSLBRIDGE);
	cli_register_command(cli, c, "rdpbridge", vs_config_protocol,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_RDPBRIDGE);
	cli_register_command(cli, c, "http", vs_config_protocol,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_HTTP);
	cli_register_command(cli, c, "https", vs_config_protocol,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_HTTPS);

#if 1
	if(strcmp(vs->type, "ipv6") != 0) {
		cli_register_command(cli, c, "ftp", vs_config_protocol,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_PROTOCOL_FTP);
	}
#endif

	return 0;
}

static int do_vserver_configure_mode_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *c;
	cli_unregister_command(cli, root, "mode");
	if(strcmp(vs->protocol, "fast-tcp") == 0 || strcmp(vs->protocol, "udp") == 0) {
		c = cli_register_command(cli, root, "mode", NULL,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_MODE_INFO);
		cli_register_command(cli, c, "nat", vs_config_protocol,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_MODE_NAT);
		cli_register_command(cli, c, "dr", vs_config_protocol,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_MODE_DR);
	}

	return 0;
}

static int do_vserver_configure_waf_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *c;
	cli_unregister_command(cli, root, "waf_enable");

	if(strcmp(vs->protocol, "http") == 0 || strcmp(vs->protocol, "https") == 0) {
		c = cli_register_command(cli, root, "waf_enable", NULL,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_WAF_ENABLE_INFO);
		cli_register_command(cli, c, "on", vs_config_arg,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_WAF_ENABLE_ON);
		cli_register_command(cli, c, "off", vs_config_arg,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_WAF_ENABLE_OFF);
	}

	return 0;
}
static int do_vserver_configure_syslog_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *c;
	cli_unregister_command(cli, root, "log_enable");
	cli_unregister_command(cli, root, "log_format");

	if(strcmp(vs->protocol, "http") == 0 || strcmp(vs->protocol, "https") == 0) {
		c = cli_register_command(cli, root, "log_format", vs_config_arg,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_LOG_FORMAT_INFO);
		cli_command_add_argument(c, "[log format]", check_log_format);

		c = cli_register_command(cli, root, "log_enable", NULL,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_LOG_ENABLE_INFO);
		cli_register_command(cli, c, "on", vs_config_arg,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LOG_ENABLE_ON);
		cli_register_command(cli, c, "off", vs_config_arg,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LOG_ENABLE_OFF);
	}

	return 0;
}

/** 重新整理 apppool 命令 **/
static int do_vserver_configure_apppool_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *c;
	cli_unregister_command(cli, root, "pool");
	cli_unregister_command(cli, root, "back-pool");

	if (strcmp(vs->contentswitch, "on") == 0 &&
			(strcmp(vs->protocol, "http") == 0 || 
			 strcmp(vs->protocol, "https") == 0)) {
		return 0;
	}
	/********** pool <poolname> **********/
	c = cli_register_command(cli, root, "pool", vs_config_pool,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_POOL);
	cli_command_add_argument(c, "<poolname>", check_pool_type);
	cli_command_setvalues_func(c, pool_get_values, default_free_values);

	/********** back-pool <poolname> **********/
	c = cli_register_command(cli, root, "back-pool", vs_config_backpool,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_BACKPOOL);
	cli_command_add_argument(c, "[poolname]", check_pool_type);
	cli_command_setvalues_func(c, backpool_get_values,
			default_free_values);

	return 0;
}
static int vm_enable_set_default(struct cli_def *cli, char *command, char *argv[], int argc)
{
	vs_config_arg(cli, command, argv, argc);
	vserver_configure_commands(cli, cli->folder->value);
	return 0;
}
/** 重新整理 common 命令 **/
static int do_vserver_configure_common_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *t, *c;
	cli_unregister_command(cli, root, "enable");
	cli_unregister_command(cli, root, "cipheader");
	cli_unregister_command(cli, root, "transparent");
	cli_unregister_command(cli, root, "limit");
	cli_unregister_command(cli, root, "persistent");
	cli_unregister_command(cli, root, "persistent-group");
	cli_unregister_command(cli, root, "persistent-cookie");
	cli_unregister_command(cli, root, "persistent-timeout");
	cli_unregister_command(cli, root, "persistent-netmask");

#define vserver root
	/********** enable <on/off> **********/
	ADD_BOOL_COMMAND("enable", vs_config_arg,
			LIBCLI_VSERVER_SET_ENABLE,
			LIBCLI_VSERVER_SET_ENABLE_ON,
			LIBCLI_VSERVER_SET_ENABLE_OFF);

	/********** transparent <on/off> **********/
	ADD_BOOL_COMMAND("transparent", vs_config_arg,
			LIBCLI_VSERVER_SET_TRANSPARENT,
			LIBCLI_VSERVER_SET_TRANSPARENT_ON,
			LIBCLI_VSERVER_SET_TRANSPARENT_OFF);

#undef vserver

	t = cli_register_command(cli, root, "vm_enable", vm_enable_set_default,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VMWARE_VM_ENABLE);
	cli_register_command(cli, t, "on", vm_enable_set_default,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VMWARE_VM_ENABLE_ON);
	cli_register_command(cli, t, "off", vm_enable_set_default,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VMWARE_VM_ENABLE_OFF);

	/********** limit maxconn/maxreq/width <value> **********/
	t = cli_register_command(cli, root, "limit", NULL,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_LIMIT);

	c = cli_register_command(cli, t, "off", vserver_config_limit,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_LIMIT_OFF);

	c = cli_register_command(cli, t, "maxconn", vserver_config_limit,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_LIMIT_MAXCONN);
	cli_command_add_argument(c, "<num>", check_num);

	if (strcmp(vs->protocol, "http") == 0 ||
			strcmp(vs->protocol, "https") == 0) {
		c = cli_register_command(cli, t, "maxreq", vserver_config_limit,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_LIMIT_MAXREQ);
		cli_command_add_argument(c, "<num>", check_num);
	}

	c = cli_register_command(cli, t, "bandwidth", vserver_config_limit,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_LIMIT_BANDWIDTH);
	cli_command_add_argument(c, "<NUMkbps|mbps, eg 100mbps, between 1kbps and 2097151kbps>", check_bandwidth);

#if 0
	c = cli_register_command(cli, root, "cipheader", vserver_config_cipheader,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_CIPHEADER);
	cli_command_add_argument(c, "[headername]", check_cipheader);
#endif


	/********** persistent <ip/hash> **********/
	t = cli_register_command(cli, root, "persistent",
			vs_config_persistent, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT);
	cli_register_command(cli, t, "off", vs_config_persistent,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT_OFF);
	cli_register_command(cli, t, "ip", vs_config_persistent,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT_IP);

	if (strcmp(vs->protocol, "https") == 0) {
		cli_register_command(cli, t, "ssl_id", vs_config_persistent,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT_SSLID);
	}
	if (strcmp(vs->protocol, "http") == 0 || strcmp(vs->protocol, "https") == 0) {
		cli_register_command(cli, t, "cookie", vs_config_persistent,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT_COOKIE);
	}
	if (strcmp(vs->protocol, "http") == 0 || strcmp(vs->protocol, "https") == 0) {
		cli_register_command(cli, t, "header", vs_config_persistent,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT_HEADER);
	}

	/** persistent-cookie **/
	if (strncmp(vs->protocol, "http", 4) == 0) {	/** http & https **/
		if (strcmp(vs->persistent, "cookie") == 0) {
			t = cli_register_command(cli, root, "persistent-cookie", vs_config_persistent_cookie,
					PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT_COOKIE_NAME);
			cli_command_add_argument(t, "[cookiename]", check_cookie_header_name);
		}
	}



	/********** persistent-group <vsname> **********/
	if (strcmp(vs->contentswitch, "on") != 0) {
		t = cli_register_command(cli, root, "persistent-group",
				vs_config_persistent_group,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_PERSISTENTGROUP);
		cli_command_add_argument(t, "[vsname]", NULL);
		cli_command_setvalues_func(t, persistent_group_get_values,
				default_free_values);
	}

	if (vs->persistent[0] != 0 && strcmp(vs->persistent, "off") != 0) {

		if (strcmp(vs->protocol, "http") != 0 && strcmp(vs->protocol, "https") != 0) {
			t = cli_register_command(cli, root, "persistent-netmask",
					vs_config_persistent_netmask, PRIVILEGE_PRIVILEGED,
					MODE_EXEC, LIBCLI_VSERVER_SET_PERSISTENT_NETMASK);
			cli_command_add_argument(t, "<netmask>", check_persistent_netmask);
		}

		t = cli_register_command(cli, root, "persistent-timeout", 
				vs_config_persistent_timeout,
				PRIVILEGE_PRIVILEGED, MODE_EXEC,
				LIBCLI_VSERVER_SET_PERSISTENT_TIMEOUT);
		cli_command_add_argument(t, "<timeout(s)>", check_persistent_timeout_range);
	}

	return 0;
}



/** 重新整理 ftp 命令 **/
static int do_vserver_configure_ftp_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *t;

	cli_unregister_command(cli, root, "data_port");

	if (strcmp(vs->protocol, "ftp") != 0) {
		return 0;
	}

	t = cli_register_command(cli, root, "data_port", vs_config_arg1,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_DATA_PORT);
	cli_command_add_argument(t, "<port>", check_port_for_ftp);

	return 0;
}

/** 重新整理 http 命令 **/
static int do_vserver_configure_http_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	cli_unregister_command(cli, root, "contentswitch");
	cli_unregister_command(cli, root, "x-forwarded-for");
	cli_unregister_command(cli, root, "rfc2616-check");
	cli_unregister_command(cli, root, "connreuse");
	cli_unregister_command(cli, root, "gzip");
	cli_unregister_command(cli, root, "deflate");
	cli_unregister_command(cli, root, "cache");
	vs_uninit_cache_cmd(cli, root);

	if (strcmp(vs->protocol, "http") != 0 && strcmp(vs->protocol, "https") != 0) {
		return 0;
	}
#define vserver root
	/********** contentswitch <on/off> **********/
	ADD_BOOL_COMMAND("contentswitch", vs_config_arg,
			LIBCLI_VSERVER_SET_CONTENTSWITCH,
			LIBCLI_VSERVER_SET_CONTENTSWITCH_ON
			, LIBCLI_VSERVER_SET_CONTENTSWITCH_OFF);

	/********** x-forwarded-for <on/off> **********/
	ADD_BOOL_COMMAND("x-forwarded-for", vs_config_arg,
			LIBCLI_VSERVER_SET_XFORWARDEDFOR,
			LIBCLI_VSERVER_SET_XFORWARDEDFOR_ON,
			LIBCLI_VSERVER_SET_XFORWARDEDFOR_OFF);

	/********** rfc2616-check <on/off> **********/
	ADD_BOOL_COMMAND("rfc2616-check", vs_config_arg,
			LIBCLI_VSERVER_SET_RFC2616CHECK,
			LIBCLI_VSERVER_SET_RFC2616CHECK_ON,
			LIBCLI_VSERVER_SET_RFC2616CHECK_OFF);

	/********** connreuse <on/off> **********/
	ADD_BOOL_COMMAND("connreuse", vs_config_arg,
			LIBCLI_VSERVER_SET_CONNREUSE,
			LIBCLI_VSERVER_SET_CONNREUSE_ON,
			LIBCLI_VSERVER_SET_CONNREUSE_OFF);

	/********** gzip <on/off> **********/
	ADD_BOOL_COMMAND("gzip", vs_config_arg,
			LIBCLI_VSERVER_SET_GZIP,
			LIBCLI_VSERVER_SET_GZIP_ON,
			LIBCLI_VSERVER_SET_GZIP_OFF);

	/********** deflate <on/off> **********/
	ADD_BOOL_COMMAND("deflate", vs_config_arg,
			LIBCLI_VSERVER_SET_DEFLATE, 
			LIBCLI_VSERVER_SET_DEFLATE_ON,
			LIBCLI_VSERVER_SET_DEFLATE_OFF);


	/********** cache <on/off> **********/
	ADD_BOOL_COMMAND("cache", vs_config_cache,
			LIBCLI_VSERVER_SET_CACHE, 
			LIBCLI_VSERVER_SET_CACHE_ON, 
			LIBCLI_VSERVER_SET_CACHE_OFF);

	if (strcmp(vs->cache, "on") == 0) {
		vs_init_cache_cmd(cli, cli->folder);
	}

#undef vserver

	return 0;
}

/** 重新整理 https 命令 **/
static int do_vserver_configure_https_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	vs_uninit_https_cmd(cli, cli->folder);

	if (strcmp(vs->protocol, "https") == 0) {
		vs_init_https_cmd(cli, cli->folder);
	}

	return 0;
}


/** 重新整理 contentswitch 命令 **/
static int do_vserver_configure_contentswitch_command(struct cli_def *cli,
		struct cli_command *root, struct vserver *vs)
{
	struct cli_command *t/*, *c*/;

	cli_unregister_command(cli, root, "addrule");
	cli_unregister_command(cli, root, "delrule");
	cli_unregister_command(cli, root, "setrule");

	if (/*strcmp(vs->contentswitch, "on") != 0 || */
			(strcmp(vs->protocol, "http") != 0 &&
			 strcmp(vs->protocol, "https") != 0)) {
		return 0;
	}

	/********** add rule <rulename> **************/
	t = cli_register_command(cli, root, "addrule", vs_config_rule_name,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_ADD_RULE);
	cli_command_add_argument(t, "<rulename>", check_rule_and_priority);
	cli_command_setvalues_func(t, rule_add_get_values, default_free_values);

	/********** del rule <rulename> **************/
	t = cli_register_command(cli, root, "delrule", vs_config_rule_name,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_DEL_RULE);
	cli_command_add_argument(t, "<rulename>", NULL);
	cli_command_setvalues_func(t, rule_name_del_get_values, default_free_values);

	/********** set rule <rulename> up/down/top/bottom **************/
	t = cli_register_command(cli, root, "setrule", NULL,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_SET_RULE);
	cli_command_add_argument(t, "<rulename>", NULL);
	cli_command_setvalues_func(t, rule_name_del_get_values, default_free_values);

	cli_register_command(cli, t, "up", rule_name_configure_order,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_RULE_UP);
	cli_register_command(cli, t, "down", rule_name_configure_order,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_RULE_DOWN);
	cli_register_command(cli, t, "top", rule_name_configure_order,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_RULE_TOP);
	cli_register_command(cli, t, "bottom", rule_name_configure_order,
			PRIVILEGE_PRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SET_RULE_BOTTOM);


	return 0;
}



static int do_vserver_configure_commands(struct cli_def *cli, 
		struct cli_command *root, struct vserver *vs)
{
	do_vserver_configure_vmware_command(cli, root, vs);
	do_vserver_configure_show_command(cli, root, vs);
	do_vserver_configure_address_command(cli, root, vs);
	do_vserver_configure_sched_command(cli, root, vs);
	do_vserver_configure_protocol_command(cli, root, vs);
	do_vserver_configure_apppool_command(cli, root, vs);
	do_vserver_configure_common_command(cli, root, vs);
	do_vserver_configure_ftp_command(cli, root, vs);
	do_vserver_configure_http_command(cli, root, vs);
	do_vserver_configure_https_command(cli, root, vs);
	do_vserver_configure_contentswitch_command(cli, root, vs);
	do_vserver_configure_mode_command(cli, root, vs);
	do_vserver_configure_syslog_command(cli, root, vs);
	do_vserver_configure_waf_command(cli, root, vs);
	return 0;
}


/** 重新整理vserver命令 **/
static int vserver_configure_commands(struct cli_def *cli, char *vsname)
{
	struct vserver *vserver;
	LIST_HEAD(queue);

	module_get_queue(&queue, "vserver", vsname);

	/** 这里有且只有一个成员 **/
	list_for_each_entry(vserver, &queue, list) {
		do_vserver_configure_commands(cli, cli->folder, vserver);
	}
	module_purge_queue(&queue, "vserver");

	return CLI_OK;
}

static int vs_new(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	char buff[BUFSIZ];
	if (argc != 1) {
		return CLI_ERROR;
	}

	if (strcmp(command, "add vserver ipv6") == 0) {
		sprintf(buff, "script4 system vserver %s ipv6", argv[0]);
	} else {
		sprintf(buff, "script4 system vserver %s", argv[0]);
	}

	system(buff);

	return CLI_OK;
}

static int vs_delete(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	char buff[BUFSIZ];
	if (argc != 1) {
		return CLI_ERROR;
	}

	if (check_name(cli, cli->folder, strtolower(argv[0])) != CLI_OK) {
		return CLI_ERROR;
	}

	/*  command : ip addr del %s dev %s  --fanpf */
	/*struct cli_def cli2 = {0};*/
	/*struct cli_command cli_cmd;*/
	/*cli2.folder = &cli_cmd;*/
	/*cli_cmd.value = argv[0];*/

	/* del vserver from system */
	sprintf(buff, "script4 system delete vserver %s", argv[0]);
	system(buff);

	return CLI_OK;
}



	__attribute__ ((unused))
static int vs_config_arg2(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char buff[BUFSIZ], resp[BUFSIZ];
	FILE *fp;
	char *cmd = "script4 system vserver";

	if (argc != 2) {
		fprintf(stderr, "Invalid argument \"%s\".\r\n", argv[0]);
		return CLI_ERROR;
	}

	snprintf(buff, BUFSIZ, "%s %s %s %s %s", cmd,
			cli->folder->value, command, argv[0], argv[1]);

	fp = popen(buff, "r");
	if (fp == NULL) {
		fprintf(stderr, "Internal Error.\r\n");
		return CLI_ERROR;
	}
	while (fgets(resp, BUFSIZ, fp) != NULL) {
		printf("%s", resp);
		pclose(fp);
		return CLI_ERROR;
	}
	pclose(fp);

	return CLI_OK;

}

int check_certificate_name(struct cli_def *cli, struct cli_command *c, char *value)
{
	/** TODO **/
	return CLI_OK;
}

int vserver_ip_get_values(struct cli_def *cli, char **values)
{
	int k = 0;
	struct vserver *vserver;
	char address[1024];

	printf("func:%s %s cli->parent\n", __func__, cli->folder->value);

	LIST_HEAD(queue);

	module_get_queue(&queue, "vserver", NULL);

	list_for_each_entry(vserver, &queue, list) {
		memset(address, 0, sizeof(address));
		inet_sockaddr2address(&vserver->address, address);
		values[k++] = strdup(address);
	}
	module_purge_queue(&queue, "vserver");

	return k;
}


/** 获取当前所有的vserver的名字，由CLI的TAB键显示 **/
int vserver_get_values(struct cli_def *cli, char **values)
{
	int k = 0;
	struct vserver *vserver;
	LIST_HEAD(queue);

	module_get_queue(&queue, "vserver", NULL);

	list_for_each_entry(vserver, &queue, list) {
		values[k++] = strdup(vserver->name);
	}
	module_purge_queue(&queue, "vserver");

	return k;
}

/** 检查add vserver xxx 中输入的名字合法性 **/
static int vs_check_name(struct cli_def *cli, struct cli_command *c, char *value)
{
	LIST_HEAD(queue);
	int ret = CLI_OK;

	/** 先检查输入合法性 **/
	if (check_name(cli, c, value) != CLI_OK) {
		return CLI_ERROR;
	}

	/** 根据名字获取vserver列表 **/
	module_get_queue(&queue, "vserver", strtolower(value));
	if (list_empty(&queue)) {
		ret = CLI_ERROR;
	}
	module_purge_queue(&queue, "vserver");

	return ret;
}

static int check_vsname(struct cli_def *cli, struct cli_command *c, char *value)
{
  int len; 

  len = strlen(value);
  if (len >= 64 || !len)
    return CLI_ERROR;
  char *ptr = value;

  while (*ptr != '\0') {
    if (!isalpha(*ptr) && !isdigit(*ptr) && *ptr != '_') 
      return CLI_ERROR;
    ++ptr;
  } 
  return CLI_OK;
}



static int vs_add_check(struct cli_def *cli, struct cli_command *c, char *value)
{

	if(check_vsname(cli, c, value)!=CLI_OK){
		printf("ERROR : vserver '%s' name error.\n", value);
		return CLI_ERROR;
	}

	if (check_vs_name_unique(strtolower(value)) == 1) {
			fprintf(stderr, "\nERROR : vserver '%s' already exists, SLB vs'name must not the same with LLB's name, add failture\n", value);
		return CLI_ERROR;
	}

	/* check exist */
#if 0
	LIST_HEAD(queue);
	module_get_queue(&queue, "vserver", strtolower(value));
	if (!list_empty(&queue)) {
		ret = CLI_ERROR;
		printf("ERROR : vserver '%s' already exists, add failture!\n", value);
	}
	module_purge_queue(&queue, "vserver");
#endif
	return CLI_OK;
}


static int vs_set_check(struct cli_def *cli, struct cli_command *c, char *value)
{
	if (vs_check_name(cli, c, value) ==CLI_ERROR) {
		printf("ERROR : vserver '%s' not exists.\n", value);
		return CLI_ERROR;
	}

	return CLI_OK;
}

static int vs_set_default(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	vserver_configure_commands(cli, argv[0]);
	return CLI_OK;
}




int vs_show_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "vserver", vs_show,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SHOW_INFO);
	cli_command_add_argument(c, "[vservername]", vs_set_check);
	cli_command_setvalues_func(c, vserver_get_values, default_free_values);


	return 0;
}

int vs_add_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "vserver", vs_new,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_ADD_INFO);
	cli_command_add_argument(c, "<vservername>", vs_add_check);
	cli_register_command(cli, c, "ipv4", vs_new,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_ADD_INFO);
	cli_register_command(cli, c, "ipv6", vs_new,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_ADD_INFO);
	return 0;
}

int vs_set_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command /* *c, */*vserver;
	/********** vserver <vservername> **********/
	vserver = cli_register_command(cli, parent, "vserver", vs_set_default,
			PRIVILEGE_PRIVILEGED, MODE_FOLDER,
			LIBCLI_VSERVER_MANAGE_INFO);
	cli_command_add_argument(vserver, "<vservername>", vs_set_check);
	cli_command_setvalues_func(vserver, vserver_get_values,
			default_free_values);

	return 0;
}

int vs_delete_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "vserver", vs_delete,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_DELETE_INFO);
	cli_command_add_argument(c, "<vservername>", vs_set_check);
	cli_command_setvalues_func(c, vserver_get_values, default_free_values);
	return 0;
}
