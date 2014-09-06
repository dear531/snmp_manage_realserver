#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <syslog.h>
#include <time.h>
#include <net/if.h>

#include "cluster/hb.h"
#include "common/module.h"
#include "common/common.h"
#include "common/logger.h"
#include "common/base64.h"
#include "common/dependence.h"
#include "common/config_apache.h"
#include "common/sys.h"

#include "loadbalance/healthcheck.h"
#include "loadbalance/apppool.h"
#include "loadbalance/vserver.h"
#include "loadbalance/rule.h"
#include "loadbalance/under_gslb.h"
#include "loadbalance/vcenter.h"
#include "loadbalance/walk4iptables.h"
#include "certificate/certcomm.h"
#include "certificate/certificate.h"
#include "certificate/crl.h"
#include "license/license.h"
#include "cli_users/cli_users.h"
#include "system/tcp_congestion_control.h"

#include "network/network.h"
#include "network/rtable.h"
#include "network/arptable.h"
#include "network/floatip.h"
#include "network/firewall.h"

#include "analyzer.h"

#include "mailsched.h"
#include "snmpsched.h"
#include "hbsched.h"
#include "generator.h"
#include "event_log.h"

#include "interface_log.h"
#include "common/strldef.h"
#include "gslb/gslb_device.h"
#include "gslb/gslb_vserver.h"
#include "gslb/gslb_listener.h"
#include "gslb/gslb_pool.h"
#include "gslb/gslb_group.h"
#include "gslb/bind9.h"
#include "gslb/topologyfiles.h"

#include  "llb/llb_vserver.h"
#include  "llb/llb_pool.h"
#include "bind9cfg.h"

#include "gslb.h"

#include "vmware_vcenter.h"
#include "xenserver.h"
#define MGMT_CONFIG "/etc/sysconfig/network-scripts/ifcfg-mgmt"
/* static struct license_module lic_module; */

static LIST_HEAD(analyzer_head);

static void analyzer_purge(struct list_head *queue)
{
	struct analyzer *analyzer;
	while (!list_empty(queue)) {
		analyzer = list_entry(queue->next, struct analyzer, list);
		list_del(&analyzer->list);
		free(analyzer);
	}
}

static int register_analyzer(struct list_head *queue, char *name, 
		int (*handler)(char *arg, struct event *e))
{
	struct analyzer *analyzer;

	analyzer = calloc(1, sizeof(struct analyzer));
	if (analyzer == NULL)
		goto out;

	strncpy(analyzer->name, name, sizeof(analyzer->name) - 1);
	analyzer->handler = handler;

	list_add_tail(&analyzer->list, queue);
	return 0;
out:
	return -1;
}


static LIST_HEAD(analyzer_system_head);

int write_return_status(int fd, int err)
{
#define WRITE_RETURN_STATUS(e)				\
	do {						\
		if (err == -e) {			\
			write(fd, #e, strlen(#e));	\
		}					\
	} while (0)
	WRITE_RETURN_STATUS(EBUSY);
	WRITE_RETURN_STATUS(EBADF);
	WRITE_RETURN_STATUS(EINVAL);
	WRITE_RETURN_STATUS(ENODEV);
	WRITE_RETURN_STATUS(ENOMEM);
	WRITE_RETURN_STATUS(ENOENT);
	WRITE_RETURN_STATUS(EEXIST);

	WRITE_RETURN_STATUS(SMARTGRID_AUTH_OK);
	WRITE_RETURN_STATUS(SMARTGRID_ADDRESS_ERROR);
	WRITE_RETURN_STATUS(SMARTGRID_POOL_ERROR);
	WRITE_RETURN_STATUS(SMARTGRID_PERSISTENTGROUP_ERROR);
	WRITE_RETURN_STATUS(SMARTGRID_RULE_ERROR);
	WRITE_RETURN_STATUS(SMARTGRID_SYNC_GROUP_ERROR);
	WRITE_RETURN_STATUS(SMARTGRID_VCENTER_CONNTEST_ERROR);
	WRITE_RETURN_STATUS(ENETUNREACH);
#undef WRITE_RETURN_STATUS
	return 0;
}

/* below is function definition */
static int analyzer_system_certificate(char *arg, struct event *e)
{
	char certname[1024], cmd[1024];

	int ret = 0;

	sscanf(arg, "%s %s", cmd, certname);
	strtolower(certname);

#define WRITE_BACK(e, str) 				\
	do {						\
		write(e->event_fd, str, strlen(str));	\
	} while (0)

	if (certname[0] == 0) {
		/** TODO: return Bad_Arguemnt **/
		WRITE_BACK(e, "RETURN_BAD_ARGUMENT");
		return 0;
	}

	if (strcmp(cmd, "ssl_new") == 0) {
		/**
		 * ssl_new <certname> <cacertname> - - - - - - -  [password]
		 **/
		ret = certificate_new(certname, arg + strlen(certname) 
				+ strlen(cmd) + 2);
	} else if (strcmp(cmd, "ssl_delete") == 0) {
		/**
		 * ssl_delete <certname> [certname] ......
		 **/
		ret = certificate_delete(certname);
	} else if (strcmp(cmd, "ca_import") == 0) {
		/**
		 * ca_import <certname> <certfile> [keyfile] [password]
		 **/
		ret = certificate_import(/*certname, */arg + strlen(cmd) + 1
				/*+ strlen(certname) + 2*/, 1/** it's ca **/);
	} else if (strcmp(cmd, "ssl_new_cli")==0){
		ret = certificate_new_cli(certname, arg + strlen(cmd) + strlen(certname) + 2);
	} else if (strcmp(cmd, "ssl_import") == 0) {
		/** 
		 * ssl_import <certname> <certfile> <keyfile> [password]
		 **/
		ret = certificate_import(/*certname, */arg + strlen(cmd) + 1
				/*+ strlen(certname) + 2*/, 0/** not ca **/);
#if 0
	} else if (strcmp(cmd, "ssl_export") == 0) {
		/**
		 * ssl_export <format> <certname> [certname] ......
		 **/
		ret = certificate_export(certname, arg + strlen(cmd)
				+ strlen(certname) + 2);
#endif
	} else if (strcmp(cmd, "crl_new") == 0) {
		ret = crl_new(certname, arg + strlen(certname) 
				+ strlen(cmd) + 2);
	} else if (strcmp(cmd, "crl_del") == 0) {
		ret = crl_delete(certname);
	} else if (strcmp(cmd, "crl_import") == 0) {
		ret = crl_import(arg + strlen(cmd) + 1);
	} else if (strcmp(cmd, "crl_export") == 0) {
		ret = crl_export(certname, arg + strlen(cmd)
				+ strlen(certname) + 2);
	} else if (strcmp(cmd, "csr_new") == 0) {
		ret = csr_new(certname, arg + strlen(cmd) + strlen(certname) + 2);
	}

	switch (ret) {
		/** RETURN_BAD_ARGUMENT
		  RETURN_NO_SUCH_FILE
		  RETURN_BAD_FORMAT **/
		case RETURN_BAD_ARGUMENT:
			WRITE_BACK(e, "RETURN_BAD_ARGUMENT");
			break;
		case RETURN_NO_SUCH_FILE:
			WRITE_BACK(e, "RETURN_NO_SUCH_FILE");
			break;
		case RETURN_BAD_FORMAT:
			WRITE_BACK(e, "RETURN_BAD_FORMAT");
			break;
		case RETURN_CA_INVALID:
			WRITE_BACK(e, "RETURN_CA_INVALID");
			break;
		case RETURN_CERT_INVALID:
			WRITE_BACK(e, "RETURN_CERT_INVALID");
			break;
		case RETURN_PKEY_INVALID:
			WRITE_BACK(e, "RETURN_PKEY_INVALID");
			break;
		case -EBUSY:
			WRITE_BACK(e, "EBUSY\n");
			break;
		case RETURN_OK:
		default:
			break;
	}
	return 0;
}

static int analyzer_system_flush_state(char *cmdarg, struct event *e)
{
	char mname[256];
	sscanf(cmdarg, "%s", mname);

	if (strcasecmp(mname, "certificate") == 0) {
		certificate_flush_state();
	} else if (strcasecmp(mname, "vserver") == 0) {
		if (vserver_flush_state() == 1){
			/* when delete draining rserver, update config,  suport for web page */
			generator_entrance(NULL);
		} 
	} else  if(strcasecmp(mname, "arptable") == 0){
		flush_dynamic_arp_state();
	} else  if(strcasecmp(mname, "apppool") == 0){
		/* apppool_flush_state(); */
	} else  if(strcasecmp(mname, "vcenter") == 0){
		/*/tmp/va.xml --> config.xml*/
		vcenter_flush_config2();
	} else  {
		module_flush_state(mname);
	}
	return 0;
}

#define GSLB_BIND9_VAR_DIRECTORY "/SmartGrid/bind9/var/"
static int gslb_vserver_delete_from_bind9(char *vsname)
{
	char filename[BUFSIZ], name[1024];
	char *p1 = NULL;
	int count = 0, i = 0;

	for (i = 0; i < strlen(vsname); i++) {
		if (vsname[i] == '.')
			count++;
	}
	
	if (count > 1) {
		p1 = strchr(vsname, '.');
		sscanf(p1+1, "%s", name);
	} else
		strcpy(name, vsname);

	memset(filename, 0, sizeof(filename));
	snprintf(filename, sizeof(filename) - 1, "%s/%s.zone", 
			GSLB_BIND9_VAR_DIRECTORY, name);

	return unlink(filename);
}



/* cmdarg form: delete vserver httplb */
static int analyzer_system_delete(char *cmdarg, struct event *e)
{
	int ret = 0;
	char type[1024] = {0}, name[1024] = {0};
	
	sscanf(cmdarg, "%s %s", type, name);

	strtolower(name);

	if (strcmp(type, "healthcheck") == 0) {
		ret = module_delete("healthcheck", name);
	} else if (strcmp(type, "errpages") == 0) {
		char file[BUFSIZ];
		sscanf(cmdarg, "%*s %s", name);
		base64_decode((uint8_t *)file, name, sizeof(file));
		ret = module_delete("errpages", file);
	} else if (strcmp(type, "pool") == 0) {
		ret = module_delete("apppool", name);
	} else if (strcmp(type, "vserver") == 0) {
		unconfig_apache();
		module_delete("vserver", name);
		config_apache(0, 0);
	} else if (strcmp(type, "rule") == 0) {
		/* if (lic_module.rule ) { */
		ret = module_delete("rule", name);
		/* } */
	} else if (strcmp(type, "interface") == 0) {
		ret = module_delete("interface", name);
	} else if (strcmp(type, "vlan") == 0) {
		if ((ret = module_delete("vlan", name)) == 0) {
			/**从浮动IP列表中删除VLAN接口对应的IP**/
			del_ipaddr_from_config(name);
		}
	} else if (strcmp(type, "snat") == 0) {
		ret = module_delete("snat", name);
		return 0;
	} else if (strcmp(type, "rtable") == 0) {
		ret = module_delete("rtable", name);
		return 0;
	}  else if (strcmp(type, "arptable") == 0) {
		ret = module_delete("arptable", name);
		return 0;
	}  else if (strcmp(type, "floatip") == 0) {
		ret = module_delete("floatip", name);
		return 0;
	} else if (strcmp(type, "firewall") == 0) {
		ret = module_delete("firewall", name);
	}  else if (strcmp(type, "gslb_listener") == 0) {
		ret = module_delete("gslb_listener", name);
		return 0;
	}  else if (strcmp(type, "gslb_vserver") == 0) {
		gslb_vserver_delete_from_bind9(name);	// delete vserver
		ret = module_delete("gslb_vserver", name);
		return 0;
	}  else if (strcmp(type, "gslb_device") == 0) {
		ret = module_delete("gslb_device", name);
		return 0;
	}	else if (strcmp(type, "gslb_pool") == 0) {
		ret = module_delete("gslb_pool", name);
		return 0;
	}	else if (strcmp(type, "gslb_group") == 0) {
		ret = module_delete("gslb_group", name);
		return 0;
	} else if (strcmp(type, "tp_node") == 0) {
		ret = module_delete("tp_node", name);
		return 0;
	} else if (strcmp(type, "tp_policy") == 0) {
		ret = module_delete("tp_policy", name);
		return 0;
	} else if (strcmp(type, "bind9_domain") == 0) {
		ret = module_delete("bind9_domain", name);
		return 0;
	} else if (strcmp(type, "llb_vserver") == 0) {
		ret = module_delete("llb_vserver", name);
		return 0;
	} else if (strcmp(type, "llb_pool") == 0) {
		ret = module_delete("llb_pool", name);
		return 0;
	} else if (strcmp(type, "firewall") == 0) {
		ret = module_delete("firewall", name);
	} else if (strcmp(type, "vcenter") == 0) {
		ret = module_delete("vcenter", name);
	} else if (strcmp(type, "llb_snat") == 0) {
		ret = module_delete("llb_snat", name);
	} else if (strcmp(type, "dnat") == 0) {
		ret = module_delete("dnat", name);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 1;
}

/* cmdarg form: weblog op address value 
 * eg: syslog address 192.168.10.74
 */
static int analyzer_system_weblog(char *cmdarg, struct event *e)
{

	char key[1024]={0}, op[1024]={0}, value[1024]={0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s", op, key, value);

	if (strcmp(op, "add") == 0) {
		ret = module_set("weblog", value, "address", value);
	} else if (strcmp(op, "del") == 0) {
		ret = module_delete("weblog", value);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;	/** modified, create configuration of lvs & smartl7 **/
}

/* cmdarg form: vsname key value 
 * eg: vs1 address 192.168.10.74:7788
 */
static int analyzer_system_vserver(char *cmdarg, struct event *e)
{

	char vsname[1024]={0}, key[1024]={0}, op[1024]={0}, value[1024]={0}, order[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s %s", vsname, op, key, value, order);
	strtolower(vsname);

	if (strcmp(op, "address") == 0) {
		unconfig_apache();
	}

	if (strcmp(op, "add") == 0 && strcmp(key, "rule") == 0) {
		ret = module_add_sub("vserver", vsname, "rule_name", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "rule") == 0) {
		ret = module_del_sub("vserver", vsname, "rule_name", value);
	} else if (strcmp(op, "set") == 0 && strcmp(key, "rule") == 0) {
		ret = module_set_sub_order("vserver", vsname, "rule_name", value, order);
	} else if (strcmp(op, "ssl_verify_client") == 0 && strcmp(key, "useca") == 0) {
		ret = module_set("vserver", vsname, op, value);
	} else {
		ret = module_set("vserver", vsname, op, key);
	}

	if (strcmp(op, "address") == 0) {
		config_apache(0, 0);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;	/** modified, create configuration of lvs & smartl7 **/
}

static int analyzer_system_pro_vserver(char *cmdarg, struct event *e)
{
	int ret = 0;
	char *ptr = NULL;
	char vsname[BUFSIZ] = {0};

	unconfig_apache();

	ptr = strchr(cmdarg, ',');
	if (ptr != NULL) {
		strncpy(vsname, cmdarg,ptr - cmdarg );
		ret = module_set("vserver", vsname, cmdarg, NULL);
	} else {
		ret = module_set("vserver", cmdarg, NULL, NULL);
	}
	
	config_apache(0, 0);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	
	return 1;
}

static int analyzer_system_check_subnet(char *cmdarg, struct event *e)
{
	int ret = 0;
	char ipaddr1[1024] = {0};	
	char ipaddr2[1024] = {0};	
	char ip1[STR_IP_LEN] = {0};
	char ip2[STR_IP_LEN] = {0};
	char netmask1[STR_NETMASK_LEN] = {0};
	char netmask2[STR_NETMASK_LEN] = {0};
	sscanf(cmdarg, "%s %s", ipaddr1, ipaddr2);
	get_ip_netmask2(ipaddr1, ip1, netmask1);
	get_ip_netmask2(ipaddr2, ip2, netmask2);
	ret = check_subnet(ip1, netmask1, ip2, netmask2);
	if (ret != 0) {
		ret = -EINVAL;
		write_return_status(e->event_fd, ret);
		return -1;
	}
	
	return 1;
}

static int analyzer_system_under_gslb(char *cmdarg, struct event *e)
{
	char name[1024]={0}, key[1024]={0}, op[1024]={0}, value[1024]={0}, order[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s %s", name, op, key, value, order);
	strtolower(name);
	ret = module_set("under_gslb", name, op, key);
	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;	/** modified, create configuration of lvs & smartl7 **/
}

int parse_sync_group_xml(char *buff, const char *filepath)
{
	system("if [ -f /SmartGrid/gslb_config/SyncGroup.xml ]; then \n"
				"rm -fr /SmartGrid/gslb_config/SyncGroup.xml;fi");	
	xmlDocPtr pdoc = config_load(filepath);
	
	char *token;

	token = strtok(buff, "|");
	xmlNodePtr pnode;
	pnode = config_add_node3(pdoc, "Vserver", NULL, NULL);
	while(token) {
		char vsname[64] = {0};
		char ip[256] = {0};
		
		xmlNodePtr psub;
		sscanf(token, "%[^+]+%s", vsname, ip);
		psub = config_add_children_node(pnode, "vs");
		config_set_attr_value(psub, "name", vsname);
		config_set_attr_value(psub, "ip", ip);
		token = strtok(NULL, "|");
	}

	config_save(pdoc, filepath);
	config_free(pdoc);
	return 0;
}

static int analyzer_system_sync_group(char *cmdarg, struct event *e)
{
//	int ret = 0;
	char address[1024] = {0};
	char password[1024] = {0};
	char command[32] = {0};

	sscanf(cmdarg, "%s %s %s", command, address, password);
	strtolower(command);	

	if (strcasecmp(command, "auth") == 0)
		gslb_command_auth(e, address, password);
	else if (strcasecmp(command, "vslist") == 0)
		gslb_command_vslist(e, address, password);
	else if (strcasecmp(command, "sync") == 0)
		gslb_command_sync_config(e, address, password);

	return 0;
}
/* format: poolname [add,del,show] key value 
 * eg: pool2 bandwidth 10000
 * eg: pool2 add realserver 192.168.10.20:8877,maxconn=10000,bandwidth=10000,healthcheck=check3,enable=on...
 * eg: pool2 del realserver 192.168.10.20:8877
 * eg: pool2 show [realserver,backserver]
 */
static int analyzer_system_pool(char *cmdarg, struct event *e)
{
	char poolname[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", poolname, op, key, value);
	strtolower(poolname);

	if (strcmp(op, "add") == 0 && strcmp(key, "realserver") == 0) {
		ret = add_realserver_to_apppool(poolname, value);
	} else if (strcmp(op, "delete") == 0 && strcmp(key, "realserver") == 0) {
		ret = module_del_sub("apppool", poolname, "realserver", value);
	} else {
		ret = module_set("apppool", poolname, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;
}

static int analyzer_system_vcenter(char *cmdarg, struct event *e)
{
	char vcentername[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", vcentername, op, key, value);
	strtolower(vcentername);

	if (strcmp(op, "add") == 0 && strcmp(key, "host") == 0) {
		ret = module_add_sub("vcenter", vcentername, "host", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "host") == 0) {
		ret = module_del_sub("vcenter", vcentername, "host", value);
	} else {
		ret = module_set("vcenter", vcentername, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;
}


static int analyzer_system_gslb_pool(char *cmdarg, struct event *e)
{
	char gslb_poolname[1024] = {0};
	char op[1024] = {0};
	char key[1024] = {0};
	char value[1024] = {0};
	int ret = 0;
	sscanf(cmdarg, "%s %s %s %s", gslb_poolname, op, key, value);
	if (strcmp(op, "add") == 0 && strcmp(key, "gslb_rserver") == 0) {
	//	ret = add_gslb_rserver_to_gslb_pool(gslb_poolname, value);
		ret = module_add_sub("gslb_pool", gslb_poolname, "gslb_rserver", value);
	} else if (strcmp(op, "delete") == 0 && strcmp(key, "gslb_rserver") == 0) {
		ret = module_del_sub("gslb_pool", gslb_poolname, "gslb_rserver", value);
	} else {
		ret = module_set("gslb_pool", gslb_poolname, op, key);
	}

	if (ret != 0) {
    	write_return_status(e->event_fd, ret);
    	return -1;
	}
	return 1;
}

static int run_match_analyzer(struct list_head *queue, char *cmdarg, struct event *e)
{
	struct analyzer *analyzer;
	char *p;
	char cmdtype[1024];

	/* cmdtype: system, show, help, exit */
	memset(cmdtype, '\0', sizeof(cmdtype));
	sscanf(cmdarg, "%s", cmdtype);

	list_for_each_entry(analyzer, queue, list) {
		if (!strncasecmp(cmdtype, analyzer->name, strlen(analyzer->name))) {
			p = strchr(cmdarg, ' ');
			if (++p)	/* point to next field start */
				return analyzer->handler(p, e);
			break;
		}
	}
	return 0;
}

static int analyzer_system_rule(char *cmdarg, struct event *e)
{
	int ret = 0;
	char rulename[64] = {0}, key[1024] = {0}, value[4096] = {0};

	sscanf(cmdarg, "%s %s %s", rulename, key, value);
	strtolower(rulename);

	ret = module_set("rule", rulename, key, value);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 1;
}

static int analyzer_system_dns(char *cmdarg, struct event *e)
{
	char op[1024] = {0}, value[4096] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s", op, value);
	if (strcmp(op, "add") == 0) {
		ret = module_set("dns", "nameserver", "address", value);
	} else if (strcmp(op, "del") == 0) {
		ret = module_delete("dns", value);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 0;
}

static int analyzer_system_forward(char *cmdarg, struct event *e)
{
	char value[4096] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s", value);
	ret = module_set("forward", "forward", "enable", value);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	gen_zebra_conf();
	gen_ripd_conf();
	gen_ospfd_conf();
	return 0;
}

static int analyzer_system_authentication(char *cmdarg, struct event *e)
{
	int ret = 0;
	char name[1024], key[1024] = {0}, value[4096] = {0};

	memset(name,  0, sizeof(name));
	memset(key,   0, sizeof(key));
	memset(value, 0, sizeof(value));

	sscanf(cmdarg, "%s %s %s", name, key, value);
	strtolower(cmdarg);

	ret = module_set("authentication", name, key, value);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 0;
}

static int analyzer_system_vlan(char *cmdarg, struct event *e)
{
	char vlanname[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", vlanname, op, key, value);
	strtolower(vlanname);

	if (strcmp(op, "add") == 0 && strcmp(key, "ipaddr") == 0) {
		unconfig_apache();
		ret = module_add_sub("vlan", vlanname, "ipaddr", value);
		/**添加或删除IP后，网络相关配置需要重新生效**/
		config_apache(0, 0);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "ipaddr") == 0) {
		unconfig_apache();
		ret = module_del_sub("vlan", vlanname, "ipaddr", value);
		/**添加或删除IP后，网络相关配置需要重新生效**/
		config_apache(0, 0);

		/** Below is for bonding interface **/
	} else if (strcmp(op, "add") == 0 && strcmp(key, "interface") == 0) {
		ret = module_add_sub("vlan", vlanname, "vlan_ifname", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "interface") == 0) {
		ret = module_del_sub("vlan", vlanname, "vlan_ifname", value);

		/** default set **/
	} else {
		ret = module_set("vlan", vlanname, op, key);

		/** After vlanid was setted ok, set  interface's vlanid **/
		if (ret==0 && strcmp(op, "vlanid")==0) {
			vlan_update_interface_vlanid(vlanname, key);
			config_rtable_merge();
			add_all_route_and_gateway_to_system();
		}

		if (ret == 0 && (strcmp(op, "web_enable") == 0 
					|| strcmp(op, "ssh_enable") == 0 
					|| strcmp(op, "gslb_enable") == 0)) {

			unconfig_apache();
			config_apache(0, 0);
		}
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	restart_routing_daemon();
	return 0;
}

static int analyzer_system_firewall(char *cmdarg, struct event *e)
{
	char name[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", name, op, key, value);
	strtolower(name);

	if (strcmp(op, "add") == 0 && strcmp(key, "iplist") == 0) {
		ret = module_add_sub("firewall", name, "iplist", value);
	} else if (strcmp(op, "delete") == 0 && strcmp(key, "iplist") == 0) {
		ret = module_del_sub("firewall", name, "iplist", value);

	} else {
		ret = module_set("firewall", name, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 0;
}

static int analyzer_system_walk4rs(char *cmdarg, struct event *e)
{
	int ret = 0;
	char op[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s", op, key, value);

	if (strcmp(op, "add") == 0 && strcmp(key, "network") == 0) {
		iptables_snmpwalk_rs(NULL, 0);
		ret = module_set("walk4rsnetwork", value, op, key);
		iptables_snmpwalk_rs(NULL, 1);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "network") == 0) {
		iptables_snmpwalk_rs(NULL, 0);
		ret = module_delete("walk4rsnetwork", value);
		iptables_snmpwalk_rs(NULL, 1);
	} else {
		return -1;
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 0;
}

//script4 system vcenter_conntest vcenter vcenter 192.168.8.254 administrator Aa123456
static int analyzer_system_vcenter_conntest(char *cmdarg, struct event *e)
{
	int ret = 0;
	char name[256] = {0};
	char type[256] = {0};
	char server[256] = {0};
	char user[256] = {0};
	char password[256] = {0};

	sscanf(cmdarg, "%s %s %s %s %s", name, type, server, user, password);
	strtolower(name);

	if(strcmp(type, "vcenter") == 0) {
		ret = vcentet_conntest_loop(name, server, user, password);
	
	} else if(strcmp(type, "xenserver") == 0) {
		char url[1024] = {0};
		sprintf(url, "https://%s", server);
		ret = xenserver_connection_test_loop(url, user, password);	
	}
	
	if (ret == 0) {
		write_return_status(e->event_fd, -SMARTGRID_VCENTER_CONNTEST_ERROR);
		return -1;
	}
	return 0;
}

static int analyzer_system_interface(char *cmdarg, struct event *e)
{
	int ret = 0;
	char ifname[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s %s", ifname, op, key, value);

	/** Below is for bonding interface **/
	if (strcmp(op, "add") == 0 && strcmp(key, "interface") == 0) {
		ret = module_add_sub("interface", ifname, "interface", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "interface") == 0) {
		ret = module_del_sub("interface", ifname, "interface", value);

		/** Below is for trunk interface **/
	} else if (strcmp(op, "permit") == 0 || strcmp(op, "deny") == 0) {
		ret = interface_trunk_set(ifname, op, key, value);

		/** default set **/
	} else {
		ret = module_set("interface", ifname, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	restart_routing_daemon();
	return 0;
}

static int analyzer_system_snat (char *cmdarg, struct event *e)
{
	/** dest/netmask key value **/
	int ret = 0;
	char name[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s", name, key, value);

	ret = module_set("snat", name, key, value);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 0;
}

/* script4 system dnat destto add dnat_dest dest */
static int analyzer_system_dnat (char *cmdarg, struct event *e)
{
	char name[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", name, op, key, value);
	strtolower(name);

	if (strcmp(op, "add") == 0 && strcmp(key, "dnat_dest") == 0) {
		ret = module_add_sub("dnat", name, "dnat_dest", value);
	} else if (strcmp(op, "delete") == 0 && strcmp(key, "dnat_dest") == 0) {
		ret = module_del_sub("dnat", name, "dnat_dest", value);
	} else {
		ret = module_set("dnat", name, op, key);
	}

	if (ret) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 0;
}

static int analyzer_system_rtable (char *cmdarg, struct event *e)
{
	/** dest/netmask key value **/
	int ret = 0;
	char name[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s %s", name, op, key, value);
	if (strcmp(op, "add") == 0 && strcmp(key, "route") == 0) {
		ret = module_add_sub("rtable", name, "route", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "route") == 0) {
		ret = module_del_sub("rtable", name, "route", value);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "s-route") == 0) {
		ret = module_add_sub("rtable", name, "s-route", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "s-route") == 0) {
		ret = module_del_sub("rtable", name, "s-route", value);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "ospf") == 0) {
		ret = module_add_sub("rtable", name, "ospf", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "ospf") == 0) {
		ret = module_del_sub("rtable", name, "ospf", value);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "rip") == 0) {
		ret = module_add_sub("rtable", name, "rip", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "rip") == 0) {
		ret = module_del_sub("rtable", name, "rip", value);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "neighbor") == 0) {
		ret = module_add_sub("rtable", name, "neighbor", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "neighbor") == 0) {
		ret = module_del_sub("rtable", name, "neighbor", value);
	} else {
		ret = module_set("rtable", name, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	restart_routing_daemon();
	return 0;
}

static int analyzer_system_arptable (char *cmdarg, struct event *e)
{
	int ret = 0;
	char name[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s %s", name, op, key, value);
	if (strcmp(op, "add") == 0 && strcmp(key, "arp") == 0) {
		ret = module_add_sub("arptable", name, "arp", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "arp") == 0) {
		ret = module_del_sub("arptable", name, "arp", value);
	} else {
		ret = module_set("arptable", name, key, value);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 0;
}

static int analyzer_system_floatip (char *cmdarg, struct event *e)
{
	int ret = 0;
	char name[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s %s", name, op, key, value);
	if (strcmp(op, "add") == 0 && strcmp(key, "ip") == 0) {
		ret = module_add_sub("floatip", name, "ip", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "ip") == 0) {
		ret = module_del_sub("floatip", name, "ip", value);
	} else {
		ret = module_set("floatip", name, key, value);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	restart_routing_daemon();
	return 0;

}

static int analyzer_system_topologyfiles(char *cmdarg, struct event *e)
{
	char name[BUFSIZ] = {0};
	sscanf(cmdarg, "%s %*s", name);

	//base64_decode((uint8_t *)file, name, sizeof(file));

	module_set("topologyfiles", name, NULL, NULL);
	return 0;
}

static int analyzer_system_errpages(char *cmdarg, struct event *e)
{
	char name[BUFSIZ] = {0};
	char file[BUFSIZ];
	sscanf(cmdarg, "%s %*s", name);

	base64_decode((uint8_t *)file, name, sizeof(file));

	module_set("errpages", file, NULL, NULL);
	return 0;
}

static int analyzer_system_healthcheck(char *cmdarg, struct event *e)
{	
	int ret = 0;
	char hname[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s", hname, key, value);	
	strtolower(hname);

	ret = module_set("healthcheck", hname, key, value);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
	return 1;
}

/*
 * analyzer_system_hb: HA process routine
 * @cmdarg: smarthb state MASTER [VRRP]
 * @e: tcp connection event
 */
static int analyzer_system_hb(char *cmdarg, struct event *e)
{
	int ret = 0;
	char hbname[64] = {0}, attr[64] = {0}, value[64] = {0}, other[64] = {0};

	sscanf(cmdarg, "%s %s %s %s", hbname, attr, value, other);

	if (strcmp(attr, "interface")==0
			|| strcmp(attr, "addif")==0
			|| strcmp(attr, "delif")==0 ) {
		strtolower(cmdarg);
	}

	if (strcmp(attr, "state")!=0 
			&& strcmp(attr, "verifycode")!=0 
			&& strcmp(attr, "backup_state")!=0 ) {
		sscanf(cmdarg, "%s %s %s %s", hbname, attr, value, other);
	}

	if (!strcasecmp(attr, "addif") || !strcasecmp(attr, "delif")) {
		if (!strcasecmp(attr, "addif"))
			ret = module_add_sub("hb", hbname, "ifname", value);
		else
			ret = module_del_sub("hb", hbname, "ifname", value);

		return 0;
	} else {

		if (!strcasecmp(attr, "config")) {		// config sync
			hb_config_sync(e, HB_SYNC_TYPE_SLB);
			return 0;
		} else if (!strcasecmp(attr, "llb_conn")) {		// llb_conn sync
			/* script4 system hb smarthb llb_conn sync */
			syslog(LOG_INFO, "%s:%d script4 system hb smarthb llb_conn sync.\n", __func__, __LINE__);
			hb_config_sync(e, HB_SYNC_TYPE_LLB);
			return 0;
		} 

		if (!strcasecmp(attr, "backup_state")) {
			if (value[0] == 0) {
				return 0;
			}
		}

		if (strcmp(attr, "enable") == 0) {
			hb_enable_set(e, value);
		} else if (strcasecmp(other, "VRRP") == 0) {
			hb_switch_notify(value, e);
		} else {
			ret = module_set("hb", hbname, attr, value);

			if (strcasecmp(other, "FORCE") == 0) { /** 强制切换 **/
				hb_switch_force(value);
			}
		} 
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	/*
	 * Don't create new config if command sent by keepalived:vrrp,
	 * else create vrrp config.
	 */
	if (strcasecmp(other, "VRRP") == 0) {
		return 0;	// return 0 by fanyf at 2012-06-11
	}
	return 1;		// call generate, inform 
}

/*
 * @snmpname: smartsnmp, can't modifiable.
 * @attr: enable, community
 */
static int analyzer_system_snmp(char *cmdarg, struct event *e)
{
	int ret = 0;
	char snmpname[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};

	sscanf(cmdarg, "%s %s %s %s", snmpname, op, key, value);

	if (strcmp(op, "add") == 0 && strcmp(key, "user") == 0) {
		snmp_enable_off(e);
		ret = module_add_sub("snmp", snmpname, "user", value);
		snmp_enable_on(e);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "user") == 0) {
		snmp_enable_off(e);
		ret = module_del_sub("snmp", snmpname, "user", value);
		snmp_enable_on(e);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "network") == 0) {
		snmp_iptables_control(0);
		ret = module_add_sub("snmp", snmpname, "network", value);
		snmp_iptables_control(1);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "network") == 0) {
		snmp_iptables_control(0);
		ret = module_del_sub("snmp", snmpname, "network", value);
		snmp_iptables_control(1);
	} else {
		snmp_enable_off(e);
		ret = module_set("snmp", snmpname, op, key);
		snmp_enable_on(e);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 0;
}

static int system_arptimeout(char *cmdarg, struct event *e)
{
	char value[1024] = {0};
	char buff[1024] = {};
	struct if_nameindex *ifnames;
	int i;
	char *token;

	sscanf(cmdarg, "%s", value);

	long timeout = atol(value);
	if (timeout < 0 || timeout > 65535) {
		return -1;
	}

	system("sed -i '/net.ipv4.neigh.default.base_reachable_time/d' /etc/sysctl.conf");

	if (timeout) {
		snprintf(buff, 1023, "echo 'net.ipv4.neigh.default.base_reachable_time=%s' >> /etc/sysctl.conf",
				value);
		system(buff);
	}

	snprintf(buff, 1023, "sysctl -w net.ipv4.neigh.default.base_reachable_time=%s", value);
	system(buff);

	if ((ifnames = if_nameindex()) == NULL) 
		return -1;

	for (i = 0; ifnames[i].if_name != NULL; i++) {
		/* convert e1.2 to e1/2 */
		if ((token = strrchr(ifnames[i].if_name, '.')) != NULL) {
			*token = '/';
		}
		snprintf(buff, 1023, "sysctl -w net.ipv4.neigh.%s.base_reachable_time=%s",
				ifnames[i].if_name, value);

		system(buff);
	}

	if_freenameindex(ifnames);
	return 0;
}

static int system_syncookie(char *cmdarg, struct event *e)
{
	char value[1024] = {0};

	sscanf(cmdarg, "%s", value);

	if (!strcmp(value, "on")) {
		system("sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf");
		system("echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf");
		system("sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null");
	} else if (!strcmp(value, "off")) {
		system("sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf");
		system("sysctl -w net.ipv4.tcp_syncookies=0 > /dev/null");
	}
	return 0;
}

static int system_reboot(char *cmdarg, struct event *e)
{
	//record_admin_log("0.0.0.0", "系统重新启动", SMARTLOG_REBOOT);
	sync();
	system("reboot");
	return 0;
}

static int system_poweroff(char *cmdarg, struct event *e)
{
	//record_admin_log("0.0.0.0", "系统关机", SMARTLOG_REBOOT);
	sync();
	system("shutdown -h now");
	return 0;
}

static int user_config_save(void)
{
	char mysqlcmd[512] = {'\0',};
#define MYSQLDUMP_USER "/SmartGrid/mysql/bin/mysqldump -u root WiseGrid user > /tmp/user_config_save.sql 2>&1"

	snprintf(mysqlcmd, sizeof(mysqlcmd)-1, "%s", MYSQLDUMP_USER);
	system(mysqlcmd);
	
	memset(mysqlcmd, '\0', sizeof(mysqlcmd));
	snprintf(mysqlcmd, sizeof(mysqlcmd)-1, "cp -af /tmp/user_config_save.sql  %s/.config/ 2>&1", CONFIG_PORT_BASE_PATH);
	system(mysqlcmd);
	
	memset(mysqlcmd, '\0', sizeof(mysqlcmd));
	snprintf(mysqlcmd, sizeof(mysqlcmd)-1, "rm -f /tmp/user_config_save.sql 2>&1");
	system(mysqlcmd);
#undef MYSQLDUMP_USER

	return 0;
}


static int user_config_restore(void)
{
	char mysqlcmd[512] = {'\0',};
#define MYSQLIMPORT_USER "/SmartGrid/mysql/bin/mysql -u root -D WiseGrid"
	
	snprintf(mysqlcmd, sizeof(mysqlcmd)-1, "%s < /tmp/_upload_from_apache/config/tmp/.config/user_config_save.sql" 
				" 2>&1", MYSQLIMPORT_USER);
	system(mysqlcmd);

	memset(mysqlcmd, '\0', sizeof(mysqlcmd));
	snprintf(mysqlcmd, sizeof(mysqlcmd)-1, "rm -f /tmp/_upload_from_apache/config/tmp/.config/user_config_save.sql 2>&1");
	system(mysqlcmd);
#undef MYSQLIMPORT_USER 

	return 0;
}

/* 配置根目录结构如下：
 * smartgrid_config/
 * ++++++++++++++++/llb_config.xml
 * ++++++++++++++++/gslb_vserver_config.xml
 * ++++++++++++++++/gslb_listener_config.xml
 * ++++++++++++++++/topology_config.xml
 * ++++++++++++++++/config_slb
 * ++++++++++++++++/...
 */
static int smart_config_save(void)
{
	char command[4096];

	sprintf(command, "rm -fr %s", CONFIG_DIRECTORY_BASE_PATH);
	system(command);

	sprintf(command, "mkdir -p %s", CONFIG_DIRECTORY_BASE_PATH);
	system(command);

	sprintf(command, "chown daemon:daemon %s", CONFIG_DIRECTORY_BASE_PATH);
	system(command);

	sprintf(command, "rm -rf %s >/dev/null 2>&1 ", CONFIG_PORT_BASE_PATH);
	system(command);

	/* Command: mkdir /tmp/smartgrid_config/.config */
	sprintf(command, "mkdir -p %s/.config >/dev/null 2>&1", CONFIG_PORT_BASE_PATH);
	system(command);

	sprintf(command, "mkdir -p %s/config_slb >/dev/null 2>&1", CONFIG_PORT_BASE_PATH);
	system(command);

	/** 杂项导出 **/

	/** 保存admin密码 **/
	sprintf(command, "cat /etc/shadow | grep -w wsadmin > %s/.config/system_admin_passwd.txt", CONFIG_PORT_BASE_PATH);
	system(command);

	/** 保存 主机名称 **/
	sprintf(command, "cp -af /etc/sysconfig/network /etc/hosts %s/.config", CONFIG_PORT_BASE_PATH);
	system(command);

	/** 保存 httpd.conf **/
	sprintf(command, "cp -af /SmartGrid/apache/conf/extra/httpd-ssl.conf %s/.config", CONFIG_PORT_BASE_PATH);
	system(command);

	/** 保存 ifcfg-mgmt **/
	if (access(MGMT_CONFIG, F_OK) == 0) {
		sprintf(command, "cp -af "MGMT_CONFIG" %s/.config", CONFIG_PORT_BASE_PATH);
	}

	/* 保存用户信息*/
	user_config_save();

	/** tar **/
	/* SLB config export */
	sprintf(command, "cp -af %s %s/config_slb/ >/dev/null 2>&1", CONFIG_DIRECTORY, CONFIG_PORT_BASE_PATH);
	system(command);

	/* GSLB config && listener_configexport */
	sprintf(command, "cp -af %s %s/gslb_vserver_config.xml >/dev/null 2>&1", 
				CONFIG_GSLB_VSERVER_CONFIG_FILE, CONFIG_PORT_BASE_PATH);
	system(command);

	sprintf(command, "cp -af %s %s/gslb_listener_config.xml >/dev/null 2>&1", 
				CONFIG_GSLB_LISTENER_CONFIG_FILE, CONFIG_PORT_BASE_PATH);
	system(command);

	/* LLB config export */
	sprintf(command, "cp  %s %s/llb_config.xml >/dev/null 2>&1", 
				CONFIG_LLB_CONFIG_FILE, CONFIG_PORT_BASE_PATH);
	system(command);

	/* Topology config export */
	sprintf(command, "cp  %s %s/topology_config.xml >/dev/null 2>&1", 
				CONFIG_GSLB_CONFIG_TOPOLOGY_FILE, CONFIG_PORT_BASE_PATH);
	system(command);

	/* TAR */
	/* tar -cjvf /tmp/_upload_from_apache/config/config_save.tar.bz2 /tmp/smartgrid_config */
	memset(command, 0, sizeof(command));
	sprintf(command, "tar -jcf %s %s >/dev/null 2>&1", 
				CONFIG_DIRECTORY_SAVE_TARBZ2, CONFIG_PORT_BASE_PATH);
	system(command);

	/** Encode **/
	/* /tmp/_upload_from_apache/config/config_save.tar.bz2 -> /tmp/_upload_from_apache/config/config_save.enc */
	sprintf(command, "openssl enc -aes-128-cbc -in %s -out %s -pass pass:%s",
			CONFIG_DIRECTORY_SAVE_TARBZ2, CONFIG_DIRECTORY_SAVE_ENC, CONFIG_SAVE_ENC_PASS);
	system(command);

	/** Base64 **/
	/* /tmp/_upload_from_apache/config/config_save_enc -> /tmp/_upload_from_apache/config/config_save */
	sprintf(command, "openssl base64  -in %s -out %s",
			CONFIG_DIRECTORY_SAVE_ENC, CONFIG_DIRECTORY_SAVE_BASE64);
	system(command);	

	/* chmod 666  /tmp/_upload_from_apache/config/config_save.tar.bz2 */
	chmod(CONFIG_DIRECTORY_SAVE_BASE64, 0666);

	/* RM base64 && encode file */
	memset(command, 0, sizeof(command));
	sprintf(command, "rm %s %s > /dev/null 2>&1 ", 
			CONFIG_DIRECTORY_SAVE_ENC, CONFIG_DIRECTORY_SAVE_TARBZ2);
	system(command);

	/* RM /tmp/smartgrid_config/ */
	sprintf(command, "rm -fr %s >/dev/null 2>&1", CONFIG_PORT_BASE_PATH);
	system(command);

	return 0;
}


/* 配置根目录结构如下：
 * smartgrid_config/
 * ++++++++++++++++/llb_config.xml
 * ++++++++++++++++/gslb_vserver_config.xml
 * ++++++++++++++++/gslb_listener_config.xml
 * ++++++++++++++++/topology_config.xml
 * ++++++++++++++++/config_slb/
 * ++++++++++++++++/...
 */
static int smart_config_restore(struct event *e)
{
	int ret = 0;
	char command[4096];

	/** base64 **/
	sprintf(command, "openssl base64  -d -in %s -out %s",
			CONFIG_DIRECTORY_SAVE_BASE64, CONFIG_DIRECTORY_SAVE_ENC);
	system(command);

	/** decode **/
	sprintf(command, "openssl enc -d -aes-128-cbc -in %s -out %s -pass pass:%s",
			CONFIG_DIRECTORY_SAVE_ENC, CONFIG_DIRECTORY_SAVE_TARBZ2, CONFIG_SAVE_ENC_PASS);
	system(command);

	/** untar **/
	memset(command, 0, sizeof(command));
	snprintf(command, sizeof(command) - 1, "tar -jxf %s -C %s 2>/dev/null",
			CONFIG_DIRECTORY_SAVE_TARBZ2, CONFIG_DIRECTORY_BASE_PATH);
	/* config_save.tar.bz2  -> smartgrid_config */

	ret = system(command);
	
	if (WEXITSTATUS(ret) != 0) {
		WRITE_BACK(e, "EBADF\n");
		return -1;
	}

	/* restore other */
	/* /tmp/_upload_from_apache/config/tmp/smartgrid_config/.config/system_admin_passwd.txt */
	sprintf(command, "%s/%s/.config/system_admin_passwd.txt", 
				CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "if [ `wc %s/%s/.config/system_admin_passwd.txt "
				"| awk '{print $1}'` = 1 ]; then\n"
				"sed -i '/^wsadmin:/d' /etc/shadow;\n"
				"cat %s/%s/.config/system_admin_passwd.txt >> /etc/shadow;\n"
				"fi", 
				CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH, 
				CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
		system(command);
	}

	sprintf(command, "%s/%s/.config/hosts", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/.config/hosts /etc/hosts", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
		system(command);
	}

	sprintf(command, "%s/%s/.config/network", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/.config/network /etc/sysconfig/network", 
					CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
		system(command);
	}

	sprintf(command, "%s/%s/.config/httpd-ssl.conf", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command,  F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/.config/httpd-ssl.conf /SmartGrid/apache/conf/extra/", 
					CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
		system(command);
	}

	sprintf(command, "%s/%s/.config/ifcfg-mgmt", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/.config/ifcfg-mgmt /etc/sysconfig/network-scripts/",
					CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
		system(command);
	}

	/* 导入用户管理信息 */
	user_config_restore();

	/* restore SLB config */
	system("rm -fr "CONFIG_DIRECTORY);
	sprintf(command, "cp -af %s/%s/config_slb/config{,.xml} /SmartGrid/", 
				CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	system(command);

	/* restore LLB config */
	sprintf(command, "%s/%s/llb_config.xml", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/llb_config.xml %s", 
			CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH, CONFIG_LLB_CONFIG_FILE);
		system(command);
	}

	/* restore GSLB config */
	sprintf(command, "%s/%s/gslb_vserver_config.xml", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/gslb_vserver_config.xml %s", 
			CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH, CONFIG_GSLB_VSERVER_CONFIG_FILE);
		system(command);
	}

	sprintf(command, "%s/%s/gslb_listener_config.xml", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/gslb_listener_config.xml %s", 
			CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH, CONFIG_GSLB_LISTENER_CONFIG_FILE);
		system(command);
	}

	/* resotre topology config */
	sprintf(command, "%s/%s/topology_config.xml", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	if (access(command, F_OK) == 0) {
		sprintf(command, "cp -af %s/%s/topology_config.xml %s", 
			CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH, CONFIG_GSLB_CONFIG_TOPOLOGY_FILE);
		system(command);
	}

	sprintf(command, "rm -fr %s/%s", CONFIG_DIRECTORY_BASE_PATH, CONFIG_PORT_BASE_PATH);
	system(command);

	system("cp -af "CONFIG_ORIG_FILE" "CONFIG_FILE);
	system("/SmartGrid/shell/upgrade_netmask mask2bits >/dev/null 2>&1");

	system("reboot");

	return 0;
}

/**
 * config: /etc/sysconfig/network-scripts/ifcfg-mgmt
 * DEVICE=mgmt
 * BOOTPROTO=static
 * IPADDR=192.168.10.2
 * NETMASK=255.255.255.0
 * GATEWAY=192.168.10.1
 * ONBOOT=yes
 **/
static int write_mgmt_config(char *ip, char *mask)
{
	FILE *fp;

	if ((fp = fopen(MGMT_CONFIG, "w")) == NULL)
		goto out;

	fprintf(fp, "%s=%s\n", "DEVICE", "mgmt");
	fprintf(fp, "%s=%s\n", "BOOTPROTO", "static");
	fprintf(fp, "%s=%s\n", "IPADDR", ip);
	fprintf(fp, "%s=%s\n", "NETMASK", mask);
	fprintf(fp, "%s=%s\n", "ONBOOT", "yes");

	fclose(fp);
out:
	return 0;
}

static int write_dns_config(char *dns1, char *dns2)
{
	FILE *fp;

	if ((fp = fopen("/etc/resolv.conf", "w")) == NULL)
		goto out;

	if (strlen(dns1) > 5)
		fprintf(fp, "nameserver\t%s\n", dns1);
	if (strlen(dns2) > 5)
		fprintf(fp, "nameserver\t%s\n", dns2);

	fclose(fp);
out:
	return 0;
}

static int smart_config_restore_default(struct event *e)
{
	extern int merge_default_config_file(void);

	snmp_enable_off(e);

	unlink("/dev/shm/config.xml");
	unlink("/SmartGrid/config/config.xml");
	unlink("/SmartGrid/hb_config.xml");
	unlink("/SmartGrid/config.xml");

	unlink("/SmartGrid/llb_config/config.xml");
	unlink("/SmartGrid/gslb_config/config.xml");
	unlink("/SmartGrid/gslb_config.xml");
	unlink("/SmartGrid/topology_config.xml");

	system("rm -fr /SmartGrid/config/{certs,crl}");
	/* Add by liuxp for BUG 2137 at 2013.9.17 */
	system("rm -fr /SmartGrid/config/errpages/*");

	merge_default_config_file();

	system("passwd wsadmin > /dev/null 2>/dev/null << FOE\n"
			"sinogrid\n"
			"sinogrid\n"
			"FOE");

	/* Add by liuxp for BUG 2156. 2013.10.8 */
	system("mysql > /dev/null 2>&1 << EOF\n"
			"use WiseGrid;\n"
			"delete from user;\n"
			"INSERT INTO user (id, username, password, role, authtype, permission) "
			"	VALUES(1, 'admin', 'ef9ffdf6c1e2fe91d4e14b30323fb771', 'superadmin', 'LOCAL', NULL);\n"
			"EOF");

	unlink("/SmartGrid/apache/conf/extra/httpd-ssl.conf");
	if (mgmt_exists()) {
		write_mgmt_config("192.168.1.1", "255.255.255.0");
	}
	truncate("/etc/resolv.conf", 0);

	unlink("/SmartGrid/config/userconfig/user.conf");

	system("cat > /etc/hosts << EOF\n"
			"127.0.0.1		localhost.localdomain localhost\n"
			"::1			localhost.localdomain6 localhost6\n"
			"EOF");

	system("cat > /etc/sysconfig/network << EOF\n"
			"NETWORKING=yes\n"
			"NETWORKING_IPV6=yes\n"
			"HOSTNAME=localhost.localdomain\n"
			"EOF");

	/** 重新启动snmpd **/
	snmp_enable_on(e);	/* Control */

	/* restore config and reboot computer */
	system("sync");
	system("reboot");

	return 0;
}


static void do_check_mgmt_conf_file(void)
{
	if (access(MGMT_CONFIG, F_OK) == 0) {
		return;
	}

	system("cat > "MGMT_CONFIG" << EOF\n"
			"DEVICE=mgmt\n"
			"BOOTPROTO=static\n"
			"ONBOOT=yes\n"
			"EOF\n");
}



static int do_mgmt_ipv4_config(char *ip, char *netmask)
{
	char orig_ip[256], orig_netmask[256];
	char buff[BUFSIZ];

	do_check_mgmt_conf_file();

	if (strcmp(netmask, "") == 0 || strcmp(netmask, "0") == 0) {
		strcpy(netmask, "24");
	}

	get_mgmt_ipv4(orig_ip, orig_netmask);

	trim(ip);
	trim(netmask);
	trim(orig_ip);
	trim(orig_netmask);

	sprintf(buff, "ip addr del %s/%s dev mgmt", orig_ip, orig_netmask);
	system(buff);

	sprintf(buff, "ip addr add %s/%s dev mgmt", ip, netmask);
	system(buff);

	sprintf(buff, "sed -i '/^IPADDR/d' "MGMT_CONFIG);
	system(buff);
	sprintf(buff, "sed -i '/^NETMASK/d' "MGMT_CONFIG);
	system(buff);

	sprintf(buff, "echo \"IPADDR=%s\" >> "MGMT_CONFIG, ip);
	system(buff);

	bits2mask(netmask, netmask);
	sprintf(buff, "echo \"NETMASK=%s\" >> "MGMT_CONFIG, netmask);
	system(buff);
	return 0;
}

static int do_mgmt_ipv6_config(char *ip, char *netmask)
{
	char orig_ip[256], orig_netmask[256];
	char buff[BUFSIZ];

	do_check_mgmt_conf_file();

	if (strcmp(netmask, "") == 0 || strcmp(netmask, "0") == 0) {
		strcpy(netmask, "64");
	}

	get_mgmt_ipv6(orig_ip, orig_netmask);

	trim(ip);
	trim(netmask);
	trim(orig_ip);

	sprintf(buff, "ip -6 addr del %s/%s dev mgmt", orig_ip, orig_netmask);
	system(buff);

	sprintf(buff, "ip -6 addr add %s/%s dev mgmt", ip, netmask);
	system(buff);

	sprintf(buff, "sed -i '/^IPV6INIT/d' "MGMT_CONFIG);
	system(buff);
	sprintf(buff, "sed -i '/^IPV6ADDR/d' "MGMT_CONFIG);
	system(buff);

	sprintf(buff, "echo 'IPV6INIT=yes' >> "MGMT_CONFIG);
	system(buff);
	sprintf(buff, "echo 'IPV6ADDR=%s/%s' >> "MGMT_CONFIG, ip, netmask);
	system(buff);

	//system("ifup mgmt");
	return 0;
}


/*
 * system_sys: hostname, date, config flush etc...
 */
static int system_sys(char *cmdarg, struct event *e)
{
	int ret = 0;
	char op[256];
	char value[256], value2[256];
	char command[1024];

	memset(op, 0, sizeof(op));
	memset(value, 0, sizeof(value));
	memset(value2, 0, sizeof(value2));
	sscanf(cmdarg, "%s %s %s", op, value, value2);

	memset(command, 0, sizeof(command));
	if (!strcasecmp(op, "tcpdump")) {
		char argument[512];

		memset(argument, 0, sizeof(argument));
		base64_decode((uint8_t *)argument, value, sizeof(argument));
		tcpdump_start(argument);
	} else if (!strcasecmp(op, "congestion")) {
		/** cmd: system congestion <method> **/
		set_tcp_congestion_control(value);
	} else if (!strcasecmp(op, "webport")) {
		unconfig_apache();
		config_apache(atoi(value), atoi(value2));
	} else if (!strcasecmp(op, "webtimeout")) {
		unconfig_apache();
		config_apache(0, atoi(value));
	} else if (!strcasecmp(op, "timezone")) {
		memset(command, 0, sizeof(command));
		snprintf(command, 
				sizeof(command) - 1, 
				"sed -i 's/ZONE.*/ZONE=\"%s\"/g' /etc/sysconfig/clock", 
				value);
		system(command);
	} else if (!strcasecmp(op, "system_control")) {
		if (!strcasecmp(value, "shutdown")) {
			system("shutdown -h now");
		} else if (!strcasecmp(value, "reboot")) {
			system("reboot");
		}
#if 0
	} else if (!strcasecmp(op, "sshd_enable")) {
		if (!strcasecmp(value, "on"))
			system("/etc/init.d/sshd start");
		else
			system("/etc/init.d/sshd stop");
#endif
	} else if (!strcasecmp(op, "mgmtip_show")) {
		char ip[256], netmask[256];
		char buff[BUFSIZ];

		get_mgmt_ipv4(ip, netmask);
		sprintf(buff, "IPV4=%s/%s\n", ip, netmask);
		write(e->event_fd, buff, strlen(buff));

		get_mgmt_ipv6(ip, netmask);
		sprintf(buff, "IPV6=%s/%s\n", ip, netmask);
		write(e->event_fd, buff, strlen(buff));

	} else if (!strcasecmp(op, "mgmtip") || !strcasecmp(op, "mgmt6ip")) {
		/** value ==> ip/netmask **/
		char ip[STR_IP_LEN], netmask[STR_NETMASK_LEN];
		int version;

		if (value[0] == 0) {
			return 0;
		}

		/** 检查IP地址是否合法 **/
		if(check_address_format(value)!=0){
			return -1;
		}

		/** 取消apache的IP地址侦听 **/
		unconfig_apache();

		get_ip_netmask2(value, ip, netmask);

		if ((version = check_ip_version(ip))==-1) {
			return -1;
		}

		if (version == IPV4) {
			do_mgmt_ipv4_config(ip, netmask);
		} else if (version == IPV6) {
			do_mgmt_ipv6_config(ip, netmask);
		}

		/** flush route**/
		config_rtable_merge();
		send_ip_modified_arp("mgmt", ip);

		/** 使用新的IP地址配置apache的侦听 **/
		config_apache(0, 0);

	} else if (!strcasecmp(op, "dns")) {
		write_dns_config(value, value2);
	} else if (!strcasecmp(op, "date") || !strcasecmp(op, "time")) {

		if (strcmp(op, "date") == 0) {
			snprintf(command, sizeof(command) - 1, "date -s \"%s `date +%%T`\" >/dev/null 2>&1", value);
		} else {
			snprintf(command, sizeof(command) - 1, "date -s %s >/dev/null 2>&1", value);
		}
		int ret = system(command);
		if( ret<0 || WEXITSTATUS(ret) != EXIT_SUCCESS){
			write_return_status(e->event_fd, -EBUSY);
			return -1;
		}

		//system("hwclock -w");
		system("hwclock --systohc");
	} else if (!strcasecmp(op, "hostname")) {
		snprintf(command, sizeof(command) - 1, "hostname %s", value);
		system(command);

		memset(command, 0, sizeof(command));
		snprintf(command, sizeof(command) - 1,
				"sed -i 's/HOSTNAME=.*/HOSTNAME=%s/g' /etc/sysconfig/network",
				value);
		system(command);

		//sprintf(command, "sed -i ### /etc/hosts", );
		sprintf(command, "sed -i 's@127.0.0.1.*@127.0.0.1\t"
				"localhost.localdomain localhost %s@' /etc/hosts",
				value);
		system(command);



	} else if (!strcasecmp(op, "config") && !strcasecmp(value, "flush")) {
		return 1;
	} else if (!strcasecmp(op, "config") && !strcasecmp(value, "save")) {
		smart_config_save();
	} else if (!strcasecmp(op, "config") && !strcasecmp(value, "restore")) {
		smart_config_restore(e);
	} else if (!strcasecmp(op, "config") && !strcasecmp(value, "restore_default")) {
		smart_config_restore_default(e);
	} else if (!strcmp(op, "upgrade")) {
		/** upgrade packet(base64) checksum(base64) **/

#ifndef VERSION
#define VERSION "V0.0.1T"
#endif
		ret = sys_upgrade(value, VERSION);
		write_return_status(e->event_fd, ret);
	} else if (!strcmp(op, "serial-number")) {
		char serial[BUFSIZ];
		if (license_show_serial_number(serial) != 0) {
			return -1;
		}
		WRITE_BACK(e, serial);
	} else if (strcmp(op, "crashlog") == 0) {
		char buff[BUFSIZ];
		time_t now;
		struct tm tm;

		now = time(NULL);
		localtime_r(&now, &tm);

		system("rm -fr /tmp/crashlog* && mkdir -p /tmp/crashlog");

		/** 命令 **/
		system("ip addr list > /tmp/crashlog/ip.log");
		system("netstat -anpt > /tmp/crashlog/netstat.log");
		system("brctl show > /tmp/crashlog/brctl.log");
		system("ps -aux > /tmp/crashlog/ps_aux.log");
		system("top -n1 > /tmp/crashlog/top_n1.log");
		system("cat /proc/net/ip_vs > /tmp/crashlog/ip_vs");
		system("cat /proc/net/ip_vs_conn > /tmp/crashlog/ip_vs_conn");
		system("iptables -t filter -nvL > /tmp/crashlog/iptables_filter.log");
		system("iptables -t mangle -nvL > /tmp/crashlog/iptables_mangle.log");
		system("iptables -t nat -nvL > /tmp/crashlog/iptables_nat.log");
		system("ip6tables -t filter -nvL > /tmp/crashlog/ip6tables_filter.log");
		system("ip6tables -t mangle -nvL > /tmp/crashlog/ip6tables_mangle.log");
		system("ip6tables -t raw -nvL > /tmp/crashlog/ip6tables_raw.log");

		system("ip rule > /tmp/crashlog/ip_rule.log");
		system("for i in `ip rule | awk '{print $NF}' | xargs`; do "
				"ip route list table $i > /tmp/crashlog/ip_rule_$i.log; "
				"done");

		/** mysql **/
		system("mysql > /tmp/crashlog/mysql_tmp_stat.log << EOF\n"
				"use WiseGrid;\n"
				"select * from tmp_stat;\n"
				"EOF");

		system("mysql > /tmp/crashlog/mysql_cpu_stat.log << EOF\n"
				"use WiseGrid;\n"
				"select * from cpu_stat;\n"
				"EOF");

		system("mysql > /tmp/crashlog/mysql_mem_stat.log << EOF\n"
				"use WiseGrid;\n"
				"select * from mem_stat;\n"
				"EOF");

		system("mysql > /tmp/crashlog/mysql_vs_stat.log << EOF\n"
				"use WiseGrid;\n"
				"select * from vs_stat;\n"
				"EOF");

		system("mysql > /tmp/crashlog/mysql_pool_stat.log << EOF\n"
				"use WiseGrid;\n"
				"select * from pool_stat;\n"
				"EOF");

		/** 文件 **/
		system("tar zcPf /tmp/crashlog.log "
				"/var/log/messages "
				"/SmartGrid/config "
				"/SmartGrid/config.xml "
				"/SmartGrid/keepalived/etc "
				"/SmartGrid/smartl7/conf "
				"/SmartGrid/smartl7/html "
				"/dev/shm/config.xml "
				"/dev/shm/keepalived_healthcheck_status "
				"/dev/shm/smartl7_stat "
				"/var/log/keepalived_local.log.0 "
				"/var/log/keepalived.log.0 "
				"/var/log/daemon4_local.log.0 "
				"/var/log/syslog_local.log.0 "
				"/var/log/nginx "
				"/tmp/crashlog >/dev/null 2>&1");

		sprintf(buff, "upgrade -e -i /tmp/crashlog.log -o "
				"/tmp/crashlog.%04d-%02d-%02d_%02d-%02d-%02d.log ", 
				tm.tm_year + 1900, tm.tm_mon + 1, 
				tm.tm_mday, tm.tm_hour,
				tm.tm_min, tm.tm_sec);
		system(buff);

		system("rm -fr /tmp/crashlog{,.log}");
	}

	return 0;
}

static int analyzer_system_cliusers(char *cmdarg, struct event *e)
{

	char username[256] = {0}; 
	char op[256] = {0}; 
	char key[256] = {0}; 
	char value[256] = {0};
	char pwd[256] = {0};
	int ret = 0;

	/* script4 system cliusers admin passwd newpassword */

	sscanf(cmdarg, "%s %s %s %s", username, op, key, value);

	base64_decode( (uint8_t *)pwd, key, sizeof(pwd));

	if (!strcasecmp(op, "passwd"))
		cliusers_encrypt(pwd, sizeof(pwd));

	ret = module_set("user", username, op, pwd);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;
}
static int analyzer_system_gslb_listener(char *cmdarg, struct event *e)
{
	/*
	*script4 system gslb_listener xxx.xxx.xxx.xxx
	*script4 system gslb_listener xxx.xxx.xxx.xxx port xx(1-65535)
	*script4 system gslb_listener xxx.xxx.xxx.xxx protocol udp
	*/
	char ipaddr[32] = {0};
	char op[32] = {0};
	char key[32] = {0};
	char value[32] = {0};
	int ret = 0;
	sscanf(cmdarg, "%s %s %s %s", ipaddr, op, key, value);
	
	ret = module_set("gslb_listener", ipaddr, op, key);
	
	if (ret != 0) {
	  write_return_status(e->event_fd, ret);
	  return -1;
	}
	
	return 1;
}

static int analyzer_system_gslb_vserver(char *cmdarg, struct event *e)
{
	//vsname add schedule master_schedule RR
	char name[512] = {0};
	char op[64] = {0};
	char key[128] = {0};
	char value[128] = {0};
	char order[128] ={0};
	int ret = 0;
	char buf[512] = {0};

	sscanf(cmdarg, "%s %s %s %s %s", name, op, key, value, order );
	if (strcmp(op, "add") == 0 && strcmp(key,"schedule") == 0) {
		sprintf(buf, "%s %s", value, order);
		ret = module_add_sub("gslb_vserver", name, "gslb_scheduler", buf);	
	} else if (strcmp(op, "del") == 0 && strcmp(key,"schedule") == 0) {
		sprintf(buf, "%s %s", value, order);
		ret = module_del_sub("gslb_vserver", name, "gslb_scheduler", buf);	
	} else {
		ret = module_set("gslb_vserver", name, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;
}

static int analyzer_system_gslb_device(char *cmdarg, struct event *e)
{
	int ret = 0;
	char *ptr = NULL;
	char gslb_devicename[BUFSIZ] = {0};
	ptr = strchr(cmdarg, ',');
	if (ptr != NULL) {
		strncpy(gslb_devicename, cmdarg,ptr - cmdarg );
		ret = module_set("gslb_device", gslb_devicename, cmdarg, NULL);
	} else {
		ret = module_set("gslb_device", cmdarg, NULL, NULL);
	}

	if (ret != 0) {
	  write_return_status(e->event_fd, ret);
	  return -1;
	}
return 1;
}

static int analyzer_system_gslb_group(char *cmdarg, struct event *e)
{
	int ret = 0;
	
	char gslb_groupname[1024] = {0};
	char key[1024] = {0};
	char op[1024] = {0};
	char value[1024] = {0};

	sscanf(cmdarg, "%s %s %s %s", gslb_groupname, op, key, value);
	strtolower(gslb_groupname);
	
	if (strcmp(op, "add") == 0 && strcmp(key, "device") == 0) {
		ret = module_add_sub("gslb_group", gslb_groupname, "device", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "device") == 0) {
		ret = module_del_sub("gslb_group", gslb_groupname, "device", value);
	} else {
		ret = module_set("gslb_group", gslb_groupname, op, key);
	}
  if (ret != 0) {
    write_return_status(e->event_fd, ret);
    return -1;
  }
  return 1;
}


static int analyzer_system_tp_node(char *cmdarg, struct event *e)
{
	int ret = 0;

	char name[1024]={0}, key[1024]={0}, op[1024]={0}, value[1024]={0}, order[1024] = {0};
	sscanf(cmdarg, "%s %s %s %s %s", name, op, key, value, order);
	strtolower(name);	
	ret = module_set("tp_node", name, op, key);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
	}
	
	return 1;
	
}

static int __analyzer_system_tp_policy(char *area_carrier, char *key, 
						char *value, char *config_file)
{
	char *o_config = NULL;
	int ret = 0;

	module_config_change("tp_policy", config_file, &o_config);
	ret = module_set("tp_policy", area_carrier, key, value);
	module_config_change("tp_policy", o_config, NULL);

	return ret;
}


// tp_policy GSLB/LLB beijing-cnc policy self/network
static int analyzer_system_tp_policy(char *cmdarg, struct event *e)
{
	char type[1024], area_carrier[1024], key[1024], value[1024];
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", type, area_carrier, key, value);
	strtolower(area_carrier);	
/*
	printf("type: %s\n", type);
	printf("area_carrier: %s\n", area_carrier);
	printf("key: %s\n", key);
	printf("value: %s\n", value);
*/
	if (strcasecmp(type, "GSLB") == 0)
		ret = __analyzer_system_tp_policy(area_carrier, key, 
					value, CONFIG_GSLB_CONFIG_FILE);
	else
		ret = __analyzer_system_tp_policy(area_carrier, key, 
					value, CONFIG_LLB_CONFIG_FILE);
	if (ret != 0) 
		write_return_status(e->event_fd, ret);

	return 1;
	
}




static int analyzer_system_bind9_domain(char *cmdarg, struct event *e)
{
	char name[1024]={0}, key[1024]={0}, op[1024]={0}, value[1024]={0}, order[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s %s", name, op, key, value, order);
	strtolower(name);

	if (strcmp(op, "add") == 0 && strcmp(key, "record") == 0) {
		ret = module_add_sub("bind9_domain", name, "bind9_record", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "record") == 0) {
		ret = module_del_sub("bind9_domain", name, "bind9_record", value);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "acl") == 0) {
		ret = module_add_sub("bind9_domain", name, "bind9_acl", value);
	} else if (strcmp(op, "del") == 0 && strcmp(key, "acl") == 0) {
		ret = module_del_sub("bind9_domain", name, "bind9_acl", value);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "soa_record") == 0) {
		ret = module_add_sub("bind9_domain", name, "bind9_soa_record", value);
	} else {
		ret = module_set("bind9_domain", name, op, key);
	}
	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;	/** modified, create configuration of lvs & smartl7 **/
	
}

static int analyzer_system_sysconfig(char *cmdarg, struct event *e)
{
  char name[512] = {0};
  char key[128] = {0};
  char value[128] = {0};
  int ret = 0;

  /* script4 system sysconfig system llbenable off/on */
  sscanf(cmdarg, "%s %s %s", name, key, value);
  ret = module_set("sysconfig", name, key, value);

  if (ret != 0) {
	  write_return_status(e->event_fd, ret);
	  return -1;
  }

  return 1;
}


static int analyzer_system_llb_system(char *cmdarg, struct event *e)
{
  char name[512] = {0};
  char key[128] = {0};
  char value[128] = {0};
  int ret = 0;

  /*  system llb_system gateway 192.168.10.1 */
  sscanf(cmdarg, "%s %s %s", name, key, value);
  ret = module_set("llb_system", name, key, value);

  if (ret != 0) {
	  write_return_status(e->event_fd, ret);
	  return -1;
  }

  return 1;
}


static int analyzer_system_llb_vserver(char *cmdarg, struct event *e)
{
	char name[1024] = {0};
	char op[1024] = {0};
	char key[1024] = {0};
	char value[1024] = {0};
	char order[1024] ={0};
	int ret = 0;
	char buf[1024] = {0};

	sscanf(cmdarg, "%s %s %s %s %s", name, op, key, value, order );

	if (strncmp(op, "add", 3) == 0 && strncmp(key,"schedule", 8) == 0) {
		sprintf(buf, "%s %s", value, order);
		ret = module_add_sub("llb_vserver", name, "llb_scheduler", buf);	
	} else if (strncmp(op, "add", 3) == 0 && strncmp(key,"sourceip", 8) == 0) {
		ret = module_add_sub("llb_vserver", name, "llb_sourceip", value);	
	} else if (strncmp(op, "del", 3) == 0 && strncmp(key,"schedule", 8) == 0) {
		sprintf(buf, "%s %s", value, order);
		ret = module_del_sub("llb_vserver", name, "llb_scheduler", buf);	 
	} else if (strncmp(op, "del", 3) == 0 && strncmp(key,"sourceip", 8) == 0) {
		ret = module_del_sub("llb_vserver", name, "llb_sourceip", value);	
	} else {
		ret = module_set("llb_vserver", name, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;
}

/* script4 system llb_snat xxxx"
 * script4 system llb_snat xxxx add llb_snat_sourceip/llb_snat_transip=2.3.4.5
 * script4 system llb_snat xxxx sched_type=ip_rr,snat_type=snat/nonat */
static int analyzer_system_llb_snat(char *cmdarg, struct event *e)
{
	char snat_name[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};
	int ret = -1;

	sscanf(cmdarg, "%s %s %s %s", snat_name, op, key, value);

	if (strcmp(op, "add") == 0 && strcmp(key, "sourceip") == 0) {
		ret = module_add_sub("llb_snat", snat_name, "sourceip", value);
	} else if (strcmp(op, "delete") == 0 && strcmp(key, "sourceip") == 0) {
		ret = module_del_sub("llb_snat", snat_name, "sourceip", value);
	} else if (strcmp(op, "add") == 0 && strcmp(key, "transip") == 0) {
		ret = module_add_sub("llb_snat", snat_name, "transip", value);
	} else if (strcmp(op, "delete") == 0 && strcmp(key, "transip") == 0) {
		ret = module_del_sub("llb_snat", snat_name, "transip", value);
	} else {
		ret = module_set("llb_snat", snat_name, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;
}

static int analyzer_system_llb_pool(char *cmdarg, struct event *e)
{
	char poolname[1024] = {0}, op[1024] = {0}, key[1024] = {0}, value[1024] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", poolname, op, key, value);
	strtolower(poolname);

	if (strcmp(op, "add") == 0 && strcmp(key, "llb_rserver") == 0) {
		ret = module_add_sub("llb_pool", poolname, "llb_rserver", value);
	} else if (strcmp(op, "delete") == 0 && strcmp(key, "llb_rserver") == 0) {
		ret = module_del_sub("llb_pool", poolname, "llb_rserver", value);
	} else {
		ret = module_set("llb_pool", poolname, op, key);
	}

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 1;
}
static int analyzer_system_smtp(char *cmdarg, struct event *e)
{
	char smtpname[256] = {0}; 
	char op[256] = {0}; 
	char key[256] = {0}; 
	char value[256] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s %s", smtpname, op, key, value);

	if (!strcasecmp(op, "password"))
		password_encrypt(key, sizeof(key));

	ret = module_set("smtp", smtpname, op, key);

	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}

	return 0;
}

static int analyzer_system_ntpdate(char *cmdarg, struct event *e)
{
	char ntpdatename[256] = {0}; 
	char key[256] = {0}; 
	char value[256] = {0};
	int ret = 0;

	sscanf(cmdarg, "%s %s %s", ntpdatename, key, value);

	if (strlen(ntpdatename) == 0 
			|| strlen(key) == 0
			|| strlen(value) == 0)
		goto out;

	ret = module_set("ntpdate", ntpdatename, key, value);
	if (ret != 0) {
		write_return_status(e->event_fd, ret);
		return -1;
	}
out:
	return 0;
}

static int license_upload(char *licensefile)
{
	char buff[BUFSIZ];
	unlink("/SmartGrid/license.lic");
	sprintf(buff, "mv %s /SmartGrid/license.lic", licensefile);
	system(buff);
	return 0;
}

/**
 * LOG module handler: log clean
 */
static int analyzer_system_log(char *cmdarg, struct event *e)
{
	char op[64];

	memset(op, '\0', sizeof(op));
	sscanf(cmdarg, "%s", op);

#define AUDIT_LOGFILE 	"/var/log/syslog_local.log.0"
#define AUDIT_LOGFILE2 	"/var/log/syslog_local.log.{1,2,3,4,5,6,7,8,9,10}"
#define SYSTEM_LOGFILE	"/var/log/messages"
#define RULE_LOGFILE	"/var/log/smartl7/smartl7.log"

	if (!strcasecmp(op, "clean")) {			// audit log
		system("rm -f " AUDIT_LOGFILE2);
		truncate(AUDIT_LOGFILE, 0);

		char details[512];
		char address[512];

		memset(address, 0, sizeof(address));
		get_local_ip(address, sizeof(address));

		memset(details, 0, sizeof(details));
		strcpy(details, "清除审计日志");
		record_admin_log( address, details, SMARTLOG_CLEAN_AUDIT_LOG);
	} else if (!strcasecmp(op, "clean_syslog")) {
		truncate(SYSTEM_LOGFILE, 0);
	} else if (!strcasecmp(op, "clean_rulelog")) {
		truncate(RULE_LOGFILE, 0);
	} else if (!strcasecmp(op, "export_syslog")) {
		system("zip /var/log/system_log.zip /var/log/messages &>/dev/null");
	}

	return 0;
}

/*
 * analyzer_system_license: handle License
 * @op: request, verify
 * @filename: license filename
 */
static int analyzer_system_license(char *cmdarg, struct event *e)
{
	char op[64], htmlfile[512], reqfile[512];

	memset(op, '\0', sizeof(op));
	memset(htmlfile, '\0', sizeof(htmlfile));
	memset(reqfile, '\0', sizeof(reqfile));
	sscanf(cmdarg, "%s %s %s", op, htmlfile, reqfile);

	if (!strcasecmp(op, "upload")) {
		license_upload(htmlfile);
	} else if (!strcasecmp(op, "request")) {
		license_request();
#if 0
	} else if (!strcasecmp(op, "webquery")) {
		license_web_query(e);
#endif
	} else if (!strcasecmp(op, "show")) {
		license_show(e);
	} else {
		return -1;
	}

	return 0;
}

static int analyzer_system(char *cmdarg, struct event *e)
{
	int result = 0, i, j;
	char section[32];

	struct functions *pfuncs = get_funcs();

	struct {
		const char *cmd;
		int (*analyzer)(char *, struct event *);
	} smart_command[] = {
		{"log", analyzer_system_log},
		{"license", analyzer_system_license},
		{"delete", analyzer_system_delete},
		{"authentication", analyzer_system_authentication},
		{"flush_state", analyzer_system_flush_state},
		{"certificate", analyzer_system_certificate},
		{"vserver", analyzer_system_vserver},
		{"pro_vserver", analyzer_system_pro_vserver},
		{"pool", analyzer_system_pool},
		{"vcenter", analyzer_system_vcenter},
		{"healthcheck", analyzer_system_healthcheck},
		{"errpages", analyzer_system_errpages},
		{"topologyfiles", analyzer_system_topologyfiles},
		{"rule", analyzer_system_rule},
		{"interface", analyzer_system_interface},
		{"vlan", analyzer_system_vlan},
		{"snat", analyzer_system_snat},
		{"dnat", analyzer_system_dnat},
		{"rtable", analyzer_system_rtable},
		{"arptable", analyzer_system_arptable},
		{"floatip", analyzer_system_floatip},
		{"hb", analyzer_system_hb},
		{"snmp", analyzer_system_snmp},
		{"dns", analyzer_system_dns},
		{"weblog", analyzer_system_weblog},
		{"forward", analyzer_system_forward},
		{"smtp", analyzer_system_smtp},
		{"reboot", system_reboot},
		{"syncookie", system_syncookie},
		{"arptimeout", system_arptimeout},
		{"poweroff", system_poweroff},
		{"sysconfig", analyzer_system_sysconfig},
		{"sys", system_sys},
		{"cliusers", analyzer_system_cliusers},
		{"ntpdate", analyzer_system_ntpdate},
		{"firewall", analyzer_system_firewall},
		{"conntest", analyzer_system_vcenter_conntest},
		{"gslb_listener", analyzer_system_gslb_listener},
		{"gslb_vserver", analyzer_system_gslb_vserver},
		{"gslb_device", analyzer_system_gslb_device},
		{"gslb_pool", analyzer_system_gslb_pool},
		{"gslb_group", analyzer_system_gslb_group},
		{"tp_node", analyzer_system_tp_node},
		{"tp_policy", analyzer_system_tp_policy},
		{"bind9_domain", analyzer_system_bind9_domain},
		{"llb_vserver", analyzer_system_llb_vserver},
		{"llb_pool", analyzer_system_llb_pool},
		{"llb_system", analyzer_system_llb_system},
		{"llb_snat", analyzer_system_llb_snat},
		{"check_subnet", analyzer_system_check_subnet}, //仅仅是为了判断两个ip/netmask 是否在同一网段
		{"under_gslb", analyzer_system_under_gslb},
		{"sync_group", analyzer_system_sync_group},
		{"firewall", analyzer_system_firewall},
		{"walknetwork", analyzer_system_walk4rs},
	};


	memset(section, '\0', sizeof(section));
	sscanf(cmdarg, "%s", section);	/* delete, certificate, vserver... */

	/* register to analyzer_system_head */
	for (i = 0; i < sizeof(smart_command) / sizeof(smart_command[0]); i ++) {
		for (j = 0; pfuncs[j].id != -1; j++) {
			if (!strcasecmp(smart_command[i].cmd, pfuncs[j].func)) {
				if (pfuncs[j].ch != 'Y' && pfuncs[j].ch != 'y')
					continue;
			}
		}

		register_analyzer(&analyzer_system_head, 
				(char *)smart_command[i].cmd,
				smart_command[i].analyzer); 
	}


	result = run_match_analyzer(&analyzer_system_head, cmdarg, e);

	analyzer_purge(&analyzer_system_head);

	/*  turn to log4c interface */
	if (result == 1 || result == 0) {
		log4c_entrance(cmdarg);
	}

	return result;	/* result: 1 generate smartl7,ipvs config */
}

static int access_config_allowed(const char *cmdarg)
{
	if (strcasestr(cmdarg, "license") != NULL) {
		return 1;
	}

	if (strcasestr(cmdarg, "mgmtip") != NULL 		|| \
			strcasestr(cmdarg, "mgmt6ip") != NULL 	|| \
			strcasestr(cmdarg, "rtable") != NULL 	|| \
			strcasestr(cmdarg, "dns") != NULL 	|| \
			strcasestr(cmdarg, "hostname") != NULL 	|| \
			strcasestr(cmdarg, "interface") != NULL	|| \
			strcasestr(cmdarg, "arp") != NULL 	|| \
			strcasestr(cmdarg, "vlan") != NULL      || \
			strcasestr(cmdarg, "snat") != NULL ) {

		return 1;
	}

	if (strncasecmp(cmdarg, "system sys date", strlen("system sys date")) == 0) {
		return 1;
	}

	if (strncasecmp(cmdarg, "system sys crashlog", strlen("system sys crashlog")) == 0) {
		return 1;
	}

	if (strncasecmp(cmdarg, "system sys serial-number", 
				strlen("system sys serial-number")) == 0) {
		return 1;
	}

	if (strncasecmp(cmdarg, "system reboot", strlen("system reboot")) == 0) {
		return 1;
	}

	if (strncasecmp(cmdarg, "system poweroff", strlen("system poweroff")) == 0) {
		return 1;
	}

	return 0;
}

/* cmdarg form: system vserver httpvs address 172.168.0.13:8082 */
int analyzer_entrance(char *cmdarg, struct event *e)
{
	static int is_license_ok = -1;

	// superkey add by fanyf
#define SUPERKEY "/var/tmp/__superkey__.txt"
	if (access(SUPERKEY, F_OK) == 0)
		goto start_analyze;

	/* allowed commands  */
	if (access_config_allowed(cmdarg)) {
		goto start_analyze;
	}

	/** 如果license正确，则skip 100 次license检查 **/
	if (is_license_ok >= 0 && is_license_ok < 100) {
		is_license_ok ++;
		goto start_analyze;
	}

	/* License check, return -1 represent license invalid */
	if ((is_license_ok = license_check()) == -1) {
		WRITE_BACK(e, "EBADLICENSE\n\n");
		return 0;	/* don't generate config */
	}

start_analyze:
#if defined(DEBUG)
	fprintf(stderr, "receive cmdarg: %s\n", cmdarg);
#endif
	log_info("config", "command- %s ", cmdarg);
	return run_match_analyzer(&analyzer_head, cmdarg, e);
}

	__attribute__((constructor))
static void register_all_analyzer(void)
{
	register_analyzer(&analyzer_head, "system", analyzer_system); 
}

