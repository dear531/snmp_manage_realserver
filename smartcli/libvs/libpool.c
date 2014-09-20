#include <arpa/inet.h>
#include <sys/stat.h>
#include <ctype.h>
#include <syslog.h>

#include "libpool.h"


#include "common/module.h"
#include "common/common.h"
#include "common/base64.h"
#include "loadbalance/vserver.h"
#include "loadbalance/apppool.h"
#include "loadbalance/vcenter.h"
#include "libnet/librtable.h"
#include "libhealthcheck.h"
#include "libvcenter/libvcenter.h"
#include "common/dependence.h"
#include "loadbalance/snmpwalk.h"


#include "check/check.h"
#include "libcli/str_desc.h"
#include "libvs.h"

static int apppool_queue_create(struct list_head *queue, const char *name);
static void apppool_queue_purge(struct list_head *queue);
static int pool_print_for_normal(struct apppool *apppool);
static int pool_print_for_Elastic(struct apppool *apppool);
int check_uuid(struct cli_def *cli, struct cli_command *c, char *value)
{
	int ret = CLI_OK;
	struct apppool *apppool;
	struct rserver *rs = NULL;
	LIST_HEAD(app_head);

	/* empty string */
	if (!strlen(value))
		return ret;

	apppool_queue_create(&app_head, cli->folder->value);

	list_for_each_entry(apppool, &app_head, list) {
		list_for_each_entry(rs, &apppool->realserver_head, list) {
			if(strlen(rs->uuid) && !strcmp(rs->uuid, value)) {
				fprintf(stderr, "ERROR : vmserver '%s' "
					"already exists.\n", value);
				ret = CLI_ERROR;
				goto end;
			}
		}
	}
end:
	apppool_queue_purge(&app_head);

	return ret;
}


int check_vmxpath(struct cli_def *cli, struct cli_command *c, char *value)
{
	int ret = CLI_OK;
	struct apppool *apppool;
	struct rserver *rs = NULL;
	LIST_HEAD(app_head);

	/* empty string */
	if (!strlen(value))
		return ret;

	apppool_queue_create(&app_head, cli->folder->value);

	list_for_each_entry(apppool, &app_head, list) {
		list_for_each_entry(rs, &apppool->realserver_head, list) {
			if(strlen(rs->vmxpath) && !strcmp(rs->vmxpath, value)) {
				fprintf(stderr, "ERROR : vmserver '%s' "
					"already exists.\n", value);
				ret = CLI_ERROR;
				goto end;
			}
		}
	}
end:
	apppool_queue_purge(&app_head);

	return ret;
}

int check_exists_vmxpath(struct cli_def *cli, struct cli_command *c, char *value)
{
	int ret = CLI_ERROR;
	struct apppool *apppool;
	struct rserver *rs = NULL;
	LIST_HEAD(app_head);

	apppool_queue_create(&app_head, cli->folder->value);

	list_for_each_entry(apppool, &app_head, list) {
		list_for_each_entry(rs, &apppool->realserver_head, list) {
			if(strlen(rs->vmxpath) && !strcmp(rs->vmxpath, value)) {
				ret = CLI_OK;
				goto end;
			}
		}
	}
end:
	if (ret != CLI_OK) {
		fprintf(stderr, "ERROR : vmserver '%s' "
				"doesn't exist.\n", value);
	}
	apppool_queue_purge(&app_head);

	return ret;
}

/*********************************************************************************/
/****       RealServer Functions                                                **/
/*********************************************************************************/

/** 
 * 新建或删除一个realserver 
 **/


static int check_realserver_address(struct cli_def *cli, struct cli_command *c ,char *value)
{
	char ipaddr[1024];

	cli_send_flush_state_command("rtable");

	/** 检查是否重复 **/
	if (value[0] != '[') {	/** IPv4 **/
		LIST_HEAD(head);
		struct apppool *apppool;
		struct rserver *rs;

		module_get_queue(&head, "apppool", cli->folder->value);

		if (list_empty(&head)) {
			printf("\nError: Something wrong!\n");
			return CLI_ERROR;
		}

		apppool = list_first_entry(&head, struct apppool, list);

		list_for_each_entry(rs, &apppool->realserver_head, list) {
			char ip[STR_IP_LEN]={0}, ip1[STR_IP_LEN]={0};
			char port[STR_PORT_LEN]={0}, port1[STR_PORT_LEN]={0};
			//get_ip_port(rs->address, ip, port);
			inet_sockaddr2ipport(&rs->address, ip, port);
			get_ip_port(value, ip1, port1);

			if (strcmp(ip, ip1)==0 && strcmp(port, port1)==0) {
				module_purge_queue(&head, "apppool");
				printf("\nError: existed realserver '%s'\n", value);
				return CLI_ERROR;
			}
		}

		module_purge_queue(&head, "apppool");
	} else {
		/** TODO: IPv6 check duplicate **/
	}

#if 0
	if (check_busy_realserver_address(cli->folder->value, value) < 0) {
		return CLI_ERROR;
	}
#endif

	/** 检查IP版本 
	 *	v4: 2.3.4.5:80
	 *	v6: [::ffff:2.3.4.5]:80
	 **/

	if (value[0] == '[') {
		/** IPv6 **/
		char ip[STR_IP_LEN] = {0};
		char port[STR_PORT_LEN] = {0};
		
		if (check_address_port(NULL, NULL, value) == CLI_ERROR) {
			return CLI_ERROR;
		}

		get_ip_port_ipv6(value, ip, port);
		
		if(check_address(NULL, NULL, ip) == CLI_ERROR) {
			return CLI_ERROR;
		}
		return CLI_OK;
	} else {
		/** IPv4 **/
		if(check_batch_ip_port(cli, c , value) != CLI_OK)
			return CLI_ERROR;

		if (check_routable_gateway() == 0) 
			return CLI_OK;

		sscanf(value, "%[^:] :", ipaddr);
		if (check_address(NULL, NULL, ipaddr) != CLI_OK) {
			sscanf(value, "%[^-] -", ipaddr);
		}
		if (check_routable_address(ipaddr, NULL) != 0) {
			printf("Can't find route for %s\n", ipaddr);
			return CLI_ERROR;
		}
	}

	return CLI_OK;
}
static int realserver_new_delete(struct cli_def *cli, char *command, char *argv[], int argc)
{
	FILE *fp;
	char buff[BUFSIZ];
	char ip[STR_IP_LEN];
	int ret = CLI_OK;

	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(head);

	module_get_queue(&head, "apppool", cli->folder->value);
	if (list_empty(&head)) {
		return CLI_ERROR;
	}
	apppool = list_first_entry(&head, struct apppool, list);

	if (strcmp(command, "add realserver") == 0) {
		get_ip_port(argv[0], ip, NULL);
		if (check_ip_version(ip) == IPV4 && strcmp(apppool->type, "ipv6") == 0) {
			printf("Bad address. Please add an IPv6 RealServer.\n");
			ret = CLI_ERROR;
			goto out;
		} else if (check_ip_version(ip) == IPV6 && strcmp(apppool->type, "ipv4") == 0) {
			printf("Bad address. Please add an IPv4 RealServer.\n");
			ret = CLI_ERROR;
			goto out;
		}
	}

	if (strcmp(command, "delete realserver") == 0) {
		list_for_each_entry(rserver, &apppool->realserver_head, list) {
			char address[BUFSIZ];
			inet_sockaddr2address(&rserver->address, address);
			if (strcmp(address, argv[0]) == 0
					&& strcmp(rserver->state, "draining") == 0) {
				printf("The realserver is draining, and soon will be automatically deleted.\n");
				ret = CLI_ERROR;
				goto out;
			}
		}
	}

	if (strcmp(command, "add realserver") == 0) {
		snprintf(buff, 1024, "script4 system pool %s add realserver %s,weight=10,enable=on",
				cli->folder->value, argv[0]);
	} else {
		snprintf(buff, 1024, "script4 system pool %s delete realserver %s",
				cli->folder->value, argv[0]);
	}

	fp = popen(buff, "r");
	if (fp == NULL) {
		fprintf(stderr, "Internal Error.\r\n");
		ret = CLI_ERROR;
		goto out;
	}
	while (fgets(buff, BUFSIZ, fp) != NULL) { }
	pclose(fp);

	if (strcmp(buff, "EINVAL")==0) {
		printf("Can't add this realserver %s to apppool\n", argv[0]);
	}

out:
	module_purge_queue(&head, "apppool");
	return ret;
}


/**
 * 对realserver进行修改操作
 **/
static int do_realserver_config_modify(char *poolname, struct rserver *rserver)
{
	struct apppool *pool;
	FILE *fp;
	char buff[BUFSIZ];

	char address[BUFSIZ];
	inet_sockaddr2address(&rserver->address, address);
	sprintf(buff, "script4 system pool %s add realserver %s", poolname, address);

#define RSERVER_SET_VALUE(x, value)					\
	do {								\
		if (value[0] != 0) {					\
			sprintf(buff, "%s,%s=%s", buff, x, value);	\
		}							\
	} while (0)

	RSERVER_SET_VALUE("weight", rserver->weight);
	RSERVER_SET_VALUE("maxconn", rserver->maxconn);
	RSERVER_SET_VALUE("maxreq", rserver->maxreq);
	RSERVER_SET_VALUE("bandwidth", rserver->bandwidth);
	RSERVER_SET_VALUE("healthcheck", rserver->healthcheck);
	RSERVER_SET_VALUE("enable", rserver->enable);

	/* check snmp state:vilad,in- */
	RSERVER_SET_VALUE("snmp_check", rserver->snmp_check);
	/* snmp version of realserver */
	RSERVER_SET_VALUE("snmp_version", rserver->snmp_version);
	/* snmp name */
	RSERVER_SET_VALUE("name", rserver->name);
	/* on, off */
	RSERVER_SET_VALUE("snmp_enable", rserver->snmp_enable);
	/* community */
	RSERVER_SET_VALUE("community", rserver->community);
	/* SNMPv3 auth type, MD5 or SHA1 */
	RSERVER_SET_VALUE("authProtocol", rserver->authProtocol);
	/* noAuthNoPriv|authNoPriv|authPriv */
	RSERVER_SET_VALUE("securelevel", rserver->securelevel);
	/* control snmptrap */
	RSERVER_SET_VALUE("trap_enable", rserver->trap_enable);
	/* manager ip */
	RSERVER_SET_VALUE("trap_manager", rserver->trap_manager);
	/* trap v3 engine id */
	RSERVER_SET_VALUE("trap_v3_engineid", rserver->trap_v3_engineid);
	/* trap v3 username */
	RSERVER_SET_VALUE("trap_v3_username", rserver->trap_v3_username);
	/* trap v3 password */
	RSERVER_SET_VALUE("trap_v3_password", rserver->trap_v3_password);
	/* DES, AES */
	RSERVER_SET_VALUE("trap_v3_privacy_protocol", rserver->trap_v3_privacy_protocol);
	/* privacy password */
	RSERVER_SET_VALUE("trap_v3_privacy_password", rserver->trap_v3_privacy_password);
	/* authencation usm_name */
	RSERVER_SET_VALUE("username", rserver->username);
	/* authencation password */
	RSERVER_SET_VALUE("password", rserver->password);
	RSERVER_SET_VALUE("cpu", rserver->cpu);
	RSERVER_SET_VALUE("memory", rserver->memory);
	RSERVER_SET_VALUE("snmp_weight", rserver->snmp_weight);

	/* get pool */
	LIST_HEAD(pool_head);
	module_get_queue(&pool_head, "apppool", poolname);
	if (list_empty(&pool_head)) {
		return CLI_ERROR;
	}
	pool = list_first_entry(&pool_head, struct apppool, list);
	if( strcmp(pool->vmtype, "vmware")==0 && strlen(rserver->vmxpath)) {
		char tmp[1024];
		memset(tmp, 0, 1024);
		base64_encode(tmp, 1023, (uint8_t *)rserver->vmxpath,
							strlen(rserver->vmxpath));
		RSERVER_SET_VALUE("vmxpath", tmp);
	} else if(strcmp(pool->vmtype, "xenserver")==0 && strlen(rserver->uuid)) {
		char tmp[1024];
		memset(tmp, 0, 1024);
		base64_encode(tmp, 1023, (uint8_t *)rserver->uuid, 
					strlen(rserver->uuid));
		RSERVER_SET_VALUE("uuid", tmp);
	}

	if (rserver->rscenter[0] != 0) {
		RSERVER_SET_VALUE("rscenter", rserver->rscenter);
	}

	if (rserver->rscenter[0] != 0) {
		RSERVER_SET_VALUE("vmdatacenter", rserver->vmdatacenter);
	}
	
	if (rserver->vmname[0] != 0) {
		RSERVER_SET_VALUE("vmname", rserver->vmname);
	}

#undef RSERVER_SET_VALUE
	fp = popen(buff, "r");
	if (fp == NULL) {
		fprintf(stderr, "Internal Error.\r\n");
		return CLI_ERROR;
	}
	while (fgets(buff, BUFSIZ, fp) != NULL) {
		printf("%s\n", buff);
		if (!strcmp(buff, "EINVAL")) {
			fprintf(stdout, "healthcheck error!\n");
		}
	}
	pclose(fp);


	return CLI_OK;
}


static int check_weight_range(struct cli_def *cli, struct cli_command *c, char *value)
{
	if (check_num_range(cli, c, 1, 100, value) != CLI_OK) {
		printf("range:<1-100>\n");
		return CLI_ERROR;
	}
	return CLI_OK;
}

static int check_cpu_mem_range(struct cli_def *cli, struct cli_command *c, char *value)
{
	if (check_num_range(cli, c, 1, 100, value) != CLI_OK) {
		printf("range:<1-100>\n");
		return CLI_ERROR;
	}
	return CLI_OK;
}

static int apppool_queue_create(struct list_head *queue, const char *name)
{
	return module_get_queue(queue, "apppool", name);
}

static void apppool_queue_purge(struct list_head *queue)
{
	module_purge_queue(queue, "apppool");
}

/** 获取所有realserver的名字 **/
static int realserver_get_values(struct cli_def *cli, char **values)
{
	int k = 0;
	char addr[BUFSIZ];
	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(app_head);

	apppool_queue_create(&app_head, cli->folder->value);

	list_for_each_entry(apppool, &app_head, list) {
		list_for_each_entry(rserver, &apppool->realserver_head, list) {
#if 0
			if(rserver->address_end[0]) {
				merger_ip(addr, rserver->address, rserver->address_end);
			} else {
				strcpy(addr, rserver->address);
			}
#endif
			//strcpy(addr, rserver->address);
			inet_sockaddr2address(&rserver->address, addr);
			values[k++] = strdup(addr);
		}
	}
	apppool_queue_purge(&app_head);

	return k;
}

static char * get_pool_elastic_desc(struct apppool *pool, char *desc)
{
	desc[0] = 0;

	if (pool->vmenable[0] != 0) {
		sprintf(desc + strlen(desc), "vmenable=%s,", pool->vmenable);
	}
	if (pool->vmtype[0] != 0) {
		sprintf(desc + strlen(desc), "vmtype=%s,", pool->vmtype);
	}
	if (pool->vminterval[0] != 0) {
		sprintf(desc + strlen(desc), "vminterval=%s,", pool->vminterval);
	}
	if (pool->vmcount[0] != 0) {
		sprintf(desc + strlen(desc), "vmcount=%s,", pool->vmcount);
	}
	if (pool->alive_vm[0] != 0) {
		sprintf(desc + strlen(desc), "alive_vm=%s,", pool->alive_vm);
	}
	if (pool->subjoinsched[0] != 0) {
		sprintf(desc + strlen(desc), "subjoinsched=%s,", pool->subjoinsched);
	}

	return desc;
}


static char * get_rserver_vmx_desc(struct rserver *rserver, char *desc)
{
	desc[0] = 0;

	if (rserver->rscenter[0] != 0) {
		sprintf(desc, "rscenter=%s,", rserver->rscenter);
	}
	if (rserver->vmdatacenter[0] != 0) {
		sprintf(desc + strlen(desc), "vmdatacenter=%s,", rserver->vmdatacenter);
	}
	if (rserver->vmname[0] != 0) {
		sprintf(desc + strlen(desc), "vmname=%s,", rserver->vmname);
	}
	if (rserver->uuid[0] != 0) {
		sprintf(desc + strlen(desc), "uuid=%s,", rserver->uuid);
	}

	return desc;
}


static char * get_rserver_desc(struct rserver *rserver, char *desc)
{
	desc[0] = 0;
	
	if (rserver->bandwidth[0] != 0) {
		sprintf(desc, "bandwidth=%s,", rserver->bandwidth);
	}
	if (rserver->maxconn[0] != 0) {
		sprintf(desc, "%smaxconn=%s,", desc, rserver->maxconn);
	}
	if (rserver->maxreq[0] != 0) {
		sprintf(desc, "%smaxreq=%s,", desc, rserver->maxreq);
	}
	if (rserver->weight[0] != 0) {
		sprintf(desc, "%sweight=%s,", desc, rserver->weight);
	}
	if (rserver->enable[0] != 0 && !strcmp(rserver->enable, "off")) {
		sprintf(desc, "%senable=%s,", desc, rserver->enable);
	}
	if (rserver->state[0] != 0) {
		sprintf(desc, "%sstate=%s,", desc, rserver->state);
	}

	/* check snmp state:vilad,in- */
	if (rserver->snmp_check[0] != 0) {
		sprintf(desc, "%ssnmp_check=%s,",				\
				desc, rserver->snmp_check);
	}
	/* snmp version:1,2c,3 */
	if (rserver->snmp_version[0] != 0) {
		sprintf(desc, "%ssnmp_version=%s,",				\
				desc, rserver->snmp_version);
	}
	if (rserver->name[0] != 0) {
		sprintf(desc, "%sname=%s,",						\
				desc, rserver->name);
	}
	/* on, off */
	if (rserver->snmp_enable[0] != 0) {
		sprintf(desc, "%ssnmp_enable=%s,",				\
				desc, rserver->snmp_enable);
	}
	if (rserver->community[0] != 0) {
		sprintf(desc, "%scommunity=%s,",				\
				desc, rserver->community);
	}

	/* noAuthNoPriv|authNoPriv|authPriv */
	if (rserver->securelevel[0] != 0) {
		sprintf(desc, "%ssecurelevel=%s,",				\
				desc, rserver->securelevel);
	}

	/* SNMPv3 auth type, MD5 or SHA1 */
	if (rserver->authProtocol[0] != 0) {
		sprintf(desc, "%sauthProtocol=%s,",				\
				desc, rserver->authProtocol);
	}
	/* control snmptrap */
	if (rserver->trap_enable[0] != 0) {
		sprintf(desc, "%strap_enable=%s,",				\
				desc, rserver->trap_enable);
	}
	/* manager ip */
	if (rserver->trap_manager[0] != 0) {
		sprintf(desc, "%strap_manager=%s,",				\
				desc, rserver->trap_manager);
	}
	/* trap v3 engine id */
	if (rserver->trap_v3_engineid[0] != 0) {
		sprintf(desc, "%strap_v3_engineid=%s,",			\
				desc, rserver->trap_v3_engineid);
	}
	/* trap v3 username */
	if (rserver->trap_v3_username[0] != 0) {
		sprintf(desc, "%strap_v3_username=%s,",			\
				desc, rserver->trap_v3_username);
	}
#if 0
	/* trap v3 password */
	if (rserver->trap_v3_password[0] != 0) {
		sprintf(desc, "%strap_v3_password=%s,",			\
				desc, rserver->trap_v3_password);
	}
#endif
	/* DES, AES */
	if (rserver->trap_v3_privacy_protocol[0] != 0) {
		sprintf(desc, "%strap_v3_privacy_protocol=%s,",	\
				desc, rserver->trap_v3_privacy_protocol);
	}
#if 0
	/* privacy password */
	if (rserver->trap_v3_privacy_password[0] != 0) {
		sprintf(desc, "%strap_v3_privacy_password=%s,",	\
				desc, rserver->trap_v3_privacy_password);
	}
#endif
	/* authencation usm_name */
	if (rserver->username[0] != 0) {
		sprintf(desc, "%susername=%s,",					\
				desc, rserver->username);
	}
#if 0
	/* authencation password */
	if (rserver->password[0] != 0) {
		sprintf(desc, "%spassword=%s,",					\
				desc, rserver->password);
	}
#endif
	if (rserver->cpu[0] != 0) {
		sprintf(desc, "%scpu=%s,",					    \
				desc, rserver->cpu);
	}

	if (rserver->memory[0] != 0) {
		sprintf(desc, "%smemory=%s,",					\
				desc, rserver->memory);
	}

	if (rserver->snmp_weight[0] != 0) {
		sprintf(desc, "%ssnmp_weight=%s,",					\
				desc, rserver->snmp_weight);
	}

	return desc;
}


static int realserver_show_for_elastic(struct rserver *rserver)
{
	char address[512] = {0}; 
	char desc[BUFSIZ] = {0};
	char vmx_desc[BUFSIZ] = {0};
#define FORMAT0						\
	/** 21 **/ "+---------------------"		\
	/** 12 **/ "+------------"			\
	/** 60 **/ "+------------------------------------------------------------"	\
	/** 45 **/ "+---------------------------------------------+"	\

#define SHOW_LINE 				\
	do {					\
		printf(FORMAT0"\r\n");		\
	} while (0)

	/** Show Title **/
	SHOW_LINE;
	struct show_fmt show_fmt[4] = {
		{21, "Address"}, {12, "Healthcheck"}, {60, "VMData"}, {45, "Notes"}
	};

	show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));

	SHOW_LINE;

	inet_sockaddr2address(&rserver->address, address);
	{
		struct show_fmt show_fmt[] = {
			{21, address},
			{12, rserver->healthcheck},
			{60, get_rserver_vmx_desc(rserver,vmx_desc)},
			{45, get_rserver_desc(rserver, desc)},
		};
		show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
	}
	SHOW_LINE;

#undef SHOW_LINE
#undef FORMAT0
	return CLI_OK;
}

static int realserver_show_for_normal(struct rserver *rserver)
{
	char desc[BUFSIZ];
	char address[BUFSIZ];
#define FORMAT0						\
	/** 21 **/ "+---------------------"		\
	/** 12 **/ "+------------"			\
	/** 32 **/ "+--------------------------------+"	\

#define SHOW_LINE 				\
	do {					\
		printf(FORMAT0"\r\n");		\
	} while (0)

	/** Show Title **/
	SHOW_LINE;
	struct show_fmt show_fmt[] = {
		{21, "Address"},
		{12, "HealthCheck"},
		{32, "Notes"},
	};
	show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
	SHOW_LINE;

	inet_sockaddr2address(&rserver->address, address);
	{
		struct show_fmt show_fmt[] = {
			{21, address},
			{12, rserver->healthcheck},
			{32, get_rserver_desc(rserver, desc)},
		};
		show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
	}
	SHOW_LINE;
#undef SHOW_LINE
#undef FORMAT0

	return CLI_OK;
}

#define ZERO(x) memset(rserver->x, 0x00, sizeof(rserver->x))

static int snmp_user(struct rserver *rserver)
{
    char buf[64];
    set_normal_tty();
again:
    memset(buf, 0x00, sizeof(buf));
    fprintf(stdout, "\nusername:");
    scanf("%s", buf);
    if (strlen(buf) == 0) {
        fprintf(stdout, "usernem can not null\n");
        goto again;
    } else if (strncasecmp(buf, "q", sizeof("q")) == 0) {
        return CLI_ERROR;
    } else {
        ZERO(username);
        memcpy(rserver->username, buf, strlen(buf));
    }
    set_nonline_tty();
    return CLI_OK;
}

static int snmp_password(struct rserver *rserver)
{
    char buf[64];
again:
    memset(buf, 0x00, sizeof(buf));
    fprintf(stdout, "\npassword:");
    scanf("%s", buf);
    if (strlen(buf) == 0) {
        fprintf(stdout, "password can not null\n");
        goto again;
    } else {
        ZERO(password);
        memcpy(rserver->password, buf, strlen(buf));
    }
    return CLI_OK;
}
#undef ZERO
int check_cpu_mem(struct rserver *rserver)
{
    if (0 != rserver->cpu[0] && 0 != rserver->memory[0])
        return 0;
    return -1;
}

int check_snmp_complete_set_snmp_enable(struct rserver *rserver)
{
    int snmpret, cpumemret;
    snmpret = check_snmp(rserver, SNMP_SHOW);
    cpumemret = check_cpu_mem(rserver);
#if 0   /* debug information */
    fprintf(stdout, "snmp ret :%d\n", snmpret);
#endif
    if (snmpret >= 0 && cpumemret == 0) {
        fprintf(stdout, "auto set snmp enable on\n");
        return 0;
    }
    if (snmpret < 0) {
        fprintf(stdout, "please complete snmp element\n");
        return -1;
    }
    if (cpumemret < 0){
        fprintf(stdout, "please set cpu and memory\n");
        return -1;
    }
    return -1;
}

static int _realserver_config_modify(struct cli_def *cli, char *command, char *argv[], int argc, char *poolname, char *rsaddr)
{
	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(app_head);

	if (poolname == NULL) {
		return CLI_ERROR;
	}

	/** get pool **/
	apppool_queue_create(&app_head, poolname);

	list_for_each_entry(apppool, &app_head, list) {
		list_for_each_entry(rserver, &apppool->realserver_head, list) {
			char address[BUFSIZ];
			inet_sockaddr2address(&rserver->address, address);
			if (rsaddr != NULL && strcmp(rsaddr, address) != 0) {
				continue;
			}
#define RSERVER_SET_VALUE(x,value)					\
			do {						\
				if (strcmp(value, "0") == 0) {		\
					x[0] = 0;			\
				} else {				\
					strcpy(x, value);		\
				}					\
			} while (0)
			if (strcmp(command, "limit off") == 0) {
				rserver->maxconn[0] = 0;
				rserver->maxreq[0] = 0;
				rserver->bandwidth[0] = 0;
			} else if (strcmp(command, "limit maxconn") == 0) {
				RSERVER_SET_VALUE(rserver->maxconn, argc == 0 ? "" : argv[0]);
			} else if (strcmp(command, "limit maxreq") == 0) {
				RSERVER_SET_VALUE(rserver->maxreq, argc == 0 ? "" : argv[0]);
			} else if (strcmp(command, "limit bandwidth") == 0) {
				char bandwidth[1024]={0};
				sprintf(bandwidth, "%d", xbytes2bytes(argc == 0 ? "" : argv[0]));
				RSERVER_SET_VALUE(rserver->bandwidth, bandwidth);
			} else if (strcmp(command, "healthcheck") == 0) {
				RSERVER_SET_VALUE(rserver->healthcheck, argc == 0 ? "" : argv[0]);
			} else if (strncmp(command, "enable ", 7) == 0) {
				RSERVER_SET_VALUE(rserver->enable, command+7);
			} else if (strncmp(command, "weight", 6) == 0) {
				sprintf(rserver->weight, "%u", atoi(argc == 0 ? "10" : argv[0]));
			} else if (strncmp(command, "vmxpath", 7) == 0) {
				RSERVER_SET_VALUE(rserver->vmxpath, argv[0]);
			} else if (strncmp(command, "uuid", 5) == 0) {
				RSERVER_SET_VALUE(rserver->uuid, argv[0]);
			} else if (strncmp(command, "vmname", 6) == 0) {
				RSERVER_SET_VALUE(rserver->vmname, argv[0]);
			} else if (strncmp(command, "rscenter", 8) == 0) {
				RSERVER_SET_VALUE(rserver->rscenter, argv[0]);
			} else if (strncmp(command, "vmdatacenter", 8) == 0) {
				RSERVER_SET_VALUE(rserver->vmdatacenter, argv[0]);
			} else if (strncmp(command, "snmp version", 12) == 0) {
                    RSERVER_SET_VALUE(rserver->snmp_version, argc == 0 ? "3" : argv[0]);
			} else if (strncmp(command, "snmp securelevel authNoPriv", 29) == 0) {
            /* at present only support authNoPriv, other later will be complete */
                if (memcmp(rserver->snmp_version, "3", sizeof("3")) == 0) {
                    RSERVER_SET_VALUE(rserver->securelevel, argc == 0 ? "authNoPriv" : argv[0]);
                } else {
                    fprintf(stdout, "securelevel needed by snmp version 3\n");
                }
			} else if (strncmp(command, "snmp authProtocol", 18) == 0) {
                if (memcmp(rserver->securelevel, "authNoPriv", sizeof("authNoPriv")) == 0) {
                    RSERVER_SET_VALUE(rserver->authProtocol, argc == 0 ? "md5" : argv[0]);
                } else {
                    fprintf(stdout, "authprotocol needed by v3 and securelevel auth\n");
                }
			} else if (strncmp(command, "snmp user", 9) == 0) {
                snmp_user(rserver);
                snmp_password(rserver);
			} else if (strncmp(command, "snmp password", 13) == 0) {
                snmp_password(rserver);
			} else if (strncmp(command, "snmp check", 10) == 0) {
                if (check_snmp_complete_set_snmp_enable(rserver) == 0)
                    RSERVER_SET_VALUE(rserver->snmp_enable, "on");
                else
                    RSERVER_SET_VALUE(rserver->snmp_enable, "off");
			} else if (strncmp(command, "snmp cpu", 8) == 0) {
                RSERVER_SET_VALUE(rserver->cpu, argc == 0 ? "" : argv[0]);
                if (strlen(rserver->cpu) > 0)
                    sprintf(rserver->memory, "%ld", 100 - strtol(argv[0], NULL, 10));
			} else if (strncmp(command, "snmp memory", 11) == 0) {
				RSERVER_SET_VALUE(rserver->memory, argc == 0 ? "" : argv[0]);
                if (strlen(rserver->memory) > 0)
                    sprintf(rserver->cpu, "%ld", 100 - strtol(argv[0], NULL, 10));
			}

			do_realserver_config_modify(poolname, rserver);
#undef RSERVER_SET_VALUE
		}
	}
	apppool_queue_purge(&app_head);

	return CLI_OK;
}

static int realserver_config_modify(struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct cli_command *c = cli->folder;
	char *rsaddr = c->value;

	/** get pool name **/
	while ((c = c->parent) != NULL && c->mode != MODE_FOLDER);

	return _realserver_config_modify(cli, command, argv, argc, c->value, rsaddr);
}

static int realserver_add_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *t;

	t = cli_register_command(cli, parent, "realserver", realserver_new_delete, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	cli_command_add_argument(t, "<ip:port>",  check_realserver_address);
	return 0;
}

/** 添加参数为 on 或 off 的命令 **/
#define ADD_BOOL_COMMAND(arg, callback, desc, desc_on, desc_off) 						\
	do {													\
		p = cli_register_command(cli, t, arg, NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, desc);	\
		cli_register_command(cli, p, "on", callback, PRIVILEGE_PRIVILEGED, MODE_EXEC, desc_on);		\
		cli_register_command(cli, p, "off", callback, PRIVILEGE_PRIVILEGED, MODE_EXEC, desc_off);	\
	} while (0)

static int rserver_show_default(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(app_head);

	struct cli_command *c = cli->folder;
	char *rsaddr = c->value;

	/** get poolname **/
	while ((c = c->parent) != NULL && c->mode != MODE_FOLDER);

	/** get pool **/
	apppool_queue_create(&app_head, c->value);

	if (list_empty(&app_head) ) {
		return -1;
	}
	apppool = list_first_entry(&app_head, struct apppool, list);
	list_for_each_entry(rserver, &apppool->realserver_head, list) {
		char address[512] = {0};
		inet_sockaddr2address(&rserver->address, address);
		if(strcmp(address, rsaddr) != 0) {
			continue;
		}
		if(strcmp(apppool->vmenable, "off") == 0 || apppool->vmenable[0] == 0) { //for normal pool print rserver
			realserver_show_for_normal(rserver);	
		}else if(strcmp(apppool->vmenable, "on") == 0) { // for Elastic pool print rserver
			realserver_show_for_elastic(rserver);	
		}
	}

	apppool_queue_purge(&app_head);
	return CLI_OK;	
}


static int do_realserver_configure_show_command(struct cli_def *cli,
		struct cli_command *root, struct rserver *rserver)
{
		
	struct cli_command *c;

	cli_unregister_command(cli, root, "show");
	c = cli_register_command(cli, root, "show", rserver_show_default,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SHOW_INFO);
	return CLI_OK;
}

static int do_realserver_configure_elastic_command(struct cli_def *cli,
		struct cli_command *root, struct rserver *rserver, struct apppool *pool)
{
	struct cli_command *p ;

	cli_unregister_command(cli, root, "vmxpath");
	cli_unregister_command(cli, root, "uuid");
	/** 资源调度中心 **/
	cli_unregister_command(cli, root, "rscenter");
	cli_unregister_command(cli, root, "vmdatacenter");

	if(pool->vmenable[0] == 0 || strcmp(pool->vmenable, "off") == 0) {
		//doing nothing
	}else if(strcmp(pool->vmenable, "on") == 0) {
		p = cli_register_command(cli, root, "rscenter", realserver_config_modify,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_REALSERVER_RSCENTER);
		cli_command_add_argument(p, "<Resource scheduling center>", NULL);
		cli_command_setvalues_func(p, vcenter_get_values, default_free_values);

		/** datacenter **/
		if(strcmp(pool->vmtype, "vcenter") == 0) {
			p = cli_register_command(cli, root, "vmdatacenter", realserver_config_modify,
					PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_REALSERVER_DATACENTER);
			cli_command_add_argument(p, "<VCenter dataceter>", NULL);
			cli_command_setvalues_func(p, vcenter_datacenter_get_values, default_free_values);
		}

		if(strcmp(pool->vmtype, "vmware") == 0)	{
			p = cli_register_command(cli, root, "vmxpath", realserver_config_modify,
					PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_REALSERVER_VMXPATH);
			cli_command_add_argument(p, "<path>", check_vmxpath);
		}else if(strcmp(pool->vmtype, "xenserver") == 0) {
			p = cli_register_command(cli, root, "uuid", realserver_config_modify,
					PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_REALSERVER_UUID);
			cli_command_add_argument(p, "<uuid>", check_vmxpath);
		}
	}

	return CLI_OK;
}

static int do_realserver_configure_commands(struct cli_def *cli, 
		struct cli_command *root, struct rserver *rserver, struct list_head *list)
{

	struct apppool *pool;
	list_for_each_entry(pool, list, list) {
		do_realserver_configure_show_command(cli, root, rserver);
		do_realserver_configure_elastic_command(cli, root, rserver, pool);
	}
	return 0;
}

static int realserver_configure_commands(struct cli_def *cli, char *rserverip)
{
	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(queue);

	struct cli_command *c = cli->folder;

	/** get poolname **/
	while ((c = c->parent) != NULL && c->mode != MODE_FOLDER);

	/** get pool **/
	apppool_queue_create(&queue, c->value);

	/** 这里有且只有一个成员 **/
	list_for_each_entry(apppool, &queue, list) {
		list_for_each_entry(rserver, &apppool->realserver_head, list) {
			char address[512] = {0};
			inet_sockaddr2address(&rserver->address, address);
			if(strcmp(address, rserverip) != 0) {
				continue;
			}
			do_realserver_configure_commands(cli, cli->folder, rserver, &queue);
		}
	}
	module_purge_queue(&queue, "apppool");

	return CLI_OK;
}


static int realserver_set_default(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	realserver_configure_commands(cli, argv[0]);
	return CLI_OK;
}

static int check_snmp_version(struct cli_def *cli, struct cli_command *c, char *value)
{
#if 0 /* current only support version 3 */
    if (memcmp(value, "1", sizeof("1")) == 0
    || memcmp(value, "2c", sizeof("2c")) == 0
    || memcmp(value, "3", sizeof("3")) == 0) {
#else
    if (memcmp(value, "3", sizeof("3")) == 0) {
#endif
        return CLI_OK;
    }
    return CLI_ERROR;
}
static int check_snmp_authProtocol(struct cli_def *cli, struct cli_command *c, char *value)
{
    if (strncasecmp(value, "md5", sizeof("md5")) == 0
        ||strncasecmp(value, "sha", sizeof("sha")) == 0) {
        return CLI_OK;
    }
    return CLI_ERROR;
}

static int realserver_set_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *t, *p, *c, *d;
	t = cli_register_command(cli, parent, "realserver", realserver_set_default, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_POOL_SET_SET_REALSERVER);
	cli_command_add_argument(t, "<ip:port>", check_address_port);
	cli_command_setvalues_func(t, realserver_get_values, default_free_values);

	p = cli_register_command(cli, t, "weight", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_WEIGHT);
	cli_command_add_argument(p, "<num>", check_weight_range);

	p = cli_register_command(cli, t, "snmp", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_SNMP);

	c = cli_register_command(cli, p, "check", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_CHECK);

	c = cli_register_command(cli, p, "version", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_VERSION);
	cli_command_add_argument(c, "3(default)", check_snmp_version);

	c = cli_register_command(cli, p, "securelevel", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_SECURELEVEL);

	d = cli_register_command(cli, c, "authNoPriv", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LIMIT_OFF);

	c = cli_register_command(cli, p, "authProtocol", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_AUTHPROTOCOL);
	cli_command_add_argument(c, "md5\tsha", check_snmp_authProtocol);

	c = cli_register_command(cli, p, "user", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_USER);

	c = cli_register_command(cli, p, "password", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_PASSWORD);

	c = cli_register_command(cli, p, "cpu", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_CPU);
	cli_command_add_argument(c, "<num:1-100>", check_cpu_mem_range);

	c = cli_register_command(cli, p, "memory", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_RSERVER_SNMPWALK_MEMORY);
	cli_command_add_argument(c, "<num>:1-100", check_cpu_mem_range);

	/** limit maxconn/maxreq/bandwidth <value> **/
	p = cli_register_command(cli, t, "limit", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LIMIT);

	c = cli_register_command(cli, p, "off", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LIMIT_OFF);

	c = cli_register_command(cli, p, "maxconn", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LIMIT_MAXCONN);
	cli_command_add_argument(c, "<num>", check_num);

	c = cli_register_command(cli, p, "maxreq", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LIMIT_MAXREQ);
	cli_command_add_argument(c, "<num>", check_num);

	c = cli_register_command(cli, p, "bandwidth", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_VSERVER_SET_LIMIT_BANDWIDTH);
	cli_command_add_argument(c, "<NUMkbps|mbps, eg 100mbps, between 1kbps and 2048mbps>", check_bandwidth);

	p = cli_register_command(cli, t, "healthcheck", realserver_config_modify,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_HEALTHCHECK_MANAGE_INFO);
	cli_command_add_argument(p, "[healthcheckname]", NULL);
	cli_command_setvalues_func(p, healthcheck_get_values, default_free_values);

	ADD_BOOL_COMMAND("enable", realserver_config_modify,
			LIBCLI_POOL_SET_REALSERVER_ENABLE,
			LIBCLI_POOL_SET_REALSERVER_ENABLE_ON,
			LIBCLI_POOL_SET_REALSERVER_ENABLE_OFF);
	return 0;
}

static int realserver_delete_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *t;
	t = cli_register_command(cli, parent, "realserver", realserver_new_delete, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_DEL_REALSERVER);
	cli_command_add_argument(t, "<ip:port>", NULL);
	cli_command_setvalues_func(t, realserver_get_values, default_free_values);

	return 0;
}



/*********************************************************************************/
/****       Pool Functions                                                      **/
/*********************************************************************************/
int pool_exists(char *name)
{
	LIST_HEAD(app_head);

	if (!name)
		return 0;

	apppool_queue_create(&app_head, name);

	if (!list_empty(&app_head)) {
		apppool_queue_purge(&app_head);
		return 1;
	}

	return 0;
}

static void pool_print_detail_line(const char *attr,
		const char *value) 
{
	struct show_fmt show_fmt[] = {
		{12, ""},
		{21, (char *)attr},
		{119, (char *)value},
	};

	show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
}
static int pool_print(struct list_head *app_head)
{
	struct apppool *pool;
	
	list_for_each_entry(pool, app_head, list){
		if(strcmp(pool->vmenable, "off") == 0 || pool->vmenable[0] == 0) {
			pool_print_for_normal(pool);
		}else if(strcmp(pool->vmenable, "on") == 0) {
			pool_print_for_Elastic(pool);
		}
	}
	
	return CLI_OK;
}


/****************for Elastic pool_*****************************************/
static int pool_print_for_Elastic(struct apppool *apppool)
{
	char addr[100], buff[BUFSIZ], vm_desc[BUFSIZ], pool_desc[BUFSIZ];
	struct rserver *rserver = NULL;
#define SHOW_LINE									\
	do {										\
		printf("+------------+---------------------+"				\
				"------------+------------------------------------------------------------+"	\
				"---------------------------------------------+\r\n");		\
	} while (0)

#define SHOW_BOTTEM_LINE								\
	do {										\
		printf("+------------+---------------------+"				\
				"------------------------------------------------------"	\
				"-----------------------------------------------------------------+\r\n");		\
	} while (0)

#define SHOW_BLANK_LINE									\
	do {										\
		printf("|            |------------------------------------------------------+"			\
				"-----------------------------------+\r\n");		\
	} while (0)

#define SHOW_VMX_LINE									\
	do {										\
		printf("|            |---------------------+-------------"		\
				"---------------------------------"			\
				"-------------------------------------------------------------------------+\r\n");		\
	} while (0)


#define SHOW_POOL_HEADER(pool)		\
	do {	\
		SHOW_LINE;		\
		struct show_fmt show_fmt[] = {		\
			{12, "Pool Name"},		\
			{21, "RealServer/VMX"},	\
			{12, "HealthCheck"},	\
			{60, "VMData"},				\
			{45, "Notes"},			\
		};		\
		show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));		\
		SHOW_LINE;									\
	}while (0)
	//apppool = list_entry(app_head, struct apppool, list);
	//list_for_each_entry(apppool, app_head, list) {
		SHOW_POOL_HEADER(apppool);
		if (strcmp(apppool->type, "ipv6") == 0) {
			sprintf(buff, "%s (ipv6)", apppool->name);
		} else {
			strcpy(buff, apppool->name);
		}

		/** show Pool line **/
		struct show_fmt show_fmt[] = {
			{12, buff},
			{21, ""},
			{12, apppool->healthcheck},
			{60, ""},
			{45, ""},
		};

		show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
		/*SHOW_BLANK_LINE;*/

		/** show Realserver line **/
		list_for_each_entry(rserver, &apppool->realserver_head, list) {
#if 0
			if(rserver->address_end[0]) {
				merger_ip(addr, rserver->address, rserver->address_end);
			} else {
				strcpy(addr, rserver->address);
			}
#endif
			//strcpy(addr, rserver->address);
			inet_sockaddr2address(&rserver->address, addr);
			struct show_fmt show_fmt[] = {
				{12, ""},
				{21, addr},
				{12, rserver->healthcheck},
				{60, get_rserver_vmx_desc(rserver, vm_desc)},
				{45, get_rserver_desc(rserver, buff)},
			};
			show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
		}

		SHOW_VMX_LINE;
		pool_print_detail_line("Elastic", get_pool_elastic_desc(apppool, pool_desc));

		SHOW_BOTTEM_LINE;
	//}
#undef	SHOW_LINE
#undef	SHOW_BOTTEM_LINE
#undef	SHOW_BLANK_LINE
#undef	SHOW_VMX_LINE
#undef	SHOW_POOL_HEADER
	return 0;
}


/*************************************************************/
static int pool_print_for_normal(struct apppool *apppool)
{
	char addr[100], buff[BUFSIZ];
	struct rserver *rserver;
#define SHOW_LINE                                               \
	do {                                                    \
		printf("+------------+---------------------+"   \
				"------------+"                 \
				"-----------------------------+\r\n");\
	} while (0)

#define SHOW_BLANK_LINE                                         \
	do {                                                    \
		printf("|            |            |---------------------+"\
				"-----------------------------+\r\n");\
	} while (0)

	{
		/** Show Title **/
		SHOW_LINE;
		struct show_fmt show_fmt[] = {
			{12, "Pool Name"},
			{21, "RealServer"},
			{12, "HealthCheck"},
			{29, "Notes"},
		};
		show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
		SHOW_LINE;
	}


		if (strcmp(apppool->type, "ipv6") == 0) {
			sprintf(buff, "%s (ipv6)", apppool->name);
		} else {
			strcpy(buff, apppool->name);
		}

        char show_subjionsched[1024] = "subjionsched=";
        strcat(show_subjionsched, apppool->subjoinsched);

		/** show Pool line **/
		struct show_fmt show_fmt[] = {
			{12, buff},
			{21, ""},
			{12, apppool->healthcheck},
			{29, show_subjionsched},
		};

		show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
		/*SHOW_BLANK_LINE;*/

		/** show Realserver line **/
		list_for_each_entry(rserver, &apppool->realserver_head, list) {
#if 0
			if(rserver->address_end[0]) {
				merger_ip(addr, rserver->address, rserver->address_end);
			} else {
				strcpy(addr, rserver->address);
			}
#endif
			//strcpy(addr, rserver->address);
			inet_sockaddr2address(&rserver->address, addr);
			struct show_fmt show_fmt[] = {
				{12, ""},
				{21, addr},
				{12, rserver->healthcheck},
				{29, get_rserver_desc(rserver, buff)},
			};

			show_line(show_fmt, sizeof(show_fmt) / sizeof(struct show_fmt));
		}
		SHOW_LINE;


#undef	SHOW_LINE
#undef	SHOW_BLANK_LINE

	return 0;
}
static int pool_show(struct cli_def *cli, char *command, char *argv[], int argc)
{
	LIST_HEAD(app_head);

	cli_send_flush_state_command("vserver");

	/* not implemented */
	cli_send_flush_state_command("apppool");

	if (strcmp(command, "show") == 0) {
		/** show one pool **/
		apppool_queue_create(&app_head, cli->folder->value);
	} else if (argc == 0) {
		/** show all pool **/
		apppool_queue_create(&app_head, NULL);
	} else {
		apppool_queue_create(&app_head, strtolower(argv[0]));
	}

	pool_print(&app_head);
	apppool_queue_purge(&app_head);

	return CLI_OK;
}
static int pool_config(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[BUFSIZ];
	char *cmd = "script4 system";
	FILE *fp;

	if (argc == 0) {
		snprintf(buff, BUFSIZ, " %s %s ", cmd, command);
	} else {
		snprintf(buff, BUFSIZ, " %s %s %s", cmd, command, argv[0]);
	}

	fp = popen(buff, "r");
	if (fp == NULL) {
		return CLI_ERROR;
	}

	while (fgets(buff, BUFSIZ, fp) != NULL) {
	}
	pclose(fp);

	if (strcmp(buff, "EBUSY") == 0) {
		printf("Can't delete the busy pool \"%s\"\n", argv[0]);
	}

	return CLI_OK;
}


static int pool_new(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[BUFSIZ];

	if (check_name(cli, cli->folder, argv[0]) != CLI_OK) {
		return CLI_ERROR;
	}

	if (strcmp(command, "add pool ipv6") == 0) {
		sprintf(buff, "script4 system pool %s ipv6", argv[0]);
	} else {
		sprintf(buff, "script4 system pool %s ", argv[0]);
	}

	system(buff);

	return CLI_OK;
}

static int pool_delete(struct cli_def *cli, char *command, char *argv[], int argc)
{
	if (check_name(cli, cli->folder, argv[0]) != CLI_OK) {
		return CLI_ERROR;
	}

	return pool_config(cli, command, argv, argc);
}

static int pool_config_arg1(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	char buff[BUFSIZ], resp[BUFSIZ];
	FILE *fp;
	char *cmd = "script4 system pool";

	if (argc == 0) {
		snprintf(buff, BUFSIZ, " %s %s %s ", cmd, cli->folder->value, command);
	} else {
		snprintf(buff, BUFSIZ, " %s %s %s %s", cmd, cli->folder->value, command, argv[0]);
	}

	fp = popen(buff, "r");
	if (fp == NULL) {
		fprintf(stderr, "Internal Error.\r\n");
		return CLI_ERROR;
	}
	while (fgets(resp, BUFSIZ, fp) != NULL) {
		fprintf(stdout, "Invalid value! Error code:%s!\n", resp);
		pclose(fp);
		return CLI_ERROR;
	}
	pclose(fp);

	return CLI_OK;
}

static int pool_config_healthcheck(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
	return pool_config_arg1(cli, command, argv, argc);
}

static int subjoinsched_check(struct cli_def *cli,
		char *command, char *argv[], int argc)
{
#if 1
	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(pool_queue);
	char address[512] = {0};

    module_get_queue(&pool_queue, "apppool", cli->folder->value);

    apppool = list_first_entry(&pool_queue, struct apppool, list);

    if (list_empty(&apppool->realserver_head)) {
        goto err;
    }

    list_for_each_entry(rserver, &apppool->realserver_head, list) {
        if (inet_sockaddr2address(&rserver->address, address) != 0
            || memcmp(rserver->snmp_enable, "on", sizeof("on")) != 0) {
            goto err;
        }
    }

#endif
	return CLI_OK;
err:
	fprintf(stderr, "snmp need by config real server\n");
	return CLI_ERROR;

}

int pool_get_counts(struct cli_def *cli, char *poolname)
{
	int count = 0;

	LIST_HEAD(app_head);
	struct apppool *apppool;

	if (poolname == NULL || strlen(poolname) == 0) {
		return 0;
	}

	/** 先检查输入合法性 **/
	if (check_name(cli, cli->folder, poolname) != CLI_OK) {
		return 0;
	}

	/** 根据名字获取apppool列表 **/
	apppool_queue_create(&app_head, poolname);

	list_for_each_entry(apppool, &app_head, list) {
		if (strcmp(apppool->name, poolname) == 0) {
			struct rserver *rserver;
			list_for_each_entry(rserver, &apppool->realserver_head, list) {
				count ++;
			}
			break;
		}
	}

	apppool_queue_purge(&app_head);

	return count;
}

/** 获取当前所有的pool的名字，由CLI的TAB键显示 **/
int pool_get_values(struct cli_def *cli, char **values)
{
	int k = 0;
	struct apppool *apppool;
	LIST_HEAD(app_head);

	apppool_queue_create(&app_head, NULL);

	list_for_each_entry(apppool, &app_head, list) {
		values[k++] = strdup(apppool->name);
	}
	apppool_queue_purge(&app_head);

	return k;
}

int pool_search_name(char *name)
{
	struct apppool *apppool;
	LIST_HEAD(app_head);

	apppool_queue_create(&app_head, name);

	list_for_each_entry(apppool, &app_head, list) {
		if (strcasecmp(apppool->name, name) == 0) {
			return 0;
		}
	}
	apppool_queue_purge(&app_head);

	return -1;
}


/** 检查set pool xxx 中输入的名字合法性 **/
int pool_check_name(struct cli_def *cli, struct cli_command *c, char *value)
{
	if (value == NULL || strlen(value) == 0) {
		return CLI_OK;
	}

	/** 先检查输入合法性 **/
	if (check_name(cli, c, value) != CLI_OK) {
		return CLI_ERROR;
	}

	if(pool_search_name(strtolower(value)) == 0) {        
		fprintf(stderr, "ERROR : Pool '%s' already exists, add failture!\n", value);
		return CLI_ERROR;
	}

	return CLI_OK;
}


int pool_show_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "pool", pool_show, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SHOW_INFO);
	cli_command_add_argument(c, "[poolname]", NULL);
	cli_command_setvalues_func(c, pool_get_values, default_free_values);
	return 0;
}

int pool_add_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "pool", pool_new, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_ADD_INFO);
	cli_command_add_argument(c, "<poolname>", pool_check_name);

	cli_register_command(cli, c, "ipv4", pool_new, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_ADD_INFO);
	cli_register_command(cli, c, "ipv6", pool_new, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_ADD_INFO);
	return 0;
}
__attribute__((unused))
static int check_interval(struct cli_def *cli, struct cli_command *c, char *value)
{
	long val = atol(value);

	if (val > 1) {
		return CLI_OK;
	}else {
		fprintf(stderr, "vmcount must be greater than 1\n");
		return CLI_ERROR;
	}
}

static int check_vmcount(struct cli_def *cli, struct cli_command *c, char *value)
{
	long val = atol(value);

	if (val >= 1) {
		return CLI_OK;
	}else {
		fprintf(stderr, "vmcount must be greater than or equal to 20\n");
		return CLI_ERROR;
	}
}

static int check_vm_counts(struct cli_def *cli, struct cli_command *c, char *value)
{
	long val = atol(value);

	if (val >= 1) {
		return CLI_OK;
	}else {
		fprintf(stderr, "the default alive vm  must be greater than or equal to 1\n");
		return CLI_ERROR;
	}
}

__attribute__((unused))
static int pool_vcenter_host_get_values(struct cli_def *cli, char **values)
{
	int k = 0;
	struct vcenter_datacenter *datacenter;
	struct vcenter *vcenter;
	struct apppool *pool;

	LIST_HEAD(pool_head);
	module_get_queue(&pool_head, "apppool", cli->folder->value);
	if (list_empty(&pool_head)) {
		goto error1;
	}
	pool = list_first_entry(&pool_head, struct apppool, list);
	if (pool->vmvcenter[0] == 0) {
		printf("\n\nError: please set vcenter first!\n");
		goto error1;
	}

	LIST_HEAD(vcenter_head);
	module_get_queue(&vcenter_head, "vcenter", pool->vmvcenter);
	list_for_each_entry(vcenter, &vcenter_head, list) {
		if (strcmp(pool->vmvcenter, vcenter->name) == 0) {
			list_for_each_entry(datacenter, &vcenter->datacenter_head, list) {
				values[k++] = strdup(datacenter->name);
			}
			break;
		}
	}

	module_purge_queue(&vcenter_head, "vcenter");

error1:
	module_purge_queue(&pool_head, "apppool");

	return k;
}

static int pool_show_default(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	struct apppool *pool = NULL;
	LIST_HEAD(queue);
	module_get_queue(&queue, "apppool", cli->folder->value);
	

	if(list_empty(&queue)){
		return CLI_ERROR;
	}
	

	list_for_each_entry(pool, &queue, list) {
		if(strcmp(pool->vmenable, "off") == 0 || pool->vmenable[0] == 0) { //just normal pool show 
			pool_print_for_normal(pool);
		}else if(strcmp(pool->vmenable, "on") == 0) {//for Elastic pool show
			pool_print_for_Elastic(pool);	
		}
	}
	return CLI_OK;
}


static int do_pool_configure_show_command(struct cli_def *cli,
		struct cli_command *root, struct apppool *pool)
{
		
	struct cli_command *c;

	cli_unregister_command(cli, root, "show");
	c = cli_register_command(cli, root, "show", pool_show_default,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			LIBCLI_VSERVER_SHOW_INFO);
	return CLI_OK;
}

static int do_pool_configure_elastic_command(struct cli_def *cli,
		struct cli_command *root, struct apppool *pool)
{

	struct cli_command *t;
	cli_unregister_command(cli, root, "vmtype");
	cli_unregister_command(cli, root, "vminterval");
	cli_unregister_command(cli, root, "vmcount");
	cli_unregister_command(cli, root, "alive_vm");
	
	if(strcmp(pool->vmenable, "off") == 0 || pool->vmenable[0] == 0) { //just normal pool show 
		
		return CLI_OK;
		
	}else if(strcmp(pool->vmenable, "on") == 0) {//for Elastic pool show
		t = cli_register_command(cli, root, "vmtype", pool_config_arg1,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VMTYPE);
		cli_register_command(cli, t, "xenserver", pool_config_arg1, PRIVILEGE_UNPRIVILEGED,
				MODE_EXEC, LIBCLI_POOL_SET_VMTYPE_XEN);
		cli_register_command(cli, t, "vcenter", pool_config_arg1, PRIVILEGE_UNPRIVILEGED,
				MODE_EXEC, LIBCLI_POOL_SET_VMTYPE_VCENTER);
		t = cli_register_command(cli, root, "vminterval", pool_config_arg1,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_INTERVAL);
		cli_command_add_argument(t, "<interval>", check_interval);

		t = cli_register_command(cli, root, "vmcount", pool_config_arg1,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_COUNT);
		cli_command_add_argument(t, "<count>", check_vmcount);

		t = cli_register_command(cli, root, "alive_vm", pool_config_arg1,
				PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_ALIVE_COUNT);
		cli_command_add_argument(t, "<count>", check_vm_counts);
	}

	return CLI_OK;
}

static int do_pool_configure_commands(struct cli_def *cli, 
		struct cli_command *root, struct apppool *pool)
{
	do_pool_configure_show_command(cli, root, pool);
	do_pool_configure_elastic_command(cli, root, pool);
	return 0;
}
static int pool_configure_commands(struct cli_def *cli, char *poolname)
{
	struct apppool *pool;
	LIST_HEAD(queue);

	module_get_queue(&queue, "apppool", poolname);

	/** 这里有且只有一个成员 **/
	list_for_each_entry(pool, &queue, list) {
		do_pool_configure_commands(cli, cli->folder, pool);
	}
	module_purge_queue(&queue, "apppool");

	return CLI_OK;
}

static int pool_set_default(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	pool_configure_commands(cli, argv[0]);
	return CLI_OK;
}

static int vmenable_set_default(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	pool_config_arg1(cli, command, argv, argc);
	pool_configure_commands(cli, cli->folder->value);
	return CLI_OK;
}

static int subjoinsched_set_default(struct cli_def *cli, char *command, char *argv[],
		int argc)
{
	pool_config_arg1(cli, command, argv, argc);
	pool_configure_commands(cli, cli->folder->value);
	return CLI_OK;
}

int pool_set_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *pool, *t;
	if (cli == NULL || parent == NULL) {
		return -1;
	}

	pool = cli_register_command(cli, parent, "pool", pool_set_default, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_POOL_MANAGE_INFO);
	cli_command_add_argument(pool, "<poolname>", NULL);
	cli_command_setvalues_func(pool, pool_get_values, default_free_values);

	t = cli_register_command(cli, pool, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	realserver_add_command(cli, t);

	t = cli_register_command(cli, pool, "delete", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_DEL_REALSERVER);
	realserver_delete_command(cli, t);

	t = cli_register_command(cli, pool, "set", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_DEL_REALSERVER);
	realserver_set_command(cli, t);

	t = cli_register_command(cli, pool, "healthcheck", pool_config_healthcheck,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_HEALTHCHECK_MANAGE_INFO);
	cli_command_add_argument(t, "[healthcheckname]", NULL);
	cli_command_setvalues_func(t, healthcheck_get_values, default_free_values);

	t = cli_register_command(cli, pool, "vmenable", vmenable_set_default,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_ENABLE);
	cli_register_command(cli, t, "on", vmenable_set_default,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_ENABLE_ON);
	cli_register_command(cli, t, "off", vmenable_set_default,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_ENABLE_OFF);

	t = cli_register_command(cli, pool, "subjoinsched", subjoinsched_set_default,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_ENABLE);
	cli_register_command(cli, t, "snmp", subjoinsched_check,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_ENABLE_ON);
	cli_register_command(cli, t, "normal", NULL,
			PRIVILEGE_PRIVILEGED, MODE_EXEC, LIBCLI_POOL_SET_VM_ENABLE_OFF);


	return 0;
}


int pool_delete_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "pool", pool_delete, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_DELETE_INFO);
	cli_command_add_argument(c, "<poolname>", NULL);
	cli_command_setvalues_func(c, pool_get_values, default_free_values);

	return 0;
}

int pool_search_port(const char *pname, int port)
{
	int n;
	char ip[STR_IP_LEN], pt[STR_PORT_LEN];
	struct apppool *apppool;
	struct rserver *rserver;
	LIST_HEAD(applist);

	apppool_queue_create(&applist, pname);

	if (list_empty(&applist)) {
		goto error;
	}

	apppool = list_entry(applist.next, struct apppool, list);

	list_for_each_entry(rserver, &apppool->realserver_head, list) {
		//get_ip_port(rserver->address, ip, pt);
		inet_sockaddr2ipport(&rserver->address, ip, pt);
		n = atoi(pt);
		if (n == port) {
			apppool_queue_purge(&applist);
			return port;
		}
		memset(ip, '\0', sizeof(ip));
		memset(pt, '\0', sizeof(pt));
	}        
error:
	apppool_queue_purge(&applist);
	return -1;
}
/* vim:set tabstop=4 softtabstop=4 shiftwidth=4 expandtab: */
