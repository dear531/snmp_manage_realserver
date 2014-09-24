#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <syslog.h>

#include "license/license.h"

#include "common/strldef.h"
#include "common/base64.h"
#include "common/common.h"
#include "common/module.h"
#include "common/dependence.h"
#include "common/strldef.h"
#include "loadbalance/healthcheck.h"
#include "loadbalance/apppool.h"
#include "loadbalance/vserver.h"
#include "loadbalance/rule.h"
#include "cluster/hb.h"

#include "layer7.h"
#include "generator.h"
#include "bind9cfg.h"

#include "gslb.h"
#include "llb.h"

extern struct global global;

static LIST_HEAD(generator_head);


static int translate_str(char *out, char *in, struct rserver *rs)
{
	char ip[STR_IP_LEN], port[STR_PORT_LEN];
	char *pos;
	char tmp[BUFSIZ];

	memset(ip, 0, sizeof(ip));
	memset(port, 0, sizeof(port));
	memset(tmp, 0, sizeof(tmp));

	out[0] = 0;
	/** get ip & port **/
	//get_ip_port(rs->address, ip, port);
	inet_sockaddr2ipport(&rs->address, ip, port);

	/** change @ip **/
	if ((pos = strstr(in, "@ip")) != NULL) {
		strncpy(tmp, in, pos - in);
		strcat(tmp, ip);
		strcat(tmp, pos + 3);
		strcpy(out, tmp);
	}

	/** change @port **/
	if ((pos = strstr(in, "@port")) != NULL) {
		strncpy(tmp, in, pos - in);
		strcat(tmp, port);
		strcat(tmp, pos + 5);
		strcpy(out, tmp);
	}

	if (out[0] == 0) {
		strcpy(out, in);
	}

	return 0;
}
/**---------------------------------------------**/
static int translate_str_for_icmp_gw(char *out, char *in,struct healthcheck *healthcheck)
{
	char *pos;
	char tmp[BUFSIZ];
	memset(tmp,0,sizeof(tmp));
	out[0] = 0;
	if ((pos = strstr(in, "@gateway")) != NULL) {
		strncpy(tmp,in,pos - in);
		strcat(tmp, healthcheck->gateway);
		strcat(tmp, pos + 8);
		strcpy(out,tmp);
	}
	return 0;
}
/**---------------------------------------------**/


static void __write_healthcheck_policy(FILE *fp, struct healthcheck *healthcheck)
{
	if (healthcheck->timeout[0] == 0 || strcmp(healthcheck->timeout, "0") == 0) {
		fprintf(fp, "\t\t\tconnect_timeout 5\n");
	} else {
		fprintf(fp, "\t\t\tconnect_timeout %s\n", healthcheck->timeout);
	}


	/** 重试次数 **/
	if (healthcheck->retry[0] == 0 || strcmp(healthcheck->retry, "0") == 0) {
		fprintf(fp, "\t\t\tnb_get_retry 3\n");
	} else {
		fprintf(fp, "\t\t\tnb_get_retry %s\n", healthcheck->retry);
	}

	/** 检测周期 **/
	if (healthcheck->interval[0] == 0 || strcmp(healthcheck->interval, "0") == 0) {
		fprintf(fp, "\t\t\tdelay_before_retry 5\n");
	} else {
		fprintf(fp, "\t\t\tdelay_before_retry %s\n", healthcheck->interval);
	}

	/** DownTime **/
	if (healthcheck->intermission[0] == 0 || strcmp(healthcheck->intermission, "0") == 0) {
		fprintf(fp, "\t\t\tdowntime 5\n");
	} else {
		fprintf(fp, "\t\t\tdowntime %s\n", healthcheck->intermission);
	}

}

static void __write_healthcheck(FILE *fp, struct rserver *rs, 
		struct apppool *apppool, struct healthcheck *healthcheck)
{
	if (!strcasecmp(healthcheck->type, "tcp"))
	{
		fprintf(fp, "\t\tTCP_CHECK {\n");
		__write_healthcheck_policy(fp, healthcheck);
		fprintf(fp, "\t\t}\n");
	}
	else if (!strcasecmp(healthcheck->type, "http") || !strcasecmp(healthcheck->type, "https"))
	{
		if (!strcasecmp(healthcheck->type, "http"))
			fprintf(fp, "\t\tHTTP_GET {\n");
		else
			fprintf(fp, "\t\tSSL_GET {\n");

		fprintf(fp, "\t\t\turl {\n");
		if (strlen(healthcheck->path))
			fprintf(fp, "\t\t\t\tpath %s\n", healthcheck->path);
		if (strlen(healthcheck->status_code))
			fprintf(fp, "\t\t\t\tstatus_code %s\n", healthcheck->status_code);
		fprintf(fp, "\t\t\t}\n");

		__write_healthcheck_policy(fp, healthcheck);
		fprintf(fp, "\t\t}\n");				/* http block end */
	}
	/**--------------------------------------------------------------**/
	else if (!strcasecmp(healthcheck->type, "http-ecv") || !strcasecmp(healthcheck->type, "https-ecv"))
	{
		if (!strcasecmp(healthcheck->type, "http-ecv"))
			fprintf(fp, "\t\tHTTP_GET {\n");
		else
			fprintf(fp, "\t\tSSL_GET {\n");

		fprintf(fp, "\t\t\turl {\n");
		if (strlen(healthcheck->path))
			fprintf(fp, "\t\t\t\tpath %s\n", healthcheck->path);
		if (strlen(healthcheck->status_code))
			fprintf(fp, "\t\t\t\tstatus_code %s\n", healthcheck->status_code);

		if (strlen(healthcheck->string)) {
			fprintf(fp, "\t\t\t\thttp_type %s\n",healthcheck->http_type);
			fprintf(fp, "\t\t\t\toffset %d\n", atoi(healthcheck->offset));
			fprintf(fp, "\t\t\t\tstring %s\n", healthcheck->string);
		}
		fprintf(fp, "\t\t\t}\n");
		__write_healthcheck_policy(fp, healthcheck);
		fprintf(fp, "\t\t}\n");				/* http block end */
	}
	/**--------------------------------------------------------------**/
	else if (!strcasecmp(healthcheck->type, "smtp"))
	{
		fprintf(fp, "\t\tSMTP_CHECK {\n");

		__write_healthcheck_policy(fp, healthcheck);
		if (strlen(healthcheck->helo))
			fprintf(fp, "\t\t\thelo_name %s\n", healthcheck->helo);
		fprintf(fp, "\t\t}\n");
	}
	else if (!strcasecmp(healthcheck->type, "script"))
	{
		fprintf(fp, "\t\tMISC_CHECK {\n");
		if (strlen(healthcheck->script)) {
			fprintf(fp, "\t\t\tmisc_path \"%s%s\"\n", 
					HC_SCRIPTS_TO_DIR, healthcheck->script);
		}
		__write_healthcheck_policy(fp, healthcheck);
		fprintf(fp, "\t\t}\n");
	}
	else if (!strcasecmp(healthcheck->type, "icmp"))
	{
		char buff[BUFSIZ];
		char command[BUFSIZ];

		if (strcmp(apppool->type, "ipv6") == 0) {
			/** 需要检查该IP在哪个vlan上，或mgmt上 **/
			char interface[16];
			char ip[STR_IP_LEN];

			inet_sockaddr2ip(&rs->address, ip);

			//get_ip_port(rs->address, ip, NULL);
			get_interface_via_ipaddr(ip, interface);
			sprintf(command, "ping6 -I %s @ip -c 1", interface);
		} else {
			strcpy(command, "ping @ip -c 1");
		}

		memset(buff, 0, BUFSIZ);
		translate_str(buff, command, rs);

		fprintf(fp, "\t\tMISC_CHECK {\n");
		fprintf(fp, "\t\t\tmisc_path \"%s\"\n", buff);

		__write_healthcheck_policy(fp, healthcheck);
		fprintf(fp, "\t\t}\n");
	}
	/**-----------------------------------------------------------**/
	else if (!strcasecmp(healthcheck->type, "icmp-gw") && healthcheck->gateway[0] != 0)
	{
		char *tmp = "ping @gateway -c 1";
		char buff[BUFSIZ];

		memset(buff, 0, BUFSIZ);
		translate_str_for_icmp_gw(buff, tmp, healthcheck); 
		fprintf(fp, "\t\tMISC_CHECK {\n");
		fprintf(fp, "\t\t\tmisc_path \"%s\"\n", buff);

		__write_healthcheck_policy(fp, healthcheck);
		fprintf(fp, "\t\t}\n");
	}
	/**-----------------------------------------------------------**/
	else if (!strcasecmp(healthcheck->type, "dns"))
	{
		char buff[BUFSIZ];
		char command[BUFSIZ];

		sprintf(command, "dig %s @@ip +tries=1 +time=30", healthcheck->domain);

		memset(buff, 0, BUFSIZ);
		translate_str(buff, command, rs);

		fprintf(fp, "\t\tMISC_CHECK {\n");
		fprintf(fp, "\t\t\tmisc_path \"%s\"\n", buff);

		__write_healthcheck_policy(fp, healthcheck);
		fprintf(fp, "\t\t}\n");
	}
}

/* 
 * rcheck: realserver healthcheck
 * pcheck: apppool healthcheck
 * healthqueue: all exist healthcheck
 *
 * healthcheck=check888   check888 is the name of healthcheck
 */
static void write_healthcheck(FILE *fp, struct rserver *rs, struct apppool *apppool,
		struct list_head *healthqueue)
{
	struct list_head *list;
	struct healthcheck *healthcheck = NULL;
	char *check = strlen(rs->healthcheck) ? rs->healthcheck : apppool->healthcheck;
	if (!check)
		goto out;
	if ((list = module_queue_search("healthcheck", healthqueue, check)) == NULL) {
		goto out;
	}
	healthcheck = list_entry(list, struct healthcheck, list);
	__write_healthcheck(fp, rs, apppool, healthcheck);
out:
	return;
}


#define SORRY_SERVER		0
#define WORK_SERVER		1

static int print_rserver_parameter(FILE *fp, struct rserver *rserver,
		struct apppool *pool,
		struct list_head *healthqueue,
		const char *str,const int n)
{
	char ip[STR_IP_LEN], port[STR_PORT_LEN];

	get_ip_port(str, ip, port);

	if (check_ip_version(ip) == IPV6) {
		fprintf(fp, "\t%s [%s] %s {\n", n == SORRY_SERVER ? "sorry_server" : "real_server", 
				ip, port);
	} else {
		fprintf(fp, "\t%s %s %s {\n", n == SORRY_SERVER ? "sorry_server" : "real_server", 
				ip, port);
	}
	fprintf(fp, "\t\tpoolname %s\n", pool->name);
	if (0 == memcmp(pool->subjoinsched, "snmp", sizeof("snmp"))) {
		if (strlen(rserver->snmp_weight))
			fprintf(fp, "\t\tweight %s\n", rserver->snmp_weight);
	} else {
		if (strlen(rserver->weight))
			fprintf(fp, "\t\tweight %s\n", rserver->weight);
	}
	if (strlen(rserver->maxconn))
		fprintf(fp, "\t\tconnmax %s\n", rserver->maxconn);
	if (strlen(rserver->bandwidth))
		fprintf(fp, "\t\tbandwidth %lu\n", ((uint64_t)atol(rserver->bandwidth)) >> 3);
	write_healthcheck(fp, rserver, pool, healthqueue);
	fprintf(fp, "\t}\n");
	return 0;
}


static int print_rserver(FILE *fp, struct rserver *rserver,
		struct apppool *pool, struct list_head *healthqueue,
		const int n)
{
	if (rserver_draining_or_disabling(rserver)) {
		return 0;
	}
	char address[BUFSIZ];
	inet_sockaddr2address(&rserver->address, address);

	print_rserver_parameter(fp, rserver, pool, healthqueue, address, n);
	return 0;
}

static void write_work_server(FILE *fp, 
		struct list_head *queue, 
		struct apppool *apppool,
		struct list_head *healthqueue)
{
	struct rserver *rserver;

	list_for_each_entry(rserver, queue, list) {
		if (strcasecmp(rserver->enable, "on") == 0) {
			print_rserver(fp, rserver, apppool, healthqueue, WORK_SERVER);
		}
	}
}

static void write_sorry_server(FILE *fp, 
		struct list_head *queue, 
		struct apppool *apppool,
		struct list_head *healthqueue)
{
	struct rserver *rserver;

	list_for_each_entry(rserver, queue, list) {
		if (strcasecmp(rserver->enable, "on") == 0) {
			print_rserver(fp, rserver, apppool, healthqueue, SORRY_SERVER);
		}
	}
}


	__attribute__((unused))
static int get_delay_loop(struct vserver *vserver, 
		struct apppool *apppool,
		struct list_head *healthqueue)
{
	int delay_loop = 30;
	int interval;
	struct rserver *rserver;
	struct list_head *list;
	struct healthcheck *healthcheck;

	list_for_each_entry(rserver, &apppool->realserver_head, list) {
		if (!strncasecmp(rserver->enable, "on", 2)) {
			char *check = strlen(rserver->healthcheck) ? rserver->healthcheck : apppool->healthcheck;
			if (!check)
				continue;
			if ((list = module_queue_search("healthcheck", healthqueue, check)) == NULL) {
				continue;
			}
			healthcheck = list_entry(list, struct healthcheck, list);
			interval = atoi(healthcheck->interval);
			if (interval < delay_loop)
				delay_loop = interval;
		}
	}

	if (delay_loop == 0)
		delay_loop = 30;
	return delay_loop;
}



static int write_realserver(FILE *fp, struct vserver *vserver, 
		struct list_head *appqueue,
		struct list_head *healthqueue,
		struct list_head *rulequeue) 
{
	struct rule *rule;
	struct rule_name *rule_name;
	char pool_name[1024]={0};
	struct apppool *apppool;
	struct list_head *list;

	if (strcasecmp(vserver->contentswitch, "on") == 0) {
		/**//** 打开了contentswitch，忽略掉 vserver->pool **/
		list_for_each_entry(rule_name, &vserver->rule_head, list) {
			if ((list = module_queue_search("rule", rulequeue, 
							rule_name->name)) == NULL) {
				continue;
			}
			rule = list_entry(list, struct rule, list);

			/*memset(buff, 0, BUFSIZ);*/
			if (get_poolname_from_rule(rule, pool_name, 1024) == NULL) {
				continue;
			}

			if ((list = module_queue_search("apppool", 
							appqueue, 
							pool_name)) == NULL) {
				continue;
			}
			apppool = list_entry(list, struct apppool, list);
			write_work_server(fp, &apppool->realserver_head, apppool, healthqueue);
		}
	} else {
		if ((list = module_queue_search("apppool", 
						appqueue, 
						vserver->pool)) != NULL) {
			apppool = list_entry(list, struct apppool, list);
			write_work_server(fp, &apppool->realserver_head, apppool, healthqueue);
		}
		/* write sorry */
		if ((list = module_queue_search("apppool", 
						appqueue, 
						vserver->backpool)) != NULL) {
			apppool = list_entry(list, struct apppool, list);
			write_sorry_server(fp, &apppool->realserver_head, apppool, healthqueue);
		}
	}
	return 0;
}

static void generate_layer4_config(struct vserver *vserver, 
		struct list_head *appqueue,
		struct list_head *healthqueue,
		struct list_head *rulequeue,
		char *filename_bk)
{
	FILE *fp;
	__attribute__((unused)) int delay_loop;

	char ip[STR_IP_LEN], port[STR_PORT_LEN];

	if (inet_sockaddr2ipport(&vserver->address, ip, port) != 0) {
		return;
	}

	if ((fp = fopen(filename_bk, "a")) == NULL)		/* append */
		goto out;

	if (check_ip_version(ip) == IPV6) {
		fprintf(fp, "virtual_server [%s] %s {\n", ip, port);
	} else {
		fprintf(fp, "virtual_server %s %s {\n", ip, port);
	}

	/** FIXME **/
	fprintf(fp, "\tdelay_loop 3\n");

	/** scheduler **/
	if (strlen(vserver->sched)) {
		if (strcmp(vserver->sched, "lc") == 0) {
			fprintf(fp, "\tlb_algo wlc\n");
		} else {
			fprintf(fp, "\tlb_algo %s\n", vserver->sched);
		}
	} else {
		fprintf(fp, "\tlb_algo %s\n", "rr");
	}
	/**********By zhangjie**************/
	if (strcasecmp(vserver->mode, "dr") == 0){
		fprintf(fp, "\tlb_kind DR\n");
	} else {
		fprintf(fp, "\tlb_kind NAT\n");
	}
	/*********************************/
	/** only for keepalived to print information **/
	fprintf(fp, "\tvsname %s\n", vserver->name);

	/** "0"端口 或 "*"端口，必须打开保持功能 **/
	if (strcmp(port, "0") == 0 || strcmp(port, "*") == 0 
			|| vserver->persistent[0] != 0) {

		char netmask_str[STR_NETMASK_LEN];

		if (check_ip_version(ip) == IPV4) {
			if (atoi(vserver->persistentnetmask) == 0) {
				strcpy(vserver->persistentnetmask, "24");
			}

			bits2mask(vserver->persistentnetmask, netmask_str);

			fprintf(fp, "\tpersistence_granularity %s\n", netmask_str);
		} else {
			if (atoi(vserver->persistentnetmask) == 0) {
				strcpy(vserver->persistentnetmask, "64");
			}
			fprintf(fp, "\tpersistence_granularity %s\n", vserver->persistentnetmask);
		}

		/** 会话保持超时 **/
		if (vserver->timeout[0] != 0)
			fprintf(fp, "\tpersistence_timeout %s\n", vserver->timeout);
		else
			fprintf(fp, "\tpersistence_timeout 900\n");
	}

	/* private member start */
	if (strlen(vserver->maxconn))
		fprintf(fp, "\tconnmax %s\n", vserver->maxconn);	/* maximum connection number */

	if (strlen(vserver->bandwidth))
		fprintf(fp, "\tbandwidth %lu\n", ((uint64_t)atol(vserver->bandwidth)) >> 3);

	/* private member end */

	if (!strncasecmp(vserver->protocol, "tcp", 3)) {
		fprintf(fp, "\tprotocol TCP\n");
		fprintf(fp, "\tSSLSession_id true\n");
	} else if (!strncasecmp(vserver->protocol, "udp", 3)) {
		fprintf(fp, "\tprotocol UDP\n");
	} else if (!strncasecmp(vserver->protocol, "ftp", 3)) {
		fprintf(fp, "\tprotocol TCP\n");
		fprintf(fp, "\tapplication_protocol FTP\n");
		fprintf(fp, "\tftp_data_port %s\n", vserver->data_port[0] == 0 ? "20" : vserver->data_port);
	} else if (!strncasecmp(vserver->protocol, "fast-tcp", 8)) {
		fprintf(fp, "\tprotocol TCP\n");
	} else if (!strncasecmp(vserver->protocol, "SSLBridge", 9)) {
		fprintf(fp, "\tprotocol TCP\n");
		fprintf(fp, "\tSSLSession_id true\n");			/* SSLBridge protocol flag */
	} else if (!strncasecmp(vserver->protocol, "RDPBridge", 9)) {
		fprintf(fp, "\tprotocol TCP\n");
		fprintf(fp, "\tRDPCookie true\n");			/* RDPBridge protocol flag */
	} else {
		fprintf(fp, "\tprotocol %s\n", vserver->protocol);
	}
	/***********By zhangjie*****************************/
	if(strcasecmp(vserver->mode, "nat") == 0) {
		if (strncasecmp(vserver->transparent, "on", 2) != 0) {
			fprintf(fp, "\tfullnat on\n");
		}
	} else if (strcasecmp(vserver->mode, "dr") == 0) {
		fprintf(fp, "\tfullnat off\n");
	}

	if (0) {
		fprintf(fp, "\thwchecksum off\n");
	} else {
		/** 检查是否是虚拟机 **/
		static char serial_num[1024] = {0};

		if (serial_num[0] == 0) {
			license_show_serial_number(serial_num);
		}

		if (strncmp(serial_num, "WiseGrid vADC", strlen("WiseGrid vADC")) == 0) {
			fprintf(fp, "\thwchecksum off\n");
		} else {
			fprintf(fp, "\thwchecksum on\n");
		}
	}

	write_realserver(fp, vserver, appqueue, healthqueue, rulequeue);

	fprintf(fp, "}\n");					/* over */
	fprintf(fp, "\n");

	fflush(fp);
	fclose(fp);
out:
	return;
}

/* this function process TCP,UDP,SSLBridge protocol */
static int generator_layer4(struct list_head *vsqueue, 
		struct list_head *appqueue,
		struct list_head *healthqueue,
		struct list_head *rulequeue,
		struct list_head *hbqueue,
		char *filename)
{
	struct vserver *vserver;

	time_t now;
	static time_t last = 0;

	now = time(NULL);
	if (now - last > 120) {
		if (license_check() == -1) {
			struct apppool *apppool;
			struct rserver *rserver;
			/** license失效 **/
			truncate(CHECK_CONF, 0);

			/** 将所有真实服务器的状态设置为down **/
			list_for_each_entry(apppool, appqueue, list) {
				list_for_each_entry(rserver, &apppool->realserver_head, list) {
					strcpy(rserver->state, "down");
				}
			}

			return 1;	/* keepalived config update */
		}

		/** license无效，则不更新last **/
		last = now;
	}

	list_for_each_entry(vserver, vsqueue, list) {
		if (strncasecmp(vserver->enable, "on", 2))
			continue;
		if (strncasecmp(vserver->protocol, "tcp", 3) 
				&& strncasecmp(vserver->protocol, "fast-tcp", 8)
				&& strncasecmp(vserver->protocol, "udp", 3)
				&& strncasecmp(vserver->protocol, "ftp", 3)
				&& strncasecmp(vserver->protocol, "sslbridge", 9)
				&& strncasecmp(vserver->protocol, "rdpbridge", 9)
				&& strncasecmp(vserver->protocol, "http", 4)/* http & https **/)
			continue;
		generate_layer4_config(vserver, appqueue, healthqueue, 
				rulequeue, CHECK_CONF_BK);
	}

	// Add GSLB healthcheck by Fanyunfei @2012-06-17
	gslb_healthcheck_register(CHECK_CONF_BK);

	// Add LLB healthcheck by Fanyunfei @2012-06-20
	llb_healthcheck_register(CHECK_CONF_BK);

	if (access(CHECK_CONF_BK, F_OK) != 0) {
		FILE *fp;
		if ((fp = fopen(CHECK_CONF_BK, "w+"))==NULL){
			return -1;
		}
		fclose(fp);
	}

	int ret = 0;
	ret = system("ps -Lf -C keepalived > /dev/null 2>&1");

	if (ret < 0 || WEXITSTATUS(ret) != 0) {
		system(KEEPALIVED_BIN_PATH);
	}

	if (check_diff_file(CHECK_CONF_BK, CHECK_CONF) != 0) {
		rename(CHECK_CONF_BK, CHECK_CONF);	/* keepalived config update */

#define CHECK_PID_FILE           "/var/run/checkers.pid"
		if (access(CHECK_PID_FILE, F_OK) == 0) {
			system("kill -s HUP `cat " CHECK_PID_FILE "`");
		}
		return 1;
	} else {
		unlink(CHECK_CONF_BK);
	}

	return 0;
}

/* layer4 ignore filename argument */
static int register_generator(char *name, 
		int (*handler)(struct list_head *vsqueue, 
			struct list_head *appqueue,
			struct list_head *healthqueue,
			struct list_head *rulequeue,
			struct list_head *hbqueue,
			char *filename),
		char *filename)
{
	struct generator *generator;

	generator = calloc(1, sizeof(struct generator));
	if (generator == NULL)
		goto out;

	strncpy(generator->name, name, sizeof(generator->name) - 1);
	strncpy(generator->filename, filename, sizeof(generator->name) - 1);
	generator->handler = handler;

	list_add_tail(&generator->list, &generator_head);
	return 0;
out:
	return -1;
}

static int create_keepalived_smartl7_config(struct list_head *generator_head,
		struct list_head *vsqueue, 
		struct list_head *appqueue,
		struct list_head *healthqueue,
		struct list_head *rulequeue,
		struct list_head *hbqueue)
{
	int ret = 0;
	struct generator *generator;

	list_for_each_entry(generator, generator_head, list) {
		/** 如果l4和l7其中一个配置文件有更新的话，则需要通知keepalived **/
		if (generator->handler(vsqueue, appqueue, healthqueue, 
					rulequeue, hbqueue, generator->filename) > 0) {
			ret = 1;
		}
	}
	return ret;
}

void generator_entrance(struct event *e)
{
	LIST_HEAD(vserver_head);
	LIST_HEAD(apppool_head);
	LIST_HEAD(healthcheck_head);
	LIST_HEAD(rule_head);
	LIST_HEAD(hb_head);

	time_t now;
	static time_t last = 0;

	/** 时间限制，1秒只做一次配置文件变更 **/
	now = time(NULL);

	if (last == now) {
		return;
	}

	last = now;

	module_get_queue(&vserver_head, "vserver", NULL);
	module_get_queue(&apppool_head, "apppool", NULL);
	module_get_queue(&rule_head, "rule", NULL);
	module_get_queue(&healthcheck_head, "healthcheck", NULL);
	module_get_queue(&hb_head, "hb", NULL);

	create_keepalived_smartl7_config(&generator_head,
				&vserver_head, 
				&apppool_head, 
				&healthcheck_head, 
				&rule_head,
				&hb_head);

	module_purge_queue(&hb_head, "hb");
	module_purge_queue(&healthcheck_head, "healthcheck");
	module_purge_queue(&rule_head, "rule");
	module_purge_queue(&apppool_head, "apppool");
	module_purge_queue(&vserver_head, "vserver");
}





	__attribute__((constructor))
static void register_all_generator(void)
{
	register_generator("gslb", generator_gslb_config, "nothing");
	register_generator("bind9", generator_bind9_config, "nothing");

	register_generator("layer4", generator_layer4, "nothing");
	register_generator("layer7", update_config, NGINX_CONF);
}


