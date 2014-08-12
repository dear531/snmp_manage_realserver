
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <time.h>

#include "base64.h"
#include "strldef.h"
#include "common.h"
#include "common/dependence.h"
#include "module.h"
#include "apppool.h"
#include "vserver.h"
#include "rule.h"
#include "common/base64.h"
#include "network/bandwidth.h"
#include "loadbalance/vcenter.h"



int add_batch_realserver_to_apppool(const char *poolname, const char *args,
		const char *ip_min, const char *ip_max)
{
	int ret = 0;
	char ipaddr[128];
	int i, a, b, c, d, e;
	char addr[24], ip1[24], ip2[24], port1[12], port2[12];

	get_ip_port(ip_min, ip1, port1);
	get_ip_port(ip_max, ip2, port2);

	if (strcmp(ip1, ip2) == 0) {
		i = atoi(port1);
		a = atoi(port2);
		for (; i <= a; i++) {
			sprintf(addr, "%s:%d", ip1, i);
			sprintf(ipaddr, "%s%s", addr, args);
			ret = module_add_sub("apppool", poolname, "realserver", ipaddr);
		}
	} else {
		sscanf(ip1, "%d . %d . %d . %d", &a, &b, &c, &d);
		sscanf(ip2, "%d . %d . %d . %d", &a, &b, &c, &e);
		for (i = d; i <= e; i++) {
			sprintf(addr, "%d.%d.%d.%d:%s", a, b, c, i, port1);
			sprintf(ipaddr, "%s%s", addr, args);
			ret = module_add_sub("apppool", poolname, "realserver", ipaddr);
		}
	}

	return ret;
}

/* 弹性计算：设置realserver类型到apppool类型 */
static int set_vmtype_to_apppool(const char *poolname)
{
	int found = 0;
	char address[512] = {0};
	struct apppool *pool;
	struct rserver *rs;
	struct vcenter *vc;

	LIST_HEAD(pool_queue);
	LIST_HEAD(vcenter_queue);
	module_get_queue(&pool_queue, "apppool", NULL);
	list_for_each_entry(pool, &pool_queue, list) {
		if (strcmp(pool->name, poolname) != 0) {
			continue;
		}
		list_for_each_entry(rs, &pool->realserver_head, list) {
			if (inet_sockaddr2address(&rs->address, address) != 0) {
				continue;
			}
			if ( address[0]== 0 || rs->rscenter[0] ==0 ) {
				continue;
			}
			found = 1;
			break;
		}
		if (found) {
			break;
		}
	}

	if (found) {
		found = 0;
		module_get_queue(&vcenter_queue, "vcenter", rs->rscenter);
		list_for_each_entry(vc, &vcenter_queue, list) {
			if (strcmp(vc->name, rs->rscenter) == 0) {
				/* set pool vmtype */
				strcpy(pool->vmtype, vc->type);
				found = 1;
				break;
			}
		}
	}

	if (found) {
		module_save_queue(&pool_queue, "apppool");
	}

	module_purge_queue(&vcenter_queue, "vcenter");
	module_purge_queue(&pool_queue, "apppool");

	return 0;
}
int add_realserver_to_apppool(const char *poolname, const char *value)
{
	int ret = 0;
	char ipaddr[1024], args[128], ip_min[128], ip_max[128];

	
        /** 检查IP版本 
         *      v4: 2.3.4.5:80
         *      v6: [::ffff:2.3.4.5]:80
         **/

        if (value[0] == '[') {
                /** IPv6 **/
		ret = module_add_sub("apppool", poolname, "realserver", value);
	} else {
		/** IPv4 **/
		sscanf(value, "%[^,] %s", ipaddr, args);
		/*检查合法性*/
		get_batch_ip_port(ipaddr, ip_min, ip_max);
		if (strcmp(ip_min, ip_max) == 0) {
			sprintf(ipaddr, "%s%s", ip_min, args);
			ret = module_add_sub("apppool", poolname, "realserver", ipaddr);
		} else {
			ret = add_batch_realserver_to_apppool(poolname, args, ip_min, ip_max);
		}
	}
	if (!ret) {
		set_vmtype_to_apppool(poolname);
	}

	return ret;
}

static struct list_head *realserver_malloc(void)
{
	struct rserver *realserver;
	if ((realserver = calloc(1, sizeof(*realserver))) == NULL) {
		return NULL;
	}
	strcpy(realserver->state, "unknown");
	return &realserver->list;
}


struct list_head *apppool_malloc(void)
{
	struct apppool *apppool;
	if ((apppool = calloc(1, sizeof(*apppool))) == NULL) {
		return NULL;
	}
	memset(apppool, 0, sizeof(*apppool));
	strcpy(apppool->type, "ipv4");
	strcpy(apppool->vmenable, "off");
	INIT_LIST_HEAD(&apppool->realserver_head);
	return &apppool->list;
}

static int apool_set_vm_enable_valid(struct apppool *pool)
{
	int rc = 1;
	struct vserver *vs;

	LIST_HEAD(vserver_head);

#if 0
	/* 1. check pool has rservers */
	if (!list_empty(&pool->realserver_head)) {
		rc = 0;
	}
#endif

	/* 2. check vserver use this pool and vserver->vm_enable != pool->vm_enable */
	if (rc) {
		module_get_queue(&vserver_head, "vserver", NULL);
		list_for_each_entry(vs, &vserver_head, list) {
			if (strcasecmp(vs->pool, pool->name) == 0) {
				if (strcasecmp(vs->vm_enable, pool->vmenable) != 0) {
					rc = 0;
					break;
				}
			}
		}
		module_purge_queue(&vserver_head, "vserver");
	}

	return rc;
}

static void realserver_free(struct list_head *list)
{
	struct rserver *realserver = list_entry(list, struct rserver, list);
	free(realserver);
}

void apppool_free(struct list_head *list)
{
	struct list_head *l;
	struct apppool *apppool = list_entry(list, struct apppool, list);
	while (!list_empty(&apppool->realserver_head)) {
		l = apppool->realserver_head.next;
		list_del(l);
		realserver_free(l);
	}

	free(apppool);
}

/** pnode --> list **/
static int realserver_analyse(xmlNodePtr pnode, struct list_head *list)
{
	struct rserver *realserver = list_entry(list, struct rserver, list);
	//m_analyse_common(pnode, realserver, address);

	const char * value;
	if ((value = config_search_attr_value(pnode, "address")) != NULL) {
		inet_address2sockaddr(value, &realserver->address);
		xmlFree((void *)value);
	}

	m_analyse_common(pnode, realserver, maxconn);
	m_analyse_common(pnode, realserver, bandwidth);
	m_analyse_common(pnode, realserver, maxreq);
	m_analyse_common(pnode, realserver, weight);
	m_analyse_common(pnode, realserver, healthcheck);
	m_analyse_common(pnode, realserver, enable);
	m_analyse_common(pnode, realserver, state);
	m_analyse_common(pnode, realserver, id);

	/* used for elastic */
	m_analyse_common(pnode, realserver, rscenter);
	m_analyse_common(pnode, realserver, vmdatacenter);
	/* used for vmware */
	m_analyse_common(pnode, realserver, vmxpath);
	/* used for xen */
	m_analyse_common(pnode, realserver, uuid);
	/* used for vcenter */
	m_analyse_common(pnode, realserver, vmname);
	m_analyse_common(pnode, realserver, vmstate);
	/*
	 * below handle function for snmpwalk 
	 * to obtain cpu and memory data
	 * @zhangly2014.8.6
	 */
	/* check snmp state: vilad,invilad */
	m_analyse_common(pnode, realserver, snmp_check);
	/* snmp version of realserver */
	m_analyse_common(pnode, realserver, snmp_version);
	/* snmp name */
	m_analyse_common(pnode, realserver, name);
    /* on, off */
	m_analyse_common(pnode, realserver, snmp_enable);
	/* community */
	m_analyse_common(pnode, realserver, community);
	/* SNMPv3 auth type, MD5 or SHA1 */
	m_analyse_common(pnode, realserver, auth_type);
	/* noAuthNoPriv|authNoPriv|authPriv */
	m_analyse_common(pnode, realserver, securelevel);
	/* control snmptrap */
	m_analyse_common(pnode, realserver, trap_enable);
	/* manager ip */
	m_analyse_common(pnode, realserver, trap_manager);
	/* trap v3 engine id */
	m_analyse_common(pnode, realserver, trap_v3_engineid);
	/* trap v3 username */
	m_analyse_common(pnode, realserver, trap_v3_username);
	/* trap v3 password */
	m_analyse_common(pnode, realserver, trap_v3_password);
	/* DES, AES */
	m_analyse_common(pnode, realserver, trap_v3_privacy_protocol);
	/* privacy password */
	m_analyse_common(pnode, realserver, trap_v3_privacy_password); 
	/* authencation usm_name */
	m_analyse_common(pnode, realserver, username);
	/* authencation password */
	m_analyse_common(pnode, realserver, password);

	return 0;
}

/** pnode --> list **/
static int apppool_analyse(xmlNodePtr pnode, struct list_head *list)
{
	struct apppool *apppool = list_entry(list, struct apppool, list);
	m_analyse_common(pnode, apppool, name);
	m_analyse_common(pnode, apppool, type);
	m_analyse_common(pnode, apppool, healthcheck);
	m_analyse_common(pnode, apppool, vmtype);
	m_analyse_common(pnode, apppool, vmaddress);
	m_analyse_common(pnode, apppool, vmenable);
	m_analyse_common(pnode, apppool, vmusername);
	m_analyse_common(pnode, apppool, vmpassword);
	m_analyse_common(pnode, apppool, vminterval);
	m_analyse_common(pnode, apppool, vmcount);
	m_analyse_common(pnode, apppool, vmvcenter);
	m_analyse_common(pnode, apppool, vmhost);
	m_analyse_common(pnode, apppool, vmdatacenter);
	m_analyse_common(pnode, apppool, vmport);
	m_analyse_common(pnode, apppool, alive_vm);
	return 0;
}

/** pnode <-- list **/
static int realserver_restore(xmlNodePtr pnode, struct list_head *list)
{
	struct rserver *realserver = list_entry(list, struct rserver, list);
	//m_restore_common(pnode, realserver, address);
	char address[BUFSIZ];
	if (inet_sockaddr2address(&realserver->address, address) == 0) {
		config_set_attr_value(pnode, "address", address);
	}
	m_restore_common(pnode, realserver, maxconn);
	m_restore_common(pnode, realserver, bandwidth);
	m_restore_common(pnode, realserver, maxreq);
	m_restore_common(pnode, realserver, weight);
	m_restore_common(pnode, realserver, healthcheck);
	m_restore_common(pnode, realserver, enable);
	m_restore_common(pnode, realserver, state);
	m_restore_common(pnode, realserver, id);

	/* used for elastic */
	m_restore_common(pnode, realserver, rscenter);
	m_restore_common(pnode, realserver, vmdatacenter);
	/* used for vmware */
	m_restore_common(pnode, realserver, vmxpath);
	/* used for xen */
	m_restore_common(pnode, realserver, uuid);
	/* use for vcenter */
	m_restore_common(pnode, realserver, vmname);
	m_restore_common(pnode, realserver, vmstate);
	/*
	 * below handle function for snmpwalk 
	 * to obtain cpu and memory data
	 * @zhangly2014.8.6
	 */
	/* check snmp state: vilad,invilad */
	m_restore_common(pnode, realserver, snmp_check);
	/* snmp version of realserver */
	m_restore_common(pnode, realserver, snmp_version);
	/* snmp name */
	m_restore_common(pnode, realserver, name);
    /* on, off */
	m_restore_common(pnode, realserver, snmp_enable);
	/* community */
	m_restore_common(pnode, realserver, community);
	/* SNMPv3 auth type, MD5 or SHA1 */
	m_restore_common(pnode, realserver, auth_type);
	/* noAuthNoPriv|authNoPriv|authPriv */
	m_restore_common(pnode, realserver, securelevel);
	/* control snmptrap */
	m_restore_common(pnode, realserver, trap_enable);
	/* manager ip */
	m_restore_common(pnode, realserver, trap_manager);
	/* trap v3 engine id */
	m_restore_common(pnode, realserver, trap_v3_engineid);
	/* trap v3 username */
	m_restore_common(pnode, realserver, trap_v3_username);
	/* trap v3 password */
	m_restore_common(pnode, realserver, trap_v3_password);
	/* DES, AES */
	m_restore_common(pnode, realserver, trap_v3_privacy_protocol);
	/* privacy password */
	m_restore_common(pnode, realserver, trap_v3_privacy_password); 
	/* authencation usm_name */
	m_restore_common(pnode, realserver, username);
	/* authencation password */
	m_restore_common(pnode, realserver, password);

	return 0;
}

/** pnode <-- list **/
static int apppool_restore(xmlNodePtr pnode, struct list_head *list)
{
	struct apppool *apppool = list_entry(list, struct apppool, list);
	m_restore_common(pnode, apppool, name);
	m_restore_common(pnode, apppool, type);
	m_restore_common(pnode, apppool, healthcheck);
	m_restore_common(pnode, apppool, vmtype);
	m_restore_common(pnode, apppool, vmaddress);
	m_restore_common(pnode, apppool, vmenable);
	m_restore_common(pnode, apppool, vmusername);
	m_restore_common(pnode, apppool, vmpassword);
	m_restore_common(pnode, apppool, vminterval);
	m_restore_common(pnode, apppool, vmcount);
	m_restore_common(pnode, apppool, vmvcenter);
	m_restore_common(pnode, apppool, vmhost);
	m_restore_common(pnode, apppool, vmdatacenter);
	m_restore_common(pnode, apppool, vmport);
	m_restore_common(pnode, apppool, alive_vm);
	return 0;
}

static int realserver_compare(struct list_head *list, const char *name)
{
	char ipaddr[BUFSIZ], ipaddr2[BUFSIZ];
	struct rserver *rserver = list_entry(list, struct rserver, list);

	sscanf(name, "%[^,] ", ipaddr);
	inet_sockaddr2address(&rserver->address, ipaddr2);

	return check_ipport_equal(ipaddr2, ipaddr);
}

struct rserver *realserver_search(struct list_head *head, const char *name)
{
	struct rserver *rserver;

	list_for_each_entry(rserver, head, list) {
		if (realserver_compare(&rserver->list, name) == 0)
			return rserver;
	}
	return NULL;
}

static int apppool_compare(struct list_head *list, const char *name)
{
	struct apppool *apppool = list_entry(list, struct apppool, list);
	return strcasecmp(apppool->name, name);
}

struct apppool *apppool_search(struct list_head *head, const char *name)
{
	struct apppool *apppool;

	list_for_each_entry(apppool, head, list) {
		if (apppool_compare(&apppool->list, name) == 0)
			return apppool;
	}

	return NULL;
}
static void set_value(char *buf, char *dst)
{
	char *p;
	p = strchr(buf, '=');
	if (p == NULL) {
		dst = NULL;
	}else{
		if (++p)
			sscanf(p, "%s", dst);
	}
}

static int realserver_set(struct list_head *list, const char *name,
		const char *attr, const char *value)
{
	char *token;
	char tmp[256] = {0};
	struct rserver *rserver = list_entry(list, struct rserver, list);

	if ((token = strtok((char *) name, ",")) != NULL) {
		token = strtok(NULL, ",");
	}
	//strcpy(rserver->address, name);
	inet_address2sockaddr(name, &rserver->address);
	
	char *p = NULL;
	int  port = 0;
	if (name[0] == '[') {
		p = strchr(name, ']');
		p += 2;
		port = atoi(p);
        int ret = 0;
        char ip_v6[STR_IP_LEN] = {0};
        char port_v6[STR_PORT_LEN] = {0};
        get_ip_port_ipv6(name, ip_v6, port_v6);

		if ((ret = address_routable(ip_v6, NULL)) != 1) {
			return -1;
		}
	} else {
		p = strchr(name, ':');
		port = atoi(++p);
	}

#define ZERO(x) memset(rserver->x, 0, sizeof(rserver->x))
	ZERO(weight);
	ZERO(bandwidth);
	ZERO(maxconn);
	ZERO(maxreq);
	ZERO(healthcheck);
	ZERO(enable);
	ZERO(vmxpath);
	ZERO(uuid);
	ZERO(rscenter);
	ZERO(vmname);
	ZERO(vmdatacenter);
#if 1
	ZERO(snmp_check);	/* recode state flag:vilad/invilad */
	ZERO(snmp_version);	/* snmp version of realserver */
	ZERO(name);      	/* snmp name */
	ZERO(snmp_enable);  /* on, off */
	ZERO(community);	/* community */
	ZERO(auth_type);	/* SNMPv3 auth type, MD5 or SHA1 */
	ZERO(securelevel);	/* noAuthNoPriv|authNoPriv|authPriv */
	ZERO(trap_enable);  /* control snmptrap */
	ZERO(trap_manager); /* manager ip */
	ZERO(trap_v3_engineid);	/* trap v3 engine id */
	ZERO(trap_v3_username);	/* trap v3 username */
	ZERO(trap_v3_password);	/* trap v3 password */
	ZERO(trap_v3_privacy_protocol);	/* DES, AES */
	ZERO(trap_v3_privacy_password);	/* privacy password */
	ZERO(username);		/* authencation usm_name */
	ZERO(password);		/* authencation password */
#endif
#undef ZERO


	while (token) {
		if (!strncasecmp(token, "weight=", 7)) {
			set_value(token, rserver->weight);
			if (strcmp(rserver->weight, "0") == 0) {
				strcpy(rserver->weight, "10");
			}
		} else if (!strncasecmp(token, "bandwidth=", 10)) {
			set_value(token, rserver->bandwidth);
			if (strcmp(rserver->bandwidth, "0") == 0) {
				rserver->bandwidth[0] = 0;
			}
		} else if (!strncasecmp(token, "maxconn=", 8)) {
			set_value(token, rserver->maxconn);
			if (strcmp(rserver->maxconn, "0") == 0) {
				rserver->maxconn[0] = 0;
			}
		} else if (!strncasecmp(token, "maxreq=", 7)) {
			set_value(token, rserver->maxreq);
			if (strcmp(rserver->maxreq, "0") == 0) {
				rserver->maxreq[0] = 0;
			}
		} else if (!strncasecmp(token, "healthcheck=", 12)) {	/* realserver healthcheck */
			set_value(token, rserver->healthcheck);
			if (port == 0) {
				if (strcmp(rserver->healthcheck, "ping") != 0 
						&& strcmp(rserver->healthcheck, "pinggw") != 0)
					return -EINVAL;
			}
		} else if (!strncasecmp(token, "enable=", 7)) {
			/* 手动关闭 enable=off */
			set_value(token, rserver->enable);
			if (!strcmp(rserver->enable, "off")) {
				strcpy(rserver->state, "disabling");
			} else {
#if 0
				if (strcmp(rserver->state, "disabling") != 0) {
					strcpy(rserver->state, "");
				}
#endif
				strcpy(rserver->state, "unknown");
			}
		} else if (!strncasecmp(token, "vmxpath=", 8)) {
			set_value(token, tmp);
			base64_decode((uint8_t *)rserver->vmxpath, tmp , 255);
		} else if (!strncasecmp(token, "uuid=", 5)) {
			set_value(token, tmp);
			base64_decode((uint8_t *)rserver->uuid, tmp , 255);
		} else if (!strncasecmp(token, "state=", 6)) {
			/* Used for elastic ,shutdown automation,  enable = on, state = disabling */
			set_value(token, rserver->state);
		} else if (!strncasecmp(token, "rscenter=", 8)) {
			set_value(token, rserver->rscenter);
			memset(rserver->vmdatacenter, 0,sizeof(rserver->vmdatacenter));
			memset(rserver->vmname, 0,sizeof(rserver->vmname));
		} else if (!strncasecmp(token, "vmdatacenter=", 8)) {
			if (rserver->rscenter[0] != 0) {
				set_value(token, rserver->vmdatacenter);
				memset(rserver->vmname, 0, sizeof(rserver->vmname));
				/* set vmname */
				char ip[512] ={0}, port[16] ={0};
				if (inet_sockaddr2ipport(&rserver->address, ip, port) == 0) {
					vcenter_vm_search(rserver->rscenter, rserver->vmdatacenter, ip, rserver->vmname);
				}
			}
#if 1
		} else if (!strncasecmp(token, "snmp_check=", 10)) {
			set_value(token, rserver->snmp_check);
		} else if (!strncasecmp(token, "snmp_version=", 13)) {
			set_value(token, rserver->snmp_version);
			if (strcmp(rserver->snmp_version, "0") == 0) {
				strcpy(rserver->snmp_version, "3");
			}
		} else if (!strncasecmp(token, "name=", 5)) {
			set_value(token, rserver->name);
		} else if (!strncasecmp(token, "snmp_enable=", 12)) {
			set_value(token, rserver->snmp_enable);
		} else if (!strncasecmp(token, "community=", 10)) {
			set_value(token, rserver->community);
		} else if (!strncasecmp(token, "auth_type=", 10)) {
			set_value(token, rserver->auth_type);
		} else if (!strncasecmp(token, "securelevel=", 12)) {
			set_value(token, rserver->securelevel);
		} else if (!strncasecmp(token, "trap_enable=", 12)) {
			set_value(token, rserver->trap_enable);
		} else if (!strncasecmp(token, "trap_manager=", 13)) {
			set_value(token, rserver->trap_manager);
		} else if (!strncasecmp(token, "trap_v3_engineid=", 18)) {
			set_value(token, rserver->trap_v3_engineid);
		} else if (!strncasecmp(token, "trap_v3_username=", 18)) {
			set_value(token, rserver->trap_v3_username);
		} else if (!strncasecmp(token, "trap_v3_password=", 18)) {
			set_value(token, rserver->trap_v3_password);
		} else if (!strncasecmp(token, "trap_v3_privacy_protocol=", 24)) {
			set_value(token, rserver->trap_v3_privacy_protocol);
		} else if (!strncasecmp(token, "trap_v3_privacy_password=", 24)) {
			set_value(token, rserver->trap_v3_privacy_password);
		} else if (!strncasecmp(token, "username=", 9)) {
			set_value(token, rserver->username);
		} else if (!strncasecmp(token, "password=", 9)) {
			set_value(token, rserver->password);
#endif
		}

		token = strtok(NULL, ",");
	}

	/** maxreq maxconn bandwidth check **/
	{
		int i;
		for (i = 0; i < strlen(rserver->maxconn); i++) {
			if (isalpha(rserver->maxconn[i])) {
				return -EINVAL;
			}
		}
		for (i = 0; i < strlen(rserver->maxreq); i++) {
			if (isalpha(rserver->maxreq[i])) {
				return -EINVAL;
			}
		}
		for (i = 0; i < strlen(rserver->bandwidth); i++) {
			if (isalpha(rserver->bandwidth[i])) {
				return -EINVAL;
			}
		}
	}

	return 0;
}


static int apppool_set(struct list_head *list, const char *name,
		const char *attr, const char *value)
{
	struct rserver *rs, *tmp;
	struct apppool *apppool = list_entry(list, struct apppool, list);
	struct rserver *rserver = NULL;
	struct apppool *pool = NULL;

	if (name[0] == 0) {
		return -EINVAL;
	}

	if (apppool->name[0] == 0) {
		LIST_HEAD(queue);

		m_set_common(apppool, name, "name", name);

		module_get_queue(&queue, "healthcheck", "ping");
		if (!list_empty(&queue)) {
			strcpy(apppool->healthcheck, "ping");
		}
		module_purge_queue(&queue, "healthcheck");
	}

	if (strcmp(attr, "ipv6") == 0) {
		strcpy(apppool->type, "ipv6");
	} else if (strcmp(attr, "ipv4") == 0) {
		strcpy(apppool->type, "ipv4");
	} else if (apppool->type[0] == 0) {
		strcpy(apppool->type, "ipv4");
	}

	if (strcmp(attr, "vmtype") == 0) {
		if (strcmp(value,"vmware") == 0) {
			/** 清空rserver uuid **/
			list_for_each_entry(rs, &apppool->realserver_head, list) {
				memset(rs->uuid, 0, sizeof(rs->uuid));
			}
		} else if (strcmp(value, "xen")==0) {
			/** 清空rserver vmxpath **/
			list_for_each_entry(rs, &apppool->realserver_head, list) {
				memset(rs->vmxpath, 0, sizeof(rs->uuid));
			}
		} else if (strcmp(value, "vcenter") == 0) {
			/** 清空uuid 和 vmxpath **/
			list_for_each_entry(rs, &apppool->realserver_head, list) {
				memset(rs->vmxpath, 0, sizeof(rs->vmxpath));
				memset(rs->uuid, 0, sizeof(rs->uuid));
			}
		} else {
			/** 清空rserver uuid和vmxpath **/
			list_for_each_entry(rs, &apppool->realserver_head, list) {
				memset(rs->vmxpath, 0, sizeof(rs->vmxpath));
				memset(rs->uuid, 0, sizeof(rs->uuid));
			}
		}
	}

	if (!strcmp(attr, "healthcheck")) {
		LIST_HEAD(queue);
		module_get_queue(&queue, "apppool", name);
		list_for_each_entry(pool, &queue, list) {
			list_for_each_entry(rserver, &pool->realserver_head, list) {
				char ip[STR_IP_LEN] = {'\0'};
				char port[STR_PORT_LEN] = {'\0'};
				inet_sockaddr2ipport(&rserver->address, ip, port);
				if (atoi(port) == 0) {
					if (strcmp(value, "ping") != 0 
							&& strcmp(value, "pinggw") != 0)
						return -EINVAL;
				}
			}
		}
		module_purge_queue(&queue, "apppool");
	}

	m_set_common(apppool, healthcheck, attr, value);
	m_set_common(apppool, vmtype, attr, value);
	m_set_common(apppool, vmenable, attr, value);
	m_set_common(apppool, vmaddress, attr, value);
	m_set_common(apppool, vmusername, attr, value);
	m_set_common(apppool, vmpassword, attr, value);
	m_set_common(apppool, vminterval, attr, value);
	m_set_common(apppool, vmcount, attr, value);
	m_set_common(apppool, vmvcenter, attr, value);
	m_set_common(apppool, vmhost, attr, value);
	m_set_common(apppool, vmdatacenter, attr, value);
	m_set_common(apppool, vmport, attr, value);
	m_set_common(apppool, alive_vm, attr, value);
	
	if(strcmp(attr, "vmenable") == 0) {
		
		if(strcmp(value, "on") == 0){
			strcpy(apppool->vminterval, "5");
			strcpy(apppool->vmcount, "20");
		}else{
			apppool->vminterval[0] = 0;
			apppool->vmcount[0] = 0;
		}
	}

	if (strcmp(attr, "vmvcenter") == 0 ||
			strcmp(attr, "vmdatacenter") == 0 ||
			strcmp(attr, "vmport") == 0 || 
			apppool->vmdatacenter[0] == 0) {

		if (strcmp(attr, "vmvcenter") == 0 ) {
			memset(apppool->vmdatacenter, 0, sizeof(apppool->vmdatacenter));
			memset(apppool->vmport, 0, sizeof(apppool->vmport));
		}
	}

	/* used for vcenter: add vm to apppool */
	if (strcmp(apppool->vmtype, "vcenter") == 0	&& 
			apppool->vmvcenter[0] != 0	&&
			apppool->vmdatacenter[0] != 0		&&
			apppool->vmport[0] != 0 ) {

		/* generate realserver */
		struct vcenter_datacenter *datacenter;
		struct vcenter *vcenter;
		struct vcenter_vm *vm;
		struct list_head *list;
		struct rserver *rs;

		/* clear old realserser */
		list_for_each_entry_safe(rs, tmp, &apppool->realserver_head, list) {
			list_del(&rs->list);
			realserver_free(&rs->list);
		}

		/* get vcenter */
		LIST_HEAD(vcenter_head);
		module_get_queue(&vcenter_head, "vcenter", apppool->vmvcenter);
	
		list_for_each_entry(vcenter, &vcenter_head, list) {
			list_for_each_entry(datacenter, &vcenter->datacenter_head, list) {
				/* find datacenter */
				if (strcmp(datacenter->name, apppool->vmdatacenter) != 0) {
					continue;
				}
				
				list_for_each_entry(vm, &datacenter->vm_head, list) {
					/* name , address, state */
					if ((list  = realserver_malloc()) == NULL) {
						continue;
					}
					if ((rs = list_entry(list, struct rserver, list)) == NULL) {
						continue;
					}

					/* IP address not exist or vm->state != "poweredOn", continue */
					if (strcmp(vm->address, "Not Known") == 0 ||
							strcmp(vm->state, "poweredOn")!=0 ) {
						continue;
					}

					char address[512] = {0};
					sprintf(address, "%s:%d", vm->address, atoi(apppool->vmport));
					inet_address2sockaddr(address, &rs->address);

					strcpy(rs->vmname, vm->name);
					if (strcmp(vm->state, "poweredOn") == 0 ) {
						strcpy(rs->vmstate, "on");
					} else if (strcmp(vm->state, "poweredOff") == 0) {
						strcpy(rs->vmstate, "down");
					} else {
						strcpy(rs->vmstate, "unknown");
					}

					strcpy(rs->weight, "10");
					strcpy(rs->enable, "on");
					strcpy(rs->state, "unknown");
					strcpy(rs->snmp_version, "3");
					list_add_tail(list, &apppool->realserver_head);
				}
				break;
			}
		}
		module_purge_queue(&vcenter_head, "vcenter");
	}


	return 0;
}

static struct list_head *apppool_get_children_queue(struct list_head *list,
		const char *name)
{
	struct apppool *apppool = list_entry(list, struct apppool, list);
	if (strcmp(name, "realserver") == 0) {
		return &apppool->realserver_head;
	}
	return NULL;
}


/**
 * 返回值:
 *	1:	busy
 *	0:	non-busy
 **/
static int apppool_is_busy(struct apppool *pool)
{
	int ret = 1;
	LIST_HEAD(queue);
	struct vserver *vserver;
	struct rule_name *rule_name;
	struct rule *rule;
	char *ptr, *end;
	char buff[4096], poolname[4096], pool_encode[4096];

	/** 删除时检查是否被使用 **/
	module_get_queue(&queue, "vserver", NULL);

	list_for_each_entry(vserver, &queue, list) {
		if (!strcmp(vserver->contentswitch, "on")) {
			list_for_each_entry(rule_name, &vserver->rule_head, list) {
				memset(buff, 0, sizeof(buff));
				memset(poolname, 0, sizeof(poolname));
				memset(pool_encode, 0, sizeof(pool_encode));

				LIST_HEAD(head);
				module_get_queue(&head, "rule", rule_name->name);
				rule = list_first_entry(&head, struct rule, list);

				base64_decode((uint8_t *)buff, rule->statements, 4095);

				if ((ptr = strstr(buff, "http.request.reroute")) != NULL) {
					if (((ptr = strchr(ptr, '"')) != NULL) && ((end = strchr(ptr+1, '"')) != NULL)
							&& (end-ptr>1)) { 
						strncpy(poolname , ptr+1, end-ptr-2);
						poolname[end-ptr-2] = '\0';
						if (!strcmp(poolname, pool->name)) {
							module_purge_queue(&head, "rule");
							goto end;
						}
					}
				}
				module_purge_queue(&head, "rule");
			}
		} else if (strcmp(vserver->pool, pool->name) == 0 ||
				strcmp(vserver->backpool, pool->name) == 0) {
			goto end;
		}
	}
	ret = 0;
end:
	module_purge_queue(&queue, "vserver");
	return ret;
}

static int apppool_execute(struct list_head *list,
		struct list_head *useless, int op)
{
	struct apppool *apppool = list_entry(list, struct apppool, list);
	LIST_HEAD(queue);

	if ( op != MODULE_OP_DEL) {
		if (!apool_set_vm_enable_valid(apppool)) {
			return -EINVAL;
		}
	}

	if (op == MODULE_OP_ADD || op == MODULE_OP_SET_ADD) {
		return 0;
	}

	if (apppool_is_busy(apppool) == 0) {
		pool_delete_rserver_bandwidth(apppool);
	} else {
		return -EBUSY;
	}

	return 0;
}

static int realserver_execute(struct list_head *list,
		struct list_head *rs_list, int op)
{
	struct apppool *apppool = list_entry(list, struct apppool, list);

	struct rserver *rs = list_entry(rs_list, struct rserver, list);

	if (op == MODULE_OP_DEL || op == MODULE_OP_SET_DEL) {
		char address[BUFSIZ] = {};

		rserver_set_bandwidth(rs, MODULE_OP_DEL);

		inet_sockaddr2address(&rs->address, address);
		if (apppool_is_busy(apppool)) {
			if (strcmp(rs->state, "up") != 0
					&& strcmp(rs->state, "unknown") != 0) {
				return 0;
			}

			strcpy(rs->state, "draining");

			if (op == MODULE_OP_DEL) {
				strcpy(rs->enable, "off");
			}
			return -EBUSY;
		}
	} else if (op == MODULE_OP_ADD || op == MODULE_OP_SET_ADD) {
		char ipaddr[512]={0}, port[512]={0};
		char address[BUFSIZ] = {};

		inet_sockaddr2address(&rs->address, address);
		/** 检查是否会造成IP地址的死循环 **/
		if (check_apppool_address_loops(apppool->name, address) != 0) {
			return -EINVAL;
		}
		/** 是否设置了网关 **/
		if (check_routable_gateway() == 0)
			goto ok;

		if (inet_sockaddr2ipport(&rs->address, ipaddr, port) != 0) {
			return -1;
		}

		if (check_ip_version(ipaddr) == IPV4 && strcmp(apppool->type, "ipv4") != 0) {
			return -EINVAL;
		} else if (check_ip_version(ipaddr) == IPV6 && strcmp(apppool->type, "ipv6") != 0) {
			return -EINVAL;
		}

		if (check_ip_version(ipaddr) == IPV4) {

			/** 是否设置了网关 **/
			if (check_routable_gateway() == 0)
				goto ok;

			/** 是否路由可达 **/
			if (check_routable_address(ipaddr, NULL) == 0)
				goto ok;

			/** 没有设置网关且路由不可达 **/
			return -ENETUNREACH;
		}
ok:
		rserver_set_bandwidth(rs, MODULE_OP_ADD);
	}

	return 0;
}


/* apppool deep copy */
struct apppool * apppool_copy(const struct apppool *src,  struct apppool **dst)
{
	struct list_head *list;
	struct rserver *rs, *rstmp;

	if ((list = apppool_malloc()) == NULL) {
		return NULL;
	}

	*dst = list_entry(list, struct apppool, list);
	memcpy(*dst, src, sizeof(struct apppool));
	INIT_LIST_HEAD(&((*dst)->realserver_head));

	/* realserver copy */
	list_for_each_entry(rs, &src->realserver_head, list) {
		if ((list = realserver_malloc()) == NULL) {
			continue;
		}
		rstmp = list_entry(list, struct rserver, list);
		memcpy(rstmp, rs, sizeof(struct rserver));
		INIT_LIST_HEAD(&rstmp->list);
		list_add_tail(&rstmp->list, &((*dst)->realserver_head));
	}

	return *dst;
}

static struct module apppool_module = {
	.m_root = "loadbalance",
	.m_desc = "apppool",
	.m_malloc = apppool_malloc,
	.m_free = apppool_free,
	.m_analyse = apppool_analyse,
	.m_restore = apppool_restore,
	.m_compare = apppool_compare,
	.m_set = apppool_set,
	.m_execute = apppool_execute,
	.m_get_children_queue = apppool_get_children_queue,
	.m_should_sort = "true",
};

static struct module realserver_module = {
	.m_desc = "realserver",
	.m_malloc = realserver_malloc,
	.m_free = realserver_free,
	.m_analyse = realserver_analyse,
	.m_restore = realserver_restore,
	.m_compare = realserver_compare,
	.m_execute = realserver_execute,
	.m_set = realserver_set,
	.m_should_sort = "true",
};

extern int module_init_apppool(void)
{
	module_register(NULL, &apppool_module);
	module_register(&apppool_module, &realserver_module);
	return 0;
}
