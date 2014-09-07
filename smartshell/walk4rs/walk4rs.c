#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/epoll.h>


#include "common/module.h"
#include "common/logger.h"
#include "loadbalance/vserver.h"
#include "common/list.h"
#include "loadbalance/apppool.h"
#include "loadbalance/snmpwalk.h"
#include "common/base64.h"
#include "smartlog.h"
#include "walk4rs.h"
#include "common/common.h"
#include "loadbalance/walk4iptables.h"

#include <syslog.h>

struct appnode {
	/* apppool name */
	char appname[64];
	/* link other appnode */
	struct list_head list;
	/* add child linker rsnode */
	struct list_head child_list;
};

struct rsnode {
	/* link prent appnode */
	struct list_head list;
	/* ip address of real server */
	char ip[INET6_ADDRSTRLEN];
	int pfd[2];
	char weight[4];
};

static int check_pool_uniq(struct vserver *vserver, struct list_head *head)
{
	struct appnode *tmpnode;
	list_for_each_entry(tmpnode, head, list) {
		/* repaet not add */
		if (memcmp(vserver->pool, tmpnode->appname, strlen(tmpnode->appname) + 1) == 0) {
			/* failrue return -1, call function coutinue current */
			return -1;
		}
	}
	/* success return 0, call function go on */
	return 0;
}

static int check_rserver_uniq(char *ip, struct list_head *head)
{
	struct rsnode *tmpnode;
	list_for_each_entry(tmpnode, head, list) {
		/* repaet not add */
		if (memcmp(ip, tmpnode->ip, strlen(tmpnode->ip) + 1) == 0) {
			/* failrue return -1, call function coutinue current */
			return -1;
		}
	}
	/* success return 0, call function go on */
	return 0;
}

/**
 * copy name of apppool into appnode, and appnode add list
 * vserver.pool-->appnode(init)-->list(head.list)
 **/
static struct appnode*
apppoll_appnode_list(struct vserver *vserver, struct list_head *head)
{
	struct appnode *appnode;
	appnode = malloc(sizeof(*appnode));
	if (NULL == appnode) {
		syslog(LOG_INFO, "malloc failure %s: %s, %s %d\n",
				strerror(errno), __FILE__, __func__, __LINE__);
		goto err;
	}

	memcpy(appnode->appname, vserver->pool, strlen(vserver->pool) + 1);
	INIT_LIST_HEAD(&appnode->list);
	INIT_LIST_HEAD(&appnode->child_list);

	list_add(&appnode->list, head);
err:
	return appnode;

}

/**
 * copy ip of real server into rsnode.ip, and rsnode add list
 * ip(real server)-->rsnode.ip-->appnode(head.list->appnode.child_list)
 **/
struct rsnode*
rsip_rsnode_list(char *ip, struct appnode *appnode)
{
	struct rsnode *rsnode;
	rsnode = malloc(sizeof(*rsnode));
	if (NULL == rsnode) {
		syslog(LOG_INFO, "malloc failure %s:%s, %s %d\n",
				strerror(errno), __FILE__, __func__, __LINE__);
		goto err;
	}
	memcpy(rsnode->ip, ip, strlen(ip) + 1);
	INIT_LIST_HEAD(&rsnode->list);
	list_add(&rsnode->list, &appnode->child_list);
err:
	return rsnode;
}

static void destroy_nodes(struct list_head *head)
{
	struct appnode *appnode, *backupapp;
	struct rsnode *rsnode, *backuprs;

	list_for_each_entry_safe(appnode, backupapp, head, list) {
		list_for_each_entry_safe(rsnode, backuprs, &appnode->child_list, list) {
			list_del(&rsnode->list);
			free(rsnode);
		}
		list_del(&appnode->list);
		free(appnode);
	}
	return;
}

static struct rsnode*
search_list_by_fd(int fd, struct list_head *head)
{
	struct appnode *appnode;
	struct rsnode *rsnode;
	list_for_each_entry(appnode, head, list) {
		list_for_each_entry(rsnode, &appnode->child_list, list) {
			if (rsnode->pfd[0] == fd)
				return rsnode;
		}
	}
	return NULL;
}

static int snmpwalk_get_data(struct list_head *head)
{
	struct vserver *vserver;
	struct apppool *apppool;
	struct rserver *rserver;
	struct appnode *appnode;
	struct rsnode *rsnode;
	char address[INET6_ADDRSTRLEN + 1 + 5 + 1] = {0};
	char ip[INET6_ADDRSTRLEN] = {0};
	pid_t pid;
	int fdnum = 0, fdn;
	/* epoll create */
	int epfd;
	/* set all fd check readable */
	struct epoll_event tmpevt = {.events = EPOLLIN};
	epfd = epoll_create(1024);
	if (epfd < 0) {
		syslog(LOG_INFO, "epoll create %s %s %s %d\n",
				strerror(errno), __FILE__, __func__, __LINE__);
		goto err;
	}

	LIST_HEAD(pool_queue);
	LIST_HEAD(queue);

	module_get_queue(&queue, "vserver", NULL);

	list_for_each_entry(vserver, &queue, list) {

		if (strlen(vserver->pool) == 0
#define NDEBUG	1
#if NDEBUG
			|| memcmp(vserver->alive_state, "up", sizeof("up")) != 0
#endif
			|| memcmp(vserver->sched, "snmp", sizeof("snmp")) != 0) {
			continue;
		}

		/** jump repeat pool of vserver **/
		if (check_pool_uniq(vserver, head) < 0)
			continue;

		/** vserver.pool-->appnode(init)-->list(head.list) **/
		if ((appnode = apppoll_appnode_list(vserver, head)) == NULL)
			goto err;

		/** get apppool used snmp **/
		module_get_queue(&pool_queue, "apppool", vserver->pool);
		apppool = list_entry(pool_queue.next, struct apppool, list);

		/** check apppool rserver empty **/
		if (list_empty(&apppool->realserver_head)) {
			continue;
		}
		/** get each address(ip:port) of apppool **/
		list_for_each_entry(rserver, &apppool->realserver_head, list) {

			/** util close snmp enable **/
			if (memcmp(rserver->snmp_enable, "on", sizeof("on")) != 0) {
				continue;
			}

			/** get ip of real server **/
			if (inet_sockaddr2address(&rserver->address, address) != 0) {
				continue;
			}
			get_ip_port(address, ip, NULL);
			/** jump repeat ip of real server, eg ip:prot(1-n) **/
			if (check_rserver_uniq(ip, &appnode->child_list) < 0) {
				continue;
			}

			if ((rsnode = rsip_rsnode_list(ip, appnode)) == NULL) {
				goto err;
			}

			if (pipe(rsnode->pfd) < 0) {
				syslog(LOG_INFO, "pipe failure :%s %s %s %d\n",
						strerror(errno), __FILE__, __func__, __LINE__);
				goto err;
			}

			if ((pid = fork()) < 0) {
			/** fork error **/
				syslog(LOG_INFO, "create proccess failure:%s %s %s %d\n",
						strerror(errno), __FILE__, __func__, __LINE__);
			} else if (pid == 0) {
			/** child proccess **/
				/* snmpwalk real server */
				int ret;
				close(rsnode->pfd[0]);
				ret = check_snmp(rserver, SNMP_HIDE);
				write(rsnode->pfd[1], &ret, sizeof(ret));
				close(rsnode->pfd[1]);
				destroy_nodes(head);
				close(epfd);
				exit(EXIT_SUCCESS);
			} else {
			/** perent proccess **/
				/** epoll set read **/
				close(rsnode->pfd[1]);
				setnonblocking(rsnode->pfd[0]);
				fdnum++;
				tmpevt.data.fd = rsnode->pfd[0];
				epoll_ctl(epfd, EPOLL_CTL_ADD, rsnode->pfd[0], &tmpevt);
			}
		}

		module_purge_queue(&pool_queue, "apppool");

		/**
		 * whenever not exits ip address of apppool,
		 * and delele current apppool node
		 **/
		if (list_empty(&appnode->child_list)) {
			list_del(&appnode->list);
			free(appnode);
			appnode = NULL;
		}
	}

	module_purge_queue(&queue, "vserver");

	{	
		struct epoll_event fdes[fdnum];
		int fdmax = fdnum;
		int n, ret, i;
		for ( ; fdmax; ) {
			fdn = epoll_wait(epfd, fdes, fdnum, 1000 * 10);
			for (i = 0; i < fdn; i++) {
				if ((n = read(fdes[i].data.fd, &ret, sizeof(ret))) > 0) {
				/* snmpwalk check return data */
					if ((rsnode = search_list_by_fd(fdes[i].data.fd, head)) == NULL) {
						syslog(LOG_INFO, "search file descriptor error\n");
					} else {
						sprintf(rsnode->weight, "%d", ret);
					}
				} else if (n == 0) {
				/* peel close */
					if ((rsnode = search_list_by_fd(fdes[i].data.fd, head)) == NULL) {
						syslog(LOG_INFO, "search file descriptor error\n");
					} else {
						rsnode->pfd[0] = -1;
					}
					epoll_ctl(epfd, EPOLL_CTL_DEL,fdes[i].data.fd, &fdes[i]);
					close(fdes[i].data.fd);
					fdmax--;
				} else {
				/* read error */
					syslog(LOG_INFO, "epoll read error :%s %s %s %d\n",
							strerror(errno), __FILE__, __func__, __LINE__);
				}
			}
		}
	}
	close(epfd);

	return 0;
err:
	return -1;
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

	/* get pool */
	LIST_HEAD(pool_head);
	module_get_queue(&pool_head, "apppool", poolname);
	if (list_empty(&pool_head)) {
		return -1;
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
	module_purge_queue(&pool_head, "apppool");

#undef RSERVER_SET_VALUE
	fp = popen(buff, "r");
	if (fp == NULL) {
		fprintf(stderr, "Internal Error.\r\n");
		return -1;
	}
	while (fgets(buff, BUFSIZ, fp) != NULL) {
		printf("%s\n", buff);
		if (!strcmp(buff, "EINVAL")) {
			fprintf(stdout, "healthcheck error!\n");
		}
	}
	pclose(fp);


	return 0;
}

static void snmpwalk_nodes_save(struct list_head *head)
{
	struct appnode *appnode;
	struct rsnode *rsnode;

	struct apppool *apppool;
	struct rserver *rserver;

	LIST_HEAD(pool_queue);

	char address[INET6_ADDRSTRLEN + 1 + 5 + 1] = {0};
	char ip[INET6_ADDRSTRLEN] = {0};

	/* traversal each appnode, get apppool name of snmp sched */
	list_for_each_entry(appnode, head, list) {

		module_get_queue(&pool_queue, "apppool", appnode->appname);
		if (list_empty(&pool_queue)) {
			continue;
		}
		/** get apppoop of rsnode->name **/
		apppool = list_entry(pool_queue.next, struct apppool, list);

		/** check apppool rserver empty **/
		if (list_empty(&apppool->realserver_head)) {
			continue;
		}

		/* traversal each rsnode, get ip of real server */
		list_for_each_entry(rsnode, &appnode->child_list, list) {
		/* assign all equal to ip, avoid oversight */

			/** get each address(ip:port) of apppool **/
			list_for_each_entry(rserver, &apppool->realserver_head, list) {

				/** util close snmp enable **/
				if (memcmp(rserver->snmp_enable, "on", sizeof("on")) != 0) {
					continue;
				}

				/** get ip of real server **/
				if (inet_sockaddr2address(&rserver->address, address) != 0) {
					continue;
				}
				get_ip_port(address, ip, NULL);
				if (memcmp(ip, rsnode->ip, strlen(rsnode->ip) + 1) != 0) {
					continue;
				}
				/** assign to rserver weight **/
				if (memcmp(rsnode->weight, "-1", sizeof("-1")) != 0) {
					memcpy(rserver->weight, rsnode->weight, strlen(rsnode->weight) + 1);
				} else {
					continue;
				}

				/*
				 * XXX : immetiataly copy do_realserver_config_modify
				 * and fix to used
				 */
				do_realserver_config_modify(apppool->name, rserver);
			}
		}
		module_purge_queue(&pool_queue, "apppool");
	}
	return;
}

int main(int argc, char *argv[])
{
	SMT_LOG_INIT();
	log_message("walk4rs start!");

#ifdef NDEBUG
	daemon(1, 1);
#endif
	if (lock_file("/var/run/walk4rs.pid") == -1) {
		fprintf(stderr, "Message: %s is already running.\n", argv[0]);
		goto out;
	}

	struct list_head head = LIST_HEAD_INIT(head);

	init_libcomm();

	signal_handler(SIGPIPE, SIG_IGN);
	signal_handler(SIGCHLD, SIG_IGN);
	iptables_snmpwalk_rs(NULL, 0);
	iptables_snmpwalk_rs(NULL, 1);

	int sleep_flag;
	while(1) {
		/* get cpu and mem result */
		snmpwalk_get_data(&head);

		sleep_flag = list_empty(&head);

		/* save result to xml file */
		snmpwalk_nodes_save(&head);

		/* free node list */
		destroy_nodes(&head);

		if (sleep_flag)
			usleep(1000 * 100);
	}
out:
	ulog_fini();

	log_message("walk4rs finish!");
	SMT_LOG_FINI();

	return 0;
}
