#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <fcntl.h>


#include "logger.h"
#include "analyzer.h"
#include "generator.h"
#include "layer7.h"
#include "hbsched.h"
#include "snmpsched.h"
#include "mailsched.h"
#include "license/license.h"
#include "common/common.h"
#include "common/module.h"
#include "common/logger.h"
#include "certificate/certcomm.h"
#include "common/config_apache.h"
#include "loadbalance/vserver.h"
#include "network/network.h"
#include "common/task.h"
#include "common/list.h"
#include "loadbalance/apppool.h"
#include "loadbalance/snmpwalk.h"
#include "common/base64.h"

#include "smartlog.h"

#include "interface_log.h"
#include "event_log.h"
#include "gslb.h"
#include "llb.h"
#include "daemon4.h"

#include <syslog.h>

static struct daemon4_config daemon4_config = {
	.epollfd 	= -1,
	.verbose	= 0,
	.client_ssl_ctx	= NULL,
	.event_head	= LIST_HEAD_INIT(daemon4_config.event_head),
};

struct daemon4_config * daemon4_config_get(void)
{
	return &daemon4_config;
}

#if 1
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
#if 1
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

	return 0;
err:
	return -1;
}

static pid_t snmpwalk_pid = 0;

/**
 * 对realserver进行修改操作
 **/
static int do_realserver_config_modify(char *poolname, struct rserver *rserver)
{
	struct apppool *pool;
	char buff[BUFSIZ];

	char address[BUFSIZ];
	inet_sockaddr2address(&rserver->address, address);
	sprintf(buff, "%s",address);

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

#undef RSERVER_SET_VALUE
	module_purge_queue(&pool_head, "apppool");

	/**
	 * XXX : immetiately call function
	 * add_realserver_to_apppool in smartcomm
	 **/
	add_realserver_to_apppool(poolname, buff);

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

static int snmpwalk_flush_vserver(void)
{

	struct list_head head = LIST_HEAD_INIT(head);
	pid_t pid;
	/* set ignore signal child, for do not zombie proccess */
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		syslog(LOG_INFO, "set child signal error:%s %s %s %d\n",
				strerror(errno), __FILE__, __func__, __LINE__);
		return -1;
	} 

	/* check snmpwalk child, if exists util else fork */
	char procfile[sizeof("/proc/4294967295/status")];
	sprintf(procfile, "/proc/%d/status", snmpwalk_pid);
	if (access(procfile, F_OK) == 0) {
		goto util;
	} else {
		snmpwalk_pid = 0;
	}

	if ((pid = fork()) < 0) {
	/** error **/
		syslog(LOG_INFO, "fork error :%s %s %s %d\n",
				strerror(errno), __FILE__, __func__, __LINE__);
		snmpwalk_pid = 0;
		return -1;
	} else if (0 == pid) {
	/** child proccess **/
		/* get cpu and mem result */
		snmpwalk_get_data(&head);

		/* save result to xml file */
		snmpwalk_nodes_save(&head);

		/* free node list */
		destroy_nodes(&head);
		exit(EXIT_SUCCESS);
	} else {
	/** perent proccess **/
		snmpwalk_pid = pid;
	}
util:
	return 0;
}
#endif

static void callback_connection(int epfd, int fd, struct event *e)
{
	char buf[BUFSIZ];
	int  len;

	memset(buf, '\0', sizeof(buf));
	if ((len = read(fd, buf, sizeof(buf))) <= 0)
		goto out;

	if (analyzer_entrance(buf, e) > 0) {
		generator_entrance(e);
		/** informer_entrance 该函数被挪到了
		generator_entrance中调用, * * by anhk, 2012-03-19 **/
		//informer_entrance();
	}
#if 1
	snmpwalk_flush_vserver();
#endif


out:
	if (e->stolen == 0)
		event_destroy(epfd, fd, e);
	return;
}

static int fd_cloexec(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFD, 0)) == -1)
		return -1;

	return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/*
 * callback_listen: listen callback function
 * @e: connection event
 */
static void callback_listen(int epfd, int fd, struct event *e)
{
	struct event *tmp;
	int connfd;

	if ((connfd = accept(fd, NULL, NULL)) == -1) {
		err("accept");
		goto out;
	}

	fd_cloexec(connfd);

	/* event_set: allocate event memory */
	tmp = event_set(epfd, connfd, EPOLLIN, callback_connection);
	if (tmp == NULL) {
		perror("event_set");
		goto err;
	}

	if (event_add(tmp) == -1) {
		perror("event_add");
		goto err1;
	}
	return;
err1:
	free(tmp);
err:
	close(connfd);
out:
	return;
}

static int rlimit_setup(int resource, int size)
{
	struct rlimit rlim;

	getrlimit(resource, &rlim);
	rlim.rlim_cur = size;
	rlim.rlim_max = size;
	setrlimit(resource, &rlim);
	return 0;
}

static int daemon4_event_flush(void)
{
	struct daemon4_config *config = daemon4_config_get();
	struct event *ep = NULL, *enxt = NULL;
	time_t now = time(NULL);

	list_for_each_entry_safe(ep, enxt, &config->event_head, node) {
		if (now > ep->expires) {
			list_del_init(&ep->node);

			write_return_status(ep->owner->event_fd, SMARTGRID_SYNC_GROUP_ERROR);
			event_destroy(ep->owner->event_epfd, ep->owner->event_fd, ep->owner);
			event_destroy(ep->event_epfd, ep->event_fd, ep);
		}
	}

	return 0;
}

static int system_default_topology_build(void)
{
	if (access(GSLB_TOPOLOGY_CONFIG_FILE, F_OK) == -1) {
		system("cp -a " SYSTEM_DEFAULT_TOPOLOGY_CONFIG_FILE " " GSLB_TOPOLOGY_CONFIG_FILE);
		system_default_topology_format();
		system_default_topology_policy_build();
	}

	return 0;
}

static int childrunning(void)
{	
	struct daemon4_config *config = daemon4_config_get();
	int epoll_fd;
	int listen_fd;
	struct event *e;
	time_t last_time = 0;
	time_t last_time_compare_config = 0;
	char address[BUFSIZ];
	memset(address, 0, sizeof(address));

	/*signal(SIGSEGV, sig_segv);*/

	/* chmod 0777 /var/tmp/unix_daemon.sock */
	umask(0);
	chmod(UNIXDAEMON, 0777);
	rlimit_setup(RLIMIT_STACK, (1 << 20) * 100);	/* 100M */

	/** 加载smartcommon库 **/
	init_libcomm();

	// add by Fanyunfei @2013-08-19
	system_default_topology_build();

	/** hb vip **/
	//hb_vip_merge();

	/** 启动apache **/
	unconfig_apache();
	config_apache(0,0);

	snmp_enable_on(NULL);

	get_local_ip(address, sizeof(address));
	record_admin_log( address, "系统启动",SMARTLOG_SYSTEM_START);
	if ((epoll_fd = event_init()) < 0)
		goto err;

	// add by Fanyunfei @2013-07-04
	config->epollfd 	= epoll_fd;
	config->client_ssl_ctx	= SSL_CTX_new(SSLv23_client_method());

	if ((listen_fd = tcp_unix_listen(UNIXDAEMON)) == -1)
		goto err1;

	e = event_set(epoll_fd, listen_fd, EPOLLIN, callback_listen);
	if (e == NULL) {
		perror("event_set");
		goto err2;
	}

	if (event_add(e) == -1) {
		perror("event_add");
		goto err3;
	}

	hb_start(e);

	last_time_compare_config = last_time = time(NULL);
	for (;;) {
		// prevent system date change to previous, add by fanyf
		if (time(NULL) < last_time)
			last_time_compare_config = last_time = time(NULL);

		event_dispatch_loop(epoll_fd);

		if (time(NULL) - last_time >= 30 /** 30 seconds **/) {
			snmpsmtp_alert_probing();
			last_time = time(NULL);
		}

		if (time(NULL) - last_time_compare_config >= 3) {
			vserver_flush_state();		// SLB vserver state flush
	
			// Add by Fanyunfei @2013-06-19
			gslb_vserver_flush_state();	// GSLB vserver state flush

			// Add by Fanyunfei @2013-07-10
			llb_vserver_flush_state();
			

			generator_entrance(NULL);
			last_time_compare_config = time(NULL);
			hb_probe(e);
			do_task_loops();
		}

		daemon4_event_flush();			// add by Fanyunfei @2013-07-19
	}
	return 0;
err3:
	free(e);
err2:
	close(listen_fd);
err1:
	close(epoll_fd);
err:
	return -1;
}


#define NDAEMON

__attribute__((unused)) static void signal_chld(int signo);

static void start_child_process(void)
{
	struct daemon4_config *config = daemon4_config_get();

	if (config->verbose == 0) {
		#ifdef NDAEMON 
			pid_t pid;

			signal_handler(SIGCHLD, signal_chld);

			pid = fork();
			if (pid == -1) {
				err("fork");
				return;
			} else if (pid == 0) {
		#endif
				signal_handler(SIGCHLD, SIG_DFL);
				childrunning();		/* child */
		#ifdef NDAEMON
			}
		#endif
	} else {	// debug mode
		printf("daemon4 running in debug mode.\n");

		signal_handler(SIGCHLD, SIG_DFL);
		childrunning();		/* child */
	}
}

__attribute__((unused)) static void signal_chld(int signo)
{
	waitpid(-1, NULL, 0);
	start_child_process();
}

static int process_initial(int argc, char *argv[])
{
	struct daemon4_config *config = daemon4_config_get();
	
	if (config->verbose == 0) {
		#ifdef NDAEMON
			daemon(1, 1);
		#endif
	}


	/* daemon */
	if (lock_file("/var/run/daemon4.pid") == -1) {
		fprintf(stderr, "Message: %s is already running.\n", argv[0]);
		goto out;
	}
	signal_handler(SIGPIPE, SIG_IGN);

	system("echo 1 >/proc/sys/net/ipv4/conf/all/promote_secondaries");
	system("echo 1 >/proc/sys/net/ipv4/ip_nonlocal_bind");
	system("echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse");
	system("echo 1 >/proc/sys/net/ipv4/tcp_tw_recycle");
	system("echo 1 >/proc/sys/net/ipv4/ip_forward");
	system("echo 1024 65535 >/proc/sys/net/ipv4/ip_local_port_range");
	system("echo 0 >/proc/sys/net/ipv4/tcp_timestamps");
	system("echo 4194304 > /proc/sys/net/netfilter/nf_conntrack_max");
	system("echo 4194304 > /proc/sys/net/nf_conntrack_max");
	system("echo 8192 > /proc/sys/net/ipv4/tcp_max_syn_backlog");

	if (access("/usr/bin/ip", F_OK) != 0) {
		system("ln -s /sbin/ip /usr/bin/ip");
	}

	if (mgmt_exists()) {
		system("echo 0 > /proc/sys/net/ipv6/conf/mgmt/dad_transmits");
	}

	system("chmod 0666 /dev/null");
	system("chmod 0777 /var/run");

	if (access("/SmartGrid/config/userconfig", F_OK) != 0) {
		system("mkdir -p /SmartGrid/config/userconfig");
	}
	system("chown daemon:daemon /SmartGrid/config/userconfig");
	system("chmod a+s /sbin/sysctl && ln -s /sbin/sysctl /usr/bin/sysctl 2>/dev/null");

#define SYSLOG "/var/log/messages"
	chmod(SYSLOG, 0666); 

	if (access(CONFIG_ORIG_FILE, F_OK) == 0 && access(CONFIG_FILE, F_OK) != 0) {
		system("cp -af "CONFIG_ORIG_FILE" "CONFIG_FILE);
	}


	/** SSL Init **/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	return 0;
out:
	return -1;
}




#ifndef VERSION
#define VERSION "undefined"
#endif

int main(int argc, char **argv)
{
	struct daemon4_config *config = daemon4_config_get();
	int t;

	/* log4c init */
	SMT_LOG_INIT();

	while ((t = getopt(argc, argv, "dv")) != -1) {
		switch(t) {
			case 'v':
				printf("VERSION: %s\n", VERSION);
				exit(0);
			case 'd':
				config->verbose = 1;
				break;
			default:
				break;
		}
	}

	if (process_initial(argc, argv) == -1)
		goto out;

	ulog_init("/SmartGrid/shell");

	/* follow is child process */
	start_child_process();

	for (;;)
		sleep(10);

	ulog_fini();

	/* log4c fini */
	SMT_LOG_FINI();

	return 0;
out:
	return -1;
}
