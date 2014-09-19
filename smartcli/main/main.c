#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#include <pwd.h>

#include "license/license.h"
#include "common/common.h"
#include "common/base64.h"
#include "check/check.h"
#include "libssl/libssl.h"
#include "libvs/libpool.h"
#include "libvs/libhealthcheck.h"
#include "libvs/librule.h"
#include "libvs/libvs.h"
#include "libcli/libcli.h"
#include "libnet/libdns.h"
#include "libnet/libntpdate.h"
#include "libnet/libnetwork.h"
#include "libnet/libfirewall.h"
#include "libnet/libdnat.h"
#include "libhb/libhb.h"
#include "libsnmp/libsnmp.h"
#include "libmail/libmail.h"
#include "libcli/str_desc.h"
#include "libsys/libsys.h"
#include "libcliusers/libcliusers.h"
#include "common/dependence.h"
#include "common/module.h"
#include "libvcenter/libvcenter.h"
#include "libgslb/gslb_liblistener.h"
#include "libgslb/gslb_libvserver.h"
#include "libgslb/gslb_libdevice.h"
#include "libgslb/gslb_libpool.h"
#include "libgslb/gslb_libgroup.h"
#include "libgslb/gslb_libbind9.h"
#include "libgslb/gslb_libtopology.h"

#include "libllb/llb_libvserver.h"
#include "libllb/llb_libpool.h"
#include "libllb/llb_libsnat.h"
#include "libsysconfig/libsysconfig.h"
#include "libvs/libwalkrs.h"

#define CLITEST_PORT                8000
#define MODE_CONFIG_INT             10
#define MODE_CONFIG_VSERVER         20
#define MODE_CONFIG_POOL            30

#ifdef __GNUC__
# define UNUSED(d) d __attribute__ ((unused))
#else
# define UNUSED(d) d
#endif

// TODO SUPERKEY add by fanyf
#define SUPERKEY "/var/tmp/__superkey__.txt"

static int check_enable(char *password)
{
	return cliusers_check_valid("system",password);
}


#ifndef VERSION
#define VERSION "V0.0.1T"
#endif


static int interfacebr_get_values(char *address, char *interface)
{
	struct vlan *vlan;
	struct ipaddr *ipaddr;
	LIST_HEAD(vlan_head);
	int ret = 0;
	module_get_queue(&vlan_head, "vlan", NULL);
	if (list_empty(&vlan_head)) {
		return -1;
	}

	list_for_each_entry(vlan, &vlan_head, list) {
		list_for_each_entry(ipaddr, &vlan->ipaddr_head, list) {
			char ip[STR_IP_LEN] = {0};
			inet_sockaddr2ip(&ipaddr->ipaddr, ip);
			if (check_subnet(ip, ipaddr->netmask,
						address, ipaddr->netmask)==0) {
				ret = 1;	
				goto out;
			}
		}
	}
out:
	if (ret){
		sprintf(interface, "br%s",vlan->vlanid);
	}
	module_purge_queue(&vlan_head, "vlan");
	return ret;
}

static int execute_cmd(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[512];
	if (strncmp(command, "sar", 3) == 0) {
		char cmd[16], args[16];
		sscanf(command, "%s %s", cmd, args);
		args[strlen(args)-1] = 0;
		sprintf(buff, "sar -n DEV %s 5", args);
	} else if (strncmp(command, "traceroute", strlen("traceroute")) == 0) {
		if (check_ip_version(argv[0]) == IPV4) {
			sprintf(buff, "traceroute %s", argv[0]);
		} else if (check_ip_version(argv[0]) == IPV6) {
			char interface[32] = {0};
			if (interfacebr_get_values(argv[0], interface)) {

				sprintf(buff, "traceroute6 -i %s %s", interface, argv[0]);
			}else {
				sprintf(buff, "traceroute6 %s", argv[0]);
			}
		}
	} else if (strncmp(command, "ping", strlen("ping")) == 0) {
		if (check_ip_version(argv[0]) == IPV4) {
			sprintf(buff, "ping -c 4 %s", argv[0]);
		} else if (check_ip_version(argv[0]) == IPV6) {
			char interface[32] = {0};
			if (interfacebr_get_values(argv[0], interface)) {
				sprintf(buff, "ping6 -I %s %s", interface, argv[0]);
			}else {
				sprintf(buff, "ping6 %s", argv[0]);
			}
		}
	} else if (strcmp(command, "netstat") == 0) {
		strcpy(buff, "netstat -an");
	} else if (strcmp(command, "netstat tcp") == 0) {
		strcpy(buff, "netstat -ant");
	} else if (strcmp(command, "netstat udp") == 0) {
		strcpy(buff, "netstat -anu");
	} else if (strcmp(command, "iostat") == 0) {
		strcpy(buff, "iostat -x -t");
	} else 
		return CLI_ERROR;
	system(buff);
	return CLI_OK;
}



static int  diagnosis_init_standard_cmd(struct cli_def *cli, struct cli_command *dia)
{
	struct cli_command *p;

	p = cli_register_command(cli, dia, "ping", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_PING);
	cli_command_add_argument(p, "<IP/Domain>", check_host);
	p = cli_register_command(cli, dia, "traceroute", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_TRACEROUTE);
	cli_command_add_argument(p, "<IP/Domain>", check_host);
	p = cli_register_command(cli, dia, "netstat", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_NETSTAT);

	cli_register_command(cli, p, "tcp", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_NETSTAT);

	cli_register_command(cli, p, "udp", execute_cmd, PRIVILEGE_UNPRIVILEGED,

			MODE_EXEC, LIBCLI_UNIX_NETSTAT);


	p = cli_register_command(cli, dia, "sar", NULL, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_SAR);

	cli_register_command(cli, p, "3s", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_SAR);

	cli_register_command(cli, p, "5s", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_SAR);

	cli_register_command(cli, p, "10s", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_SAR);

	cli_register_command(cli, dia, "iostat", execute_cmd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_UNIX_IOSTAT);

	return 0;
}

static int check_passwd_range(const char *pa)
{
	const char *p = pa;
	while(*p!=0){
		if( *p <32 || *p >126){
			return -1;
		}
		p++;
	}
	
	return 0;
}

static int cliusers_default(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[512]={0}, cmd[512]={0}, password1[128]={0}, password2[128]={0};
	FILE *fp;

	while(1){
		printf("New System PassWord: ");
		fgets(password1, sizeof(password1), stdin);

		printf("\nConfirm System PassWord: ");
		fgets(password2, sizeof(password2), stdin);

		password1[strlen(password1)-1] = '\0';
		password2[strlen(password2)-1] = '\0';
		/** password ascii code should between 32~126 **/
		
		if(check_passwd_range(password1)!=0 ||
				check_passwd_range(password2)!=0){
			printf("\nSorry, input error.\n");
			return CLI_ERROR;
		}
		
		if(strlen(password1)==0 || strlen(password2)==0){
			printf("\nSorry, passwords length can't be zero.\n");
			return CLI_ERROR;
		}

		if (strcmp(password1, password2) == 0) {
			break;
		}
		else{
			printf("\nSorry, passwords do not match.\n");
			return CLI_ERROR;
		}
	}

	base64_encode(buff, sizeof(buff), (const uint8_t *)password1, strlen(password1));

	sprintf(cmd , "script4 system cliusers %s passwd %s", "system", buff);

	/*system(cmd);*/
	if ((fp = popen(cmd, "r")) == NULL) {
		printf("\nPassword changed failure.\n");
		return CLI_ERROR;
	}

	if (fgets(buff, sizeof(buff), fp) != NULL) {
		printf("\nPassword changed failure.\n");
		pclose(fp);
		return CLI_ERROR;
	}

	pclose(fp);

	printf("\nPassword changed successfully.\n");
	return CLI_OK;
}


static int show_version(struct cli_def *cli, char *command, char *argv[], int argc)
{
	printf("VERSION: %s\n", VERSION);
	return CLI_OK;
}


static int show_cpuinfo(struct cli_def *cli, char *command, char *argv[], int argc)
{
	FILE *fp;
	char buff[BUFSIZ];
	char user[32], sys[32], iowait[32], soft[32], idle[32];


	printf("\n\tGenerating...\n\n");

	if ((fp = popen("mpstat -P ALL 1 1 | grep '^Average:' | grep -w 'all' | awk '{print $3,$5,$6,$8,$10}'", "r")) == NULL) {
		return CLI_ERROR;
	}


	if (fgets(buff, BUFSIZ, fp) == NULL) {
		pclose(fp);
		return CLI_ERROR;
	}

	sscanf(buff, "%s %s %s %s %s", user, sys, iowait, soft, idle);

	printf("%11s%%%11s%%%11s%%%11s%%%11s%%\n", "User", "Sys", "Iowait", "Soft", "Idle");
	printf("%12s%12s%12s%12s%12s\n", user, sys, iowait, soft, idle);

	pclose(fp);


	return CLI_OK;
	/*system("cat /proc/cpuinfo | less");*/
}

static int convert(unsigned long int n, char * str)
{
	if (n > 1048576 ) {
		sprintf(str, "%.2fT", ((double)n)/1048576);
	} else if ( n > 1024) {
		sprintf(str, "%.2fG", ((double)n)/1024);
	} else {
		sprintf(str, "%luM", n);
	}

	return 0;
}

static int show_memory(struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct memory memory;
	char a[18], b[18], c[18], d[18];

	if (system_memory_info(&memory) == 0) {
		printf("%12s%12s%12s%12s%12s\n" ,
				"Total", "Used", "free", "Swap" ,"Percent");
		convert(memory.total, a);
		convert(memory.used, b);
		convert(memory.free, c);
		convert(memory.cached, d);
		printf("%12s%12s%12s%12s%12s\n", a, b, c, d ,memory.percent);
	}

	return CLI_OK;
}

static int show_hard_disk(struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct hard_disk hd;
	char a[18], b[18], c[18];


	if (system_hard_disk_info(&hd) == 0) {
		printf("%12s%12s%12s%12s\n", "Total", "Used", "free" ,"Percent");
		convert(hd.total, a);
		convert(hd.used, b);
		convert(hd.free, c);
		printf("%12s%12s%12s%12s\n", a, b, c, hd.percent);
	}

	return CLI_OK;
}

static int show_time(struct cli_def *cli, char *command, char *argv[], int argc)
{
/*
	system("date");
*/
	FILE *fp;
	char buff[BUFSIZ];
	
#define PRINT_LINE \
	printf("+-----------------+--------------------------------+\n");
	
	if ((fp = popen("date +\"%Y-%m-%d %H:%M:%S\"", "r")) == NULL)
	  return CLI_ERROR;
	
	memset(buff, 0, sizeof(buff));
	fgets(buff, sizeof(buff) - 1, fp);
	buff[strlen(buff) - 1] = 0;
	PRINT_LINE;
	printf("| %-15s | %-30s |\n", "Time", buff);
	PRINT_LINE;
	pclose(fp);
	return CLI_OK;
}

static int do_shell(struct cli_def *cli, char *command, char *argv[], int argc)
{
	set_normal_tty();
	system("su - root -c \"/bin/bash\" ");
	set_nonline_tty();
	return CLI_OK;
}

static int do_syncookie(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[128] = {0};

	sprintf(buff, "script4 system %s", command);
	system(buff);
	return CLI_OK;
}

static int do_forward(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[128] = {0};

	sprintf(buff, "script4 system %s", command);
	system(buff);
	return CLI_OK;
}

static int reboot_poweroff_machine (struct cli_def *cli, char *command,
		char *argv[], int argc)
{
	char cmd[BUFSIZ];
	sprintf(cmd, "script4 system %s", command);
	system(cmd);
	return CLI_OK;
}


static int restore_default_configure (struct cli_def *cli, char *command,
		char *argv[], int argc)
{
	char ch[1024];
	printf("Warning: This operation will cause system restart, continue? [Y/N] ");
	set_normal_tty();
	if (fgets(ch, 1023, stdin) == NULL) {
		goto error;
	}

	if (strcasecmp(ch, "y\n") == 0 || strcasecmp(ch, "yes\n") == 0) {
		system("script4 system sys config restore_default");
		set_nonline_tty();
		return CLI_OK;
	}

error:
	set_nonline_tty();
	return CLI_ERROR;

}

static int default_func(struct cli_def *cli, char *command, char *argv[], int argc)
{
	printf("%s what?\n", command);
	return CLI_OK;
}

static int change_admin_passwd(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[4096], cmd[128], password1[257], password2[257];
	FILE *fp;

	while(1){
		printf("New wsadmin PassWord: ");
		fgets(password1, 256, stdin);
		printf("\nConfirm wsadmin PassWord: ");
		fgets(password2, 256, stdin);

		password1[strlen(password1)-1] = '\0';
		password2[strlen(password2)-1] = '\0';

		if(check_passwd_range(password1)!=0 ||
				check_passwd_range(password2)!=0){
			printf("\nSorry, input error.\n");
			return CLI_ERROR;
		}
		
		if(strlen(password1)==0 || strlen(password2)==0){
			printf("\nSorry, passwords length can't be zero.\n");
			return CLI_ERROR;
		}

		if (strcmp(password1, password2) == 0 &&
				strlen(password1) != 0) {
			break;
		} else {
			printf("\nSorry, passwords do not match.\n");
			return CLI_ERROR;
		}
	}
	memset(buff, 0, 4096);
	base64_encode(buff, 4095, (const uint8_t *)password1, strlen(password1));

	sprintf(cmd, "script4 system cliusers wsadmin passwd %s", buff);

	if ((fp = popen(cmd, "r")) == NULL) {
		printf("\nPassword changed failure.\n");
		return CLI_ERROR;
	}

	if (fgets(buff, sizeof(buff), fp) != NULL) {
		printf("\nPassword changed failure.\n");
		pclose(fp);
		return CLI_ERROR;
	}

	pclose(fp);

	printf("\nPassword changed successfully.\n");

	return CLI_OK;
}


static void signal_do_nothing(int signum)
{
	/** only interrupt the select call in libcli.c **/
}

int system_set_SLB_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;
	struct cli_command *p;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "SLB", NULL, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_COMMON_SET_SLB);

	p= cli_register_command(cli, c, "show", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_SHOW_INFO);

	healthcheck_show_command(cli, p);
	pool_show_command(cli, p);
	vs_show_command(cli, p);
	rule_show_command(cli, p);


	p= cli_register_command(cli, c, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_ADD_INFO);
	healthcheck_add_command(cli, p);

	pool_add_command(cli, p);
	vs_add_command(cli, p);

	p = cli_register_command(cli, c, "set", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_MANAGE_INFO);
	healthcheck_set_command(cli, p);
	pool_set_command(cli, p);
	vs_set_command(cli, p);
	walkrs_network_set_command(cli, p);



	p = cli_register_command(cli, c, "delete", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_DELETE_INFO);
	healthcheck_delete_command(cli, p);

	pool_delete_command(cli, p);
	vs_delete_command(cli, p);
	return 0;
}

int system_set_GSLB_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;
	struct cli_command *p;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "GSLB", NULL, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_COMMON_SET_GSLB);

	p= cli_register_command(cli, c, "show", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_SHOW_INFO);
	gslb_listener_show_command(cli, p);
	gslb_vserver_show_command(cli, p);
	gslb_device_show_command(cli, p);
	gslb_pool_show_command(cli, p);
	gslb_group_show_command(cli, p);
	tp_policy_show_command(cli, p);		// show topology policy
	healthcheck_show_command(cli, p);


	p= cli_register_command(cli, c, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_ADD_INFO);
	gslb_listener_add_command(cli, p);
	healthcheck_add_command(cli, p);
	gslb_vserver_add_command(cli, p);
	gslb_device_add_command(cli, p);
	gslb_pool_add_command(cli, p);

	p = cli_register_command(cli, c, "set", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_MANAGE_INFO);
	gslb_vserver_set_command(cli, p);
	healthcheck_set_command(cli, p);
	gslb_device_set_command(cli, p);
	gslb_pool_set_command(cli, p);
	gslb_group_set_command(cli, p);
	//tp_node_set_command(cli, p);
	tp_policy_set_command(cli, p);

	p = cli_register_command(cli, c, "delete", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_DELETE_INFO);
	gslb_listener_delete_command(cli, p);
	gslb_vserver_delete_command(cli, p);
	healthcheck_delete_command(cli, p);
	gslb_device_delete_command(cli, p);
	gslb_pool_delete_command(cli, p);
	//gslb_group_delete_command(cli, p);
	//tp_node_delete_command(cli, p);
	return 0;
}

int system_set_LLB_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;
	struct cli_command *p;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "LLB", NULL, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_COMMON_SET_LLB);

	p= cli_register_command(cli, c, "show", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_SHOW_INFO);
	llb_vserver_show_command(cli, p);
	healthcheck_show_command(cli, p);
	llb_pool_show_command(cli, p);
	tp_policy_show_command(cli, p);		// show topology policy
	llb_snat_show_command(cli, p);


	p= cli_register_command(cli, c, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_ADD_INFO);
	healthcheck_add_command(cli, p);
	llb_vserver_add_command(cli, p);
	llb_pool_add_command(cli, p);
	llb_snat_add_command(cli, p);
	//tp_node_add_command(cli, p);

	p = cli_register_command(cli, c, "set", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_MANAGE_INFO);
	llb_vserver_set_command(cli, p);
	healthcheck_set_command(cli, p);
	llb_pool_set_command(cli, p);
	//tp_node_set_command(cli, p);
	tp_policy_set_command(cli, p);
	//llb_snat_set_command(cli, p);


	p = cli_register_command(cli, c, "delete", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_DELETE_INFO);
	llb_vserver_delete_command(cli, p);
	healthcheck_delete_command(cli, p);
	llb_pool_delete_command(cli, p);
	llb_snat_delete_command(cli, p);
	//tp_node_delete_command(cli, p);

	return 0;
}

int system_set_TOPOLOGY_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;
	struct cli_command *p;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "Topology", NULL, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_COMMON_SET_TOPOLOGY);

	p= cli_register_command(cli, c, "show", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_TOPOLOGY_SHOW_INFO);
	tp_node_show_command(cli, p);


	p= cli_register_command(cli, c, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_TOPOLOGY_ADD_INFO);
	tp_node_add_command(cli, p);

/*
	p = cli_register_command(cli, c, "set", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_TOPOLOGY_SET_INFO);
	tp_node_set_command(cli, p);
*/

	p = cli_register_command(cli, c, "delete", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_TOPOLOGY_DELETE_INFO);
	tp_node_delete_command(cli, p);
	return 0;

}

int system_set_BIND9_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *c;
	struct cli_command *p;

	if (cli == NULL || parent == NULL) {
		return -1;
	}

	c = cli_register_command(cli, parent, "BIND9", NULL, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_COMMON_SET_BIND9);

	p= cli_register_command(cli, c, "show", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_BIND9_SHOW_INFO);
	bind9_show_command(cli, p);


	p= cli_register_command(cli, c, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_BIND9_ADD_INFO);
	bind9_add_command(cli, p);

	p = cli_register_command(cli, c, "set", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_BIND9_MANAGE_INFO);
	bind9_set_command(cli, p);


	p = cli_register_command(cli, c, "delete", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_BIND9_DELETE_INFO);
	bind9_delete_command(cli, p);
	return 0;
}

static int cli_show_vserver_detail_info(char *vsname)
{
	LIST_HEAD(queue);
	module_get_queue(&queue, "vserver", vsname);

	vserver_print_detail(&queue);

	module_purge_queue(&queue, "vserver");
	return 0;
}

int main(int argc, char **argv)
{
	struct cli_def *cli;
	struct cli_command *c;

	char *vsname = NULL;

	int t;
	while ((t = getopt(argc, argv, "vp:")) != -1) {
		switch(t) {
			case 'v':
				printf("VERSION: %s\n", VERSION);
				exit(0);
			case 'p':
				vsname = optarg;
				break;
			default:
				break;
		}
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGINT, signal_do_nothing);

	if (getuid() == 0) {
		/** 获取wsadmin用户的uid **/
		struct passwd *p = getpwnam("wsadmin");
		if (p == NULL) {
			printf("Create user \"wsadmin\" first.\n");
			exit(-1);
		}
		setuid(p->pw_uid);
	}

	init_libcomm();

	if (vsname != NULL) {
		cli_show_vserver_detail_info(vsname);
		exit(0);
	}

	cli = cli_init();
	cli_set_enable_callback(cli, check_enable);

	/*** add modify cli system user's password ***/
	c = cli_register_command(cli, NULL, "passwd", cliusers_default, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_CLIUSERS_SET_PASSWD);

	/*** add PRIVILEGE_UNPRIVILEGED command here **/
	c = cli_register_command(cli, NULL, "show", default_func, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_SHOW_INFO);
	cli_register_command(cli, c, "time", show_time, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_TIME);
	cli_register_command(cli, c, "version", show_version, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_VERSION);
	cli_register_command(cli, c, "cpuinfo", show_cpuinfo, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_CPU);
	cli_register_command(cli, c, "memory", show_memory, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_MEMORY);
	cli_register_command(cli, c, "hard_disk", show_hard_disk, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_HARDDISK);
	cli_register_command(cli, NULL, "passwd", change_admin_passwd, PRIVILEGE_UNPRIVILEGED,
			MODE_EXEC, LIBCLI_ADMIN_RESET_PASSWD);

	/*** add PRIVILEGE_PRIVILEGED command here ***/
	c = cli_register_command(cli, NULL, "show", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_SHOW_INFO);
	sysconfig_show_command(cli, c);
	network_show_command(cli, c);
	ssl_show_command(cli, c);
	hb_show_command(cli, c);
	snmp_show_command(cli, c);
	smtp_show_command(cli, c);
	dns_show_command(cli, c);
	sys_show_command(cli, c);
	ntpdate_show_command(cli, c);
	//firewall_show_command(cli, c);
	vcenter_show_command(cli, c);

	c = cli_register_command(cli, NULL, "add", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_ADD_INFO);
	network_add_command(cli, c);
	ssl_add_command(cli, c);
	dns_add_command(cli, c);
	vcenter_add_command(cli,c);



	c = cli_register_command(cli, NULL, "set", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_MANAGE_INFO);
	system_set_SLB_command(cli, c);	
	system_set_GSLB_command(cli, c);	
	system_set_LLB_command(cli, c);	
	system_set_BIND9_command(cli, c);	
	system_set_TOPOLOGY_command(cli, c);	

	sysconfig_set_command(cli, c);
	ssl_set_command(cli, c);
	network_set_command(cli, c);
	hb_set_command(cli, c);
	snmp_set_command(cli, c);
	smtp_set_command(cli, c);
	sys_set_command(cli, c);
	ntpdate_set_command(cli, c);
	//firewall_set_command(cli, c);
	vcenter_set_command(cli, c);

	c = cli_register_command(cli, NULL, "delete", default_func, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_COMMON_DELETE_INFO);
	network_delete_command(cli, c);
	ssl_delete_command(cli, c);
	dns_delete_command(cli, c);
	vcenter_delete_command(cli, c);

	c = cli_register_command(cli, NULL, "reboot", reboot_poweroff_machine, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_REBOOT);
	c = cli_register_command(cli, NULL, "poweroff", reboot_poweroff_machine, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_POWEROFF);
	c = cli_register_command(cli, NULL, "restore", restore_default_configure, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_RESTORE);

	c = cli_register_command(cli, NULL, "diagnosis", NULL, 
			PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_UNIX_DIAGNOSIS);

	diagnosis_init_standard_cmd(cli, c);

	c = cli_register_shadow_command(cli, NULL, "!shell", do_shell, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_SHELL);

	c = cli_register_command(cli, NULL, "syncookie", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_SYNCOOKIE);
	cli_register_command(cli, c, "on", do_syncookie, PRIVILEGE_PRIVILEGED, 
			MODE_EXEC, LIBCLI_SYSTEM_SYNCOOKIE_ON);
	cli_register_command(cli, c, "off", do_syncookie, PRIVILEGE_PRIVILEGED, 
			MODE_EXEC, LIBCLI_SYSTEM_SYNCOOKIE_OFF);

	c = cli_register_command(cli, NULL, "forward", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_SYSTEM_FORWARD);

	cli_register_command(cli, c, "on", do_forward, PRIVILEGE_PRIVILEGED, 
			MODE_EXEC, LIBCLI_SYSTEM_FORWARD_ON);
	cli_register_command(cli, c, "off", do_forward, PRIVILEGE_PRIVILEGED, 
			MODE_EXEC, LIBCLI_SYSTEM_FORWARD_OFF);

	cli_loop(cli, STDOUT_FILENO);

	cli_done(cli);
	return 0;
}
