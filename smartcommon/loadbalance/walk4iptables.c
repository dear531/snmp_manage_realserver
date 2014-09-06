#include "common/module.h"
#include "common/list.h"
#include "walk4rsnetwork.h"
#include "walk4iptables.h"
#if 0
#include <signal.h>
typedef void (*sighandler_t)(int);
int system_sig_dfl(const char *command)
{
	int ret;
	sighandler_t old_sig_func;
	if (SIG_ERR == (old_sig_func = signal(SIGCHLD, SIG_DFL))) {
		syslog(LOG_INFO, "set signal child to default error :%s\n",
				strerror(errno));
	}

	if (0 > (ret = system(command))) {
		syslog(LOG_INFO, "system error :%s\n",
				strerror(errno));
	}

	if (SIG_ERR == signal(SIGCHLD, old_sig_func)) {
		syslog(LOG_INFO, "restorge signal child to old error :%s\n",
				strerror(errno));
	}

	return ret;
}
#endif
void iptables_snmpwalk_rs(struct list_head *head, int op)
{
	char cmd[BUFSIZ];
#if 0
	struct network *network;

	/** 当没有配置网络白名单时，所有ip都可以访问 **/
	if (list_empty(&snmp->network_head)) {
		sprintf(cmd, "iptables %s INPUT -p udp --dport 161 -j ACCEPT >/dev/null 2>&1",
				op == 1 ? "-A" : "-D");
		system(cmd);

		sprintf(cmd, "ip6tables %s INPUT -p udp --dport 161 -j ACCEPT >/dev/null 2>&1",
				op == 1 ? "-A" : "-D");
		system(cmd);
		return;
	}

	list_for_each_entry(network, &snmp->network_head, list) {
		if (strchr(network->ipaddr, ':') == NULL) {	// ipv4
			sprintf(cmd, "iptables %s INPUT -s %s/%s -p udp --dport 161 -j ACCEPT",
					op == 1 ? "-A" : "-D",
					network->ipaddr, network->netmask);
		} else {
			sprintf(cmd, "ip6tables %s INPUT -s %s/%s -p udp --dport 161 -j ACCEPT",
					op == 1 ? "-A" : "-D",
					network->ipaddr, network->netmask);
		}
		system(cmd);
	}
#else
    struct walk4rsnetwork *network;
	LIST_HEAD(queue);
    module_get_queue(&queue, "walk4rsnetwork", NULL);
	list_for_each_entry(network, &queue, list) {
		if (strchr(network->ipaddr, ':') == NULL) {	// ipv4
			sprintf(cmd, "iptables %s INPUT -s %s/%s -p udp --sport 161 -j ACCEPT",
					op == 1 ? "-A" : "-D",
					network->ipaddr, network->netmask);
		} else {
			sprintf(cmd, "ip6tables %s INPUT -s %s/%s -p udp --sport 161 -j ACCEPT",
					op == 1 ? "-A" : "-D",
					network->ipaddr, network->netmask);
		}
		system(cmd);
	/* system("iptables -A INPUT -s 192.168.12.0/24  -p udp  --sport 161 -j ACCEPT"); */

	}
    module_purge_queue(&queue, "walk4rsnetwork");
#endif
}
