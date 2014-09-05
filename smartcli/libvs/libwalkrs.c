#include "libwalkrs.h"
#include "libcli/str_desc.h"
#include "common/dependence.h"
#include "common/common.h"
#include "loadbalance/walk4rsnetwork.h"
#include "common/module.h"

int check_walkrs_ip_netmask(struct cli_def *cli, struct cli_command *c, char *value)
{
	int rc;

	/** check netmask & ip **/
	rc = check_address_format(value);
	return rc;
}

static int add_del_walk_rs_network(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char buff[BUFSIZ];
	char para[BUFSIZ];

	if (argc != 1) {
		if (argc)
			fprintf(stderr, "Invalid argument \"%s\".\r\n", argv[0]);
		else
			fprintf(stderr, "\"%s\" requires an argument.\r\n", 
					command);

		return CLI_ERROR;
	}

	strcpy(para, argv[0]);

	if (strncmp(command, "add network", strlen("add network"))==0) {
		char ip[STR_IP_LEN], netmask[STR_NETMASK_LEN];
		get_ip_netmask2(para, ip, netmask);
		sprintf(para, "%s/%s", ip, netmask);
	}
	snprintf(buff, BUFSIZ, "script4 system walknetwork %s %s", 
			command, para);
	system(buff);

	return 0;
}

int walk4rs_network_get_values(struct cli_def *cli, char **values)
{
	int k = 0;
	struct walk4rsnetwork *network;
	LIST_HEAD(queue);

	module_get_queue(&queue, "walk4rsnetwork", NULL);
	list_for_each_entry(network, &queue, list) {
		values[k++] = strdup(network->ipaddr);
	}
	module_purge_queue(&queue, "walk4rsnetwork");

	return k;
}

static int walk4rsnetwork_print(struct list_head *queue)
{
	struct walk4rsnetwork *network;

#define printf_format(attr, value)\
	printf("| %-34s | %-29s |\n", attr, value);  \
	printf("+--------------------------------------------------------------------+\n");

		printf("+--------------------------------------------------------------------+\n");
		printf("|          snmpwalk for real server ipaddress and netmask            |\n");
		printf("+--------------------------------------------------------------------+\n");
		printf("|           ipaddress                |           netmask             |\n");
		printf("+--------------------------------------------------------------------+\n");

	list_for_each_entry(network, queue, list) {
			printf_format(network->ipaddr, network->netmask);
	}

#undef printf_format

	return 0;

}

static int walk4rsnetwork_show(struct cli_def *cli, char *command, char *argv[], int argc)
{
	LIST_HEAD(queue);

	if (strcmp(command, "show") == 0) {
		module_get_queue(&queue, "walk4rsnetwork", NULL);
	}

	walk4rsnetwork_print(&queue);
	module_purge_queue(&queue, "walk4rsnetwork");

	return CLI_OK;
}

int walkrs_network_set_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *walknetwork, *t, *p;
	walknetwork = cli_register_command(cli, parent, "walknetwork", NULL, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_POOL_MANAGE_INFO);
	t = cli_register_command(cli, walknetwork, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	p = cli_register_command(cli, t, "network", add_del_walk_rs_network, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	cli_command_add_argument(p, "<ipv4: ipaddr/prefix; ipv6: ipaddr/prefix>", check_walkrs_ip_netmask);

	t = cli_register_command(cli, walknetwork, "del", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	p = cli_register_command(cli, t, "network", add_del_walk_rs_network, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	cli_command_add_argument(p, "<ipaddr/netmask>", check_walkrs_ip_netmask);
	cli_command_setvalues_func(p, walk4rs_network_get_values, default_free_values);

    t = cli_register_command(cli, walknetwork, "show", walk4rsnetwork_show, PRIVILEGE_PRIVILEGED, MODE_EXEC,
            LIBCLI_SNMP_SET_SHOW);


	return 0;
}
