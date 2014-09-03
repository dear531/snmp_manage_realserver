#include "libwalkrs.h"
#include "libcli/str_desc.h"
#include "common/dependence.h"
int check_walkrs_ip_netmask(struct cli_def *cli, struct cli_command *c, char *value)
{
	int rc;

	/** check netmask & ip **/
	rc = check_address_format(value);
	return rc;
}

static int add_walk_rs_network(struct cli_def *cli, char *command, char *argv[], int argc)
{
	fprintf(stdout, "here add walk4rs ip/netmask\n");
	return 0;
}
static int del_walk_rs_network(struct cli_def *cli, char *command, char *argv[], int argc)
{
	fprintf(stdout, "here del walk4rs ip/netmask\n");
	return 0;
}
int walkrs_network_set_command(struct cli_def *cli, struct cli_command *parent)
{
	struct cli_command *walknetwork, *t, *p;
	walknetwork = cli_register_command(cli, parent, "walknetwork", NULL, PRIVILEGE_PRIVILEGED,
			MODE_FOLDER, LIBCLI_POOL_MANAGE_INFO);
	t = cli_register_command(cli, walknetwork, "add", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	p = cli_register_command(cli, t, "network", add_walk_rs_network, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	cli_command_add_argument(p, "<ipv4: ipaddr/prefix; ipv6: ipaddr/prefix>", check_walkrs_ip_netmask);

	t = cli_register_command(cli, walknetwork, "del", NULL, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	p = cli_register_command(cli, t, "network", del_walk_rs_network, PRIVILEGE_PRIVILEGED,
			MODE_EXEC, LIBCLI_POOL_SET_ADD_REALSERVER);
	cli_command_add_argument(p, "<ipaddr/netmask>", check_walkrs_ip_netmask);
	cli_command_setvalues_func(p, NULL, NULL);

	return 0;
}
