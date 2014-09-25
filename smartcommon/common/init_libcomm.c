

#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>

#include "cli_users/cli_users.h"

#include "network/network.h"
#include "network/arptable.h"
#include "network/rtable.h"
#include "network/snat.h"
#include "network/dns.h"
#include "network/forward.h"
#include "network/floatip.h"
#include "network/bandwidth.h"
#include "network/ntpdate.h"
#include "network/firewall.h"
#include "network/dnat.h"

#include "snmp/snmp.h"
#include "mail.h"
#include "common/common.h"
#include "common/config_apache.h"

#include "cluster/hb.h"

#include "loadbalance/errpages.h"
#include "loadbalance/healthcheck.h"
#include "loadbalance/apppool.h"
#include "loadbalance/rule.h"
#include "loadbalance/vserver.h"
#include "loadbalance/under_gslb.h"
#include "loadbalance/vcenter.h"
#include "loadbalance/walk4rsnetwork.h"
#include "common/module.h"
#include "weblog/weblog.h"
#include "authentication/authentication.h"
#include "system/tcp_congestion_control.h"
#include "gslb/gslb_listener.h"
#include "gslb/gslb_vserver.h"
#include "gslb/gslb_device.h"
#include "gslb/gslb_pool.h"
#include "gslb/gslb_group.h"
#include "gslb/topology.h"
#include "gslb/topologyfiles.h"
#include "gslb/bind9.h"
#include "llb/llb_qos_schedule.h"
#include "llb/llb_qos_class.h"
#include "llb/llb_vserver.h"
#include "llb/llb_pool.h"
#include "llb/llb_system.h"
#include "llb/llb_snat.h"

#include "sysconfig/sysconfig.h"

extern int merge_default_config_file(void)
{
	/** get process name **/
	char procname[256];
	memset(procname, 0, sizeof(procname));

#define DAEMON4 "/SmartGrid/shell/daemon4"
	readlink("/proc/self/exe", procname, sizeof(procname));//读取绝对路径

	if (strcmp(procname, DAEMON4) != 0 || getuid() != 0) { 
		return 0;
	}

	config_sysconfig_merge();
	config_cliusers_merge();
	config_network_merge();
	config_smtp_merge();
	config_snmp_merge();
	config_hb_merge();
	config_ntpdate_merge();
	config_under_gslb_merge();
	config_SyncGroup_merge();
	config_firewall_merge();
	config_firewall_merge();
	/** 添加默认健康检查规则 **/
	config_healthcheck_merge();

	/** merge web认证 **/
	config_authentication_merge();

	/** bandwidth for vserver/rserver **/
	module_init_bandwidth();

	set_cpu_interrupt_mask();

	set_tcp_congestion_control(NULL);

	if (access("/SmartGrid/apache/conf/extra/httpd-ssl.conf", F_OK) != 0) {
		config_apache(0, 0);
	}
	cpu_interrupt_init() ;

	return 0;
}


extern int init_libcomm(void)
{
	/* init system config, such as llbenable  ... */
	module_init_sysconfig();

	/* init_smartcli */
	module_init_cliusers();

	/** init networking **/
	module_init_network();
	module_init_arptable();
	module_init_floatip();
	module_init_rtable();
	module_init_snat();
	module_init_dnat();
	module_init_dns();
	module_init_forward();
	module_init_ntpdate();
	module_init_weblog();

	/** init snmp **/
	module_init_snmp();
	module_init_smtp();

	/** init cluster **/
	module_init_hb();

	/** init loadbalance **/
	module_init_errpages();
	module_init_topologyfiles();
	module_init_healthcheck();
	module_init_apppool();
	module_init_rule();
	module_init_vserver();
	module_init_walk4rsnetwork();
/***init firewall*********/
	module_init_firewall();
	/* init GSLB*/
	module_init_gslb_listener();
	module_init_gslb_vserver();
	module_init_gslb_device();
	module_init_gslb_pool();
	module_init_gslb_group();
	module_init_bind9_domain();
	module_init_tp_node();
	module_init_tp_policy();
	/*init LLB*/
	module_init_llb_qos_class();
	module_init_llb_system();
	module_init_llb_vserver();
	module_init_llb_pool();
	module_init_llb_qos_schedule();
	module_init_under_gslb();
	module_init_llb_snat();

	/***init vcenter**/
	module_init_vcenter();

	/* authentication，web认证 */
	module_init_authentication();

	merge_default_config_file();
	

	return 0;
}

