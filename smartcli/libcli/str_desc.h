
#ifndef __SMARTCLI_STR_DESC_H__
#define __SMARTCLI_STR_DESC_H__



enum {
	/************ NULL ***************/
	LIBCLI_NULL_INFO = 0,

	/************ common ***************/
	LIBCLI_COMMON_LANGUAGE_SET,
	LIBCLI_COMMON_LANGUAGE_EN_US,
	LIBCLI_COMMON_LANGUAGE_ZH_CN,
	LIBCLI_COMMON_SYSTEM_INFO,
	LIBCLI_COMMON_EXIT_INFO,
	LIBCLI_COMMON_HELP_INFO,
	LIBCLI_COMMON_QUIT_INFO,
	LIBCLI_COMMON_HISTORY_INFO,
	LIBCLI_COMMON_PWD_INFO,
	LIBCLI_COMMON_SHOW_INFO,
	LIBCLI_COMMON_ADD_INFO,
	LIBCLI_COMMON_DELETE_INFO,

	LIBCLI_COMMON_SET_GSLB,
	LIBCLI_COMMON_SET_LLB,
	LIBCLI_COMMON_SET_BIND9,
	LIBCLI_COMMON_SET_TOPOLOGY,
	LIBCLI_COMMON_SET_SLB,

	LIBCLI_COMMON_MANAGE_INFO,
	LIBCLI_ADMIN_RESET_PASSWD,
	LIBCLI_SYSTEM_TIME,
	LIBCLI_SYSTEM_VERSION,
	LIBCLI_SYSTEM_CPU,
	LIBCLI_SYSTEM_MEMORY,
	LIBCLI_SYSTEM_HARDDISK,
	LIBCLI_SYSTEM_REBOOT,
	LIBCLI_SYSTEM_POWEROFF,
	LIBCLI_SYSTEM_RESTORE,
	LIBCLI_SYSTEM_SHELL,
	LIBCLI_SYSTEM_FORWARD,
	LIBCLI_SYSTEM_FORWARD_ON,
	LIBCLI_SYSTEM_FORWARD_OFF,
	LIBCLI_SYSTEM_SYNCOOKIE,
	LIBCLI_SYSTEM_SYNCOOKIE_ON,
	LIBCLI_SYSTEM_SYNCOOKIE_OFF,
	LIBCLI_UNIX_DIAGNOSIS,
	LIBCLI_UNIX_PING,
	LIBCLI_UNIX_TRACEROUTE,
	LIBCLI_UNIX_NETSTAT,
	LIBCLI_UNIX_SAR,
	LIBCLI_UNIX_IOSTAT,
	LIBCLI_ADD_IP,
	LIBCLI_DEL_IP,
	LIBCLI_ADD_INTERFACE,
	LIBCLI_DEL_INTERFACE,


	
	LIBCLI_SYSTEM_UNDER_GSLB_SHOW_INFO,
	LIBCLI_SYSTEM_UNDER_GSLB_MANAGE_INFO,
	LIBCLI_SYSTEM_UNDER_GSLB_SET_PASSWORD,
	LIBCLI_SYSTEM_UNDER_GSLB_ENABLE,
	LIBCLI_SYSTEM_UNDER_GSLB_ENABLE_ON,
	LIBCLI_SYSTEM_UNDER_GSLB_ENABLE_OFF,


	/************ vserver ***************/
	LIBCLI_VSERVER_ADD_INFO,
	LIBCLI_VSERVER_SHOW_INFO,
	LIBCLI_VSERVER_SHOW_IPADDR_INFO,
	LIBCLI_VSERVER_SHOW_RULE_NAME,
	LIBCLI_VSERVER_MANAGE_INFO,
	LIBCLI_VSERVER_DELETE_INFO,
	LIBCLI_VSERVER_SET_ADDRESS,
	LIBCLI_VSERVER_SET_WEIGHT,
	LIBCLI_VSERVER_SET_SNMP,
	LIBCLI_VSERVER_SET_SCHED_ALG,
	LIBCLI_VSERVER_SET_SCHED_RR,
	LIBCLI_VSERVER_SET_SCHED_WRR,
	LIBCLI_VSERVER_SET_SCHED_LC,
	LIBCLI_VSERVER_SET_SCHED_WLC,
	LIBCLI_VSERVER_SET_SCHED_HASHIP,
	LIBCLI_VSERVER_SET_SCHED_HASHURL,
	LIBCLI_VSERVER_SET_SCHED_FAIR,
	LIBCLI_VSERVER_SET_SCHED_LLCR,
	LIBCLI_VSERVER_SET_SCHED_SH,
	LIBCLI_VSERVER_SET_SCHED_SED,
	LIBCLI_VSERVER_SET_SCHED_NQ,
	LIBCLI_VSERVER_SET_SCHED_LBLC,
	LIBCLI_VSERVER_SET_SCHED_LBLCR,
	LIBCLI_VSERVER_SET_SCHED_COOKIE,
	LIBCLI_VSERVER_SET_PROTOCOL,
	LIBCLI_VSERVER_SET_ENABLE,
	LIBCLI_VSERVER_SET_ENABLE_ON,
	LIBCLI_VSERVER_SET_ENABLE_OFF,
	LIBCLI_VSERVER_SET_TRANSPARENT,
	LIBCLI_VSERVER_SET_TRANSPARENT_ON,
	LIBCLI_VSERVER_SET_TRANSPARENT_OFF,
	LIBCLI_VSERVER_SET_CONTENTSWITCH,
	LIBCLI_VSERVER_SET_CONTENTSWITCH_ON,
	LIBCLI_VSERVER_SET_CONTENTSWITCH_OFF,
	LIBCLI_VSERVER_SET_XFORWARDEDFOR,
	LIBCLI_VSERVER_SET_XFORWARDEDFOR_ON,
	LIBCLI_VSERVER_SET_XFORWARDEDFOR_OFF,
	LIBCLI_VSERVER_SET_RFC2616CHECK,
	LIBCLI_VSERVER_SET_RFC2616CHECK_ON,
	LIBCLI_VSERVER_SET_RFC2616CHECK_OFF,
	LIBCLI_VSERVER_SET_CONNREUSE,
	LIBCLI_VSERVER_SET_CONNREUSE_ON,
	LIBCLI_VSERVER_SET_CONNREUSE_OFF,
	LIBCLI_VSERVER_SET_ADD_RULE,
	LIBCLI_VSERVER_SET_DEL_RULE,
	LIBCLI_VSERVER_SET_SET_RULE,
	LIBCLI_VSERVER_SET_RULE_UP,
	LIBCLI_VSERVER_SET_RULE_DOWN,
	LIBCLI_VSERVER_SET_RULE_TOP,
	LIBCLI_VSERVER_SET_RULE_BOTTOM,
	LIBCLI_VSERVER_SET_RULE_NAME,
	LIBCLI_VSERVER_SET_POOL,
	LIBCLI_VSERVER_SET_BACKPOOL,
	LIBCLI_VSERVER_SET_PERSISTENT,
	LIBCLI_VSERVER_SET_PERSISTENTGROUP,
	LIBCLI_VSERVER_SET_PERSISTENT_TIMEOUT,
	LIBCLI_VSERVER_SET_PERSISTENT_NETMASK,
	LIBCLI_VSERVER_SET_GZIP,
	LIBCLI_VSERVER_SET_GZIP_ON,
	LIBCLI_VSERVER_SET_GZIP_OFF,
	LIBCLI_VSERVER_SET_DEFLATE,
	LIBCLI_VSERVER_SET_DEFLATE_ON,
	LIBCLI_VSERVER_SET_DEFLATE_OFF,
	LIBCLI_VSERVER_SET_CACHE,
	LIBCLI_VSERVER_SET_CACHE_ON,
	LIBCLI_VSERVER_SET_CACHE_OFF,
	LIBCLI_VSERVER_SET_TIMEOUT,
	LIBCLI_VSERVER_SET_LIMIT,
	LIBCLI_VSERVER_SET_LIMIT_OFF,
	LIBCLI_VSERVER_SET_LIMIT_MAXCONN,
	LIBCLI_VSERVER_SET_LIMIT_MAXREQ,
	LIBCLI_VSERVER_SET_LIMIT_BANDWIDTH,
	LIBCLI_VSERVER_SET_CIPHEADER,
	LIBCLI_VSERVER_SET_PERSISTENT_OFF,
	LIBCLI_VSERVER_SET_PERSISTENT_IP,
	LIBCLI_VSERVER_SET_PERSISTENT_SSLID,
	LIBCLI_VSERVER_SET_PERSISTENT_COOKIE,
	LIBCLI_VSERVER_SET_PERSISTENT_COOKIE_NAME,
	LIBCLI_VSERVER_SET_PERSISTENT_HEADER,
	LIBCLI_VSERVER_SET_PERSISTENT_HEADER_NAME,
	LIBCLI_VSERVER_SET_RULENAME_SET_PRIORITY,
	LIBCLI_VSERVER_SET_RULENAME_SET_NAME,
	LIBCLI_VSERVER_SET_DATA_PORT,
	LIBCLI_VSERVER_SET_MODE_INFO,
	LIBCLI_VSERVER_SET_MODE_NAT,
	LIBCLI_VSERVER_SET_MODE_DR,
	LIBCLI_VSERVER_SET_LOG_ENABLE_INFO,
	LIBCLI_VSERVER_SET_LOG_FORMAT_INFO,
	LIBCLI_VSERVER_SET_LOG_ENABLE_ON,
	LIBCLI_VSERVER_SET_LOG_ENABLE_OFF,
	LIBCLI_VSERVER_SET_WAF_ENABLE_INFO,
	LIBCLI_VSERVER_SET_WAF_ENABLE_ON,
	LIBCLI_VSERVER_SET_WAF_ENABLE_OFF,

	/*add */
	LIBCLI_BIND9_RECORD_TYPE_A,
	LIBCLI_BIND9_RECORD_TYPE_SRV,
	LIBCLI_BIND9_RECORD_TYPE_AAAA,
	LIBCLI_BIND9_RECORD_TYPE_MX,
	LIBCLI_BIND9_RECORD_TYPE_CNAME,
	LIBCLI_BIND9_RECORD_TYPE_TXT,
	LIBCLI_BIND9_RECORD_TYPE_NS,
	LIBCLI_BIND9_RECORD_TYPE_PTR,
	
	/************ pool ***************/
	LIBCLI_POOL_ADD_INFO,
	LIBCLI_POOL_SHOW_INFO,
	LIBCLI_POOL_MANAGE_INFO,
	LIBCLI_POOL_DELETE_INFO,
	LIBCLI_POOL_SET_ADD_REALSERVER,
	LIBCLI_POOL_SET_SET_REALSERVER,
	LIBCLI_POOL_SET_DEL_REALSERVER,
	LIBCLI_POOL_SET_SHOW_REALSERVER,
	LIBCLI_POOL_SET_REALSERVER_ENABLE,
	LIBCLI_POOL_SET_REALSERVER_ENABLE_ON,
	LIBCLI_POOL_SET_REALSERVER_ENABLE_OFF,
	LIBCLI_POOL_SET_HEALTHCHECK,

  /* used for elastic */
  LIBCLI_POOL_SET_VMWARE_VMWARE,
  LIBCLI_POOL_SET_REALSERVER_VMXPATH,
  LIBCLI_POOL_SET_REALSERVER_UUID,
  LIBCLI_POOL_SET_REALSERVER_RSCENTER,
  LIBCLI_POOL_SET_REALSERVER_DATACENTER,
  LIBCLI_POOL_SET_VMTYPE,
  LIBCLI_POOL_SET_VMTYPE_VMWARE,
  LIBCLI_POOL_SET_VMTYPE_XEN,
  LIBCLI_POOL_SET_VMTYPE_VCENTER,
  LIBCLI_POOL_SET_VM_ADDRESS, 
  LIBCLI_POOL_SET_VM_ENABLE,
  LIBCLI_POOL_SET_VM_ENABLE_ON,
  LIBCLI_POOL_SET_VM_ENABLE_OFF,
  LIBCLI_POOL_SET_VM_USERNAME,
  LIBCLI_POOL_SET_VM_PASSWORD,
  LIBCLI_POOL_SET_VM_INTERVAL,
  LIBCLI_POOL_SET_VM_COUNT,
  LIBCLI_POOL_SET_VM_VCENTER,
  LIBCLI_POOL_SET_VM_DATACENTER,
  LIBCLI_POOL_SET_VM_PORT,
  LIBCLI_POOL_SET_VM_ALIVE_COUNT,

	/********* healthcheck ************/
	LIBCLI_HEALTHCHECK_ADD_INFO,
	LIBCLI_HEALTHCHECK_SHOW_INFO,
	LIBCLI_HEALTHCHECK_MANAGE_INFO,
	LIBCLI_HEALTHCHECK_DELETE_INFO,
	LIBCLI_HEALTHCHECK_SET_TYPE,
	LIBCLI_HEALTHCHECK_SET_TIMEOUT,
	LIBCLI_HEALTHCHECK_SET_RETRY,
	LIBCLI_HEALTHCHECK_SET_INTERVAL,
	LIBCLI_HEALTHCHECK_SET_DOWNTIME,
	LIBCLI_HEALTHCHECK_SET_HTTP_PATH,
	LIBCLI_HEALTHCHECK_SET_HTTP_STATUSCODE,
	LIBCLI_HEALTHCHECK_SET_HTTP_OFFSET,
	LIBCLI_HEALTHCHECK_SET_HTTP_STRING,
	/**--------------------------------------**/
	LIBCLI_HEALTHCHECK_SET_HTTP_ECV_OFFSET,
	LIBCLI_HEALTHCHECK_SET_HTTP_ECV_STRING,
	LIBCLI_HEALTHCHECK_SET_HTTP_TYPE,
	LIBCLI_HEALTHCHECK_SET_ICMP_GW_IP,
	/**--------------------------------------**/
	LIBCLI_HEALTHCHECK_SET_SMTP_HELO,
	LIBCLI_HEALTHCHECK_SET_SCRIPT,
	LIBCLI_HEALTHCHECK_SET_DNS_DOMAIN,


	/************ rule ***************/
	LIBCLI_RULE_ADD_INFO,
	LIBCLI_RULE_SHOW_INFO,
	LIBCLI_RULE_MANAGE_INFO,
	LIBCLI_RULE_DELETE_INFO,
	LIBCLI_RULE_SET_CONDITION,
	LIBCLI_RULE_SET_ACTION,

	/********** interface *************/
	LIBCLI_INTERFACE_MGMT_SHOW_INFO,
	LIBCLI_INTERFACE_SHOW_INFO,
	LIBCLI_INTERFACE_MANAGE_INFO,
	LIBCLI_INTERFACE_SET_ADD,
	LIBCLI_INTERFACE_SET_ADD_IP_FLOAT,
	LIBCLI_INTERFACE_SET_ADD_IP_STATIC,
	LIBCLI_INTERFACE_SET_DELETE,
	LIBCLI_INTERFACE_SET_PROTOCOL,
	LIBCLI_INTERFACE_SET_PROTOCOL_STATIC,
	LIBCLI_INTERFACE_SET_PROTOCOL_DHCP,
	LIBCLI_INTERFACE_IP,

	LIBCLI_INTERFACE_TYPE_INFO,
	LIBCLI_INTERFACE_TYPE_NORMAL_INFO,
	LIBCLI_INTERFACE_TYPE_TRUNK_INFO,
	LIBCLI_INTERFACE_TYPE_TRUNK_PERMIT_INFO,
	LIBCLI_INTERFACE_TYPE_TRUNK_PERMIT_VLAN,
	LIBCLI_INTERFACE_TYPE_TRUNK_DENY_INFO,
	LIBCLI_INTERFACE_TYPE_TRUNK_DENY_VLAN,
	LIBCLI_INTERFACE_SET_SPEED,
	LIBCLI_INTERFACE_SET_SPEED_10HALF,
	LIBCLI_INTERFACE_SET_SPEED_10FULL,
	LIBCLI_INTERFACE_SET_SPEED_100HALF,
	LIBCLI_INTERFACE_SET_SPEED_100FULL,
	LIBCLI_INTERFACE_SET_SPEED_1000FULL,
	LIBCLI_INTERFACE_SET_SPEED_AUTO,

	LIBCLI_INTERFACE_PAUSE,
	LIBCLI_INTERFACE_PAUSE_NONE,
	LIBCLI_INTERFACE_PAUSE_RX,
	LIBCLI_INTERFACE_PAUSE_TX,
	LIBCLI_INTERFACE_PAUSE_RX_TX,
	LIBCLI_INTERFACE_PAUSE_AUTO,
	LIBCLI_INTERFACE_ENABLE,
	LIBCLI_INTERFACE_ENABLE_ON,
	LIBCLI_INTERFACE_ENABLE_OFF,

	LIBCLI_INTERFACE_METHOD,
	LIBCLI_INTERFACE_METHOD_RR,
	LIBCLI_INTERFACE_METHOD_AB,
	LIBCLI_INTERFACE_METHOD_XOR,
	LIBCLI_INTERFACE_METHOD_BC,
	LIBCLI_INTERFACE_METHOD_8023AD,
	LIBCLI_INTERFACE_METHOD_TLB,
	LIBCLI_INTERFACE_METHOD_ALB,

	/*********** bonding & vlan **************/
	LIBCLI_BONDING_ADD_INFO,
	LIBCLI_BONDING_MANAGE_INFO,
	LIBCLI_BONDING_DELETE_INFO,

	/*********** network->DNS  *************/
	LIBCLI_NETWORK_DNS_SHOW_INFO,
	LIBCLI_NETWORK_DNS_DEL_ADDR,
	LIBCLI_NETWORK_DNS_ADD_ADDR,

	/*********** network->SNAT  **************/
	LIBCLI_NETWORK_SNAT_SHOW_INFO,
	LIBCLI_NETWORK_SNAT_ADD_INFO,
	LIBCLI_NETWORK_SNAT_DELETE_INFO,
	LIBCLI_NETWORK_SNAT_MANAGE_INFO,
	LIBCLI_NETWORK_SNAT_SET_TYPE,
	LIBCLI_NETWORK_SNAT_SET_TYPE_STATIC,
	LIBCLI_NETWORK_SNAT_SET_TYPE_MASQUERADE,
	LIBCLI_NETWORK_SNAT_SET_SRCFROM,
	LIBCLI_NETWORK_SNAT_SET_SRCTO,
	LIBCLI_NETWORK_SNAT_SET_DESTFROM,
	LIBCLI_NETWORK_SNAT_SET_DESTTO,
	LIBCLI_NETWORK_SNAT_SET_INTERFACE,
	LIBCLI_NETWORK_SNAT_SET_ENABLE,
	LIBCLI_NETWORK_SNAT_SET_ENABLE_ON,
	LIBCLI_NETWORK_SNAT_SET_ENABLE_OFF,

	/*********** network->DNAT  **************/
	LIBCLI_NETWORK_DNAT_SHOW_INFO,
	LIBCLI_NETWORK_DNAT_ADD_INFO,
	LIBCLI_NETWORK_DNAT_SET_INFO,
	LIBCLI_NETWORK_DNAT_DEL_INFO,
	LIBCLI_NETWORK_DNAT_DEST_ADD_INFO,
	LIBCLI_NETWORK_DNAT_DEST_DEL_INFO,

	/*********** network->ROUTETABLE  **************/
	LIBCLI_NETWORK_RTABLE_SHOW_INFO,
	LIBCLI_NETWORK_RTABLE_ADD_INFO,
	LIBCLI_NETWORK_RTABLE_DELETE_INFO,
	LIBCLI_NETWORK_RTABLE_MANAGE_INFO,
	LIBCLI_NETWORK_RTABLE_SET_RULE,
	LIBCLI_NETWORK_RTABLE_SET_RULEID,
	LIBCLI_NETWORK_RTABLE_SET_ADD,
	LIBCLI_NETWORK_RTABLE_SET_DELETE,
	LIBCLI_NETWORK_RTABLE_ADD_ROUTE,
	LIBCLI_NETWORK_RTABLE_DEL_ROUTE,

	LIBCLI_NETWORK_RTABLE_ADD_S_ROUTE,
	LIBCLI_NETWORK_RTABLE_DEL_S_ROUTE,
	LIBCLI_NETWORK_RTABLE_SHOW_S_ROUTE,

	LIBCLI_NETWORK_RTABLE_ADD_ROUTE_NEXTHOP,
	LIBCLI_NETWORK_RTABLE_ADD_ROUTE_GATEWAY,
	LIBCLI_NETWORK_RTABLE_ADD_OSPF,
	LIBCLI_NETWORK_RTABLE_ADD_OSPF_AREA,
	LIBCLI_NETWORK_RTABLE_ADD_OSPF6,
	LIBCLI_NETWORK_RTABLE_ADD_OSPF6_AREA,
	LIBCLI_NETWORK_RTABLE_ADD_OSPF6_INTERFACE,
	LIBCLI_NETWORK_RTABLE_ADD_RIP,
	LIBCLI_NETWORK_RTABLE_ADD_RIPNG,
	LIBCLI_NETWORK_RTABLE_ADD_NEIGHBOR,
	LIBCLI_NETWORK_RTABLE_DELETE_OSPF,
	LIBCLI_NETWORK_RTABLE_DELETE_RIP,
	LIBCLI_NETWORK_RTABLE_DELETE_NEIGHBOR,
	LIBCLI_NETWORK_RTABLE_SET_OSPF,
	LIBCLI_NETWORK_RTABLE_SET_OSPF_ON,
	LIBCLI_NETWORK_RTABLE_SET_OSPF_OFF,
	LIBCLI_NETWORK_RTABLE_SET_OSPF6,
	LIBCLI_NETWORK_RTABLE_SET_OSPF6_ON,
	LIBCLI_NETWORK_RTABLE_SET_OSPF6_OFF,
	LIBCLI_NETWORK_RTABLE_SET_RIP,
	LIBCLI_NETWORK_RTABLE_SET_RIP_ON,
	LIBCLI_NETWORK_RTABLE_SET_RIP_OFF,
	LIBCLI_NETWORK_RTABLE_SET_RIPNG,
	LIBCLI_NETWORK_RTABLE_SET_RIPNG_ON,
	LIBCLI_NETWORK_RTABLE_SET_RIPNG_OFF,
	
	/*********** network->ARPTABLE  **************/
	LIBCLI_NETWORK_ARPTABLE_SHOW_INFO,
	LIBCLI_NETWORK_ARPTABLE_MANAGE_INFO,
	LIBCLI_NETWORK_ARPTABLE_SET_DELETE_ARP,
	LIBCLI_NETWORK_ARPTABLE_SET_DELETE_ALL_ARP,
	LIBCLI_NETWORK_ARPTABLE_SET_ADD_ARP,
	LIBCLI_NETWORK_ARPTABLE_SET,
	LIBCLI_NETWORK_ARPTABLE_SET_ARP_MAC,
	LIBCLI_NETWORK_ARPTABLE_SET_ARP_INTERFACE,

	/*********** network->ARPTABLE  **************/
	LIBCLI_NETWORK_FLOATIP_SHOW_INFO,
	LIBCLI_NETWORK_FLOATIP_DEL_IP,
	LIBCLI_NETWORK_FLOATIP_ADD_IP,

	/*********** network->arp timeout **********/
	LIBCLI_ARP_TIMEOUT_SHOW_INFO,
	LIBCLI_ARP_TIMEOUT_SET_INFO,
	/*********** certif&crls **************/
	LIBCLI_CERTIF_SHOW_INFO,
	LIBCLI_CERTIF_DELETE_INFO,
	LIBCLI_CRLS_SHOW_INFO,
	LIBCLI_CRLS_DELETE_INFO,



	LIBCLI_SYS_SYSLOG_SERVER_SET,
	LIBCLI_SYS_DATE_SET,
	LIBCLI_SYS_TIME_SET,
	LIBCLI_SYS_HOSTNAME_SET,
	LIBCLI_SYS_SHOW_DATETIME,
	LIBCLI_SYS_SHOW_LICENSE,
	LIBCLI_SYS_SHOW_SERIALNUM,
	LIBCLI_SYS_SHOW_SYSLOG_SERVER_INFO,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL_BIC,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL_CUBIC,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL_HTCP,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL_HYBLA,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL_VEGAS,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL_VENO,
	LIBCLI_SYS_TCP_CONGESTION_CONTROL_WESTWOOD,


	/************** snmp *********************/
	LIBCLI_SNMP_MANAGE_INFO,
	LIBCLI_SNMP_SET_SHOW,
	LIBCLI_SNMP_SET_ENABLE,
	LIBCLI_SNMP_SET_ENABLE_ON,
	LIBCLI_SNMP_SET_ENABLE_OFF,
	LIBCLI_SNMP_SET_TRAP_ENABLE,
	LIBCLI_SNMP_SET_TRAP_ENABLE_ON,
	LIBCLI_SNMP_SET_TRAP_ENABLE_OFF,
	LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PROTOCOL,
	LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PROTOCOL_DES,
	LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PROTOCOL_AES,
	LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PASSWORD,
	LIBCLI_SNMP_SET_TRAP_V3_USERNAME,
	LIBCLI_SNMP_SET_TRAP_V3_PASSWORD,
	LIBCLI_SNMP_SET_TRAP_V3_ENGINEID,
	LIBCLI_SNMP_SET_TRAP_MANAGER,
	LIBCLI_SNMP_SET_AUTHTYPE,
	LIBCLI_SNMP_SET_AUTHTYPE_MD5,
	LIBCLI_SNMP_SET_AUTHTYPE_SHA1,
	LIBCLI_SNMP_SET_COMMUNITY,
	LIBCLI_SNMP_SET_ADD,
	LIBCLI_SNMP_SET_DEL,
	LIBCLI_SNMP_SET_USER,
	LIBCLI_SNMP_SET_USER_ADD,
	LIBCLI_SNMP_SET_USER_DEL,
	LIBCLI_SNMP_SET_NETWORK,
	LIBCLI_SNMP_SET_NETWORK_ADD,
	LIBCLI_SNMP_SET_NETWORK_DEL,

	/************** smtp *********************/
	LIBCLI_SMTP_MANAGE_INFO,
	LIBCLI_SMTP_SET_SHOW,
	LIBCLI_SMTP_SET_ENABLE,
	LIBCLI_SMTP_SET_ENABLE_ON,
	LIBCLI_SMTP_SET_ENABLE_OFF,
	LIBCLI_SMTP_SET_SERVER,
	LIBCLI_SMTP_SET_PORT,
	LIBCLI_SMTP_SET_USERNAME,
	LIBCLI_SMTP_SET_PASSWORD,
	LIBCLI_SMTP_SET_SSL_ENABLE,
	LIBCLI_SMTP_SET_SSL_ENABLE_ON,
	LIBCLI_SMTP_SET_SSL_ENABLE_OFF,
	LIBCLI_SMTP_SET_DESTINATION,
	LIBCLI_SMTP_SET_INTERVAL,

	/************** sysconfig *********************/
	LIBCLI_SYSCONFIG_MANAGE_INFO,
	LIBCLI_SYSCONFIG_LLBENABLE,
	LIBCLI_SYSCONFIG_LLBAGENTENABLE,
	LIBCLI_SYSCONFIG_LLBAGENT_ENABLE_ON,
	LIBCLI_SYSCONFIG_LLBAGENT_ENABLE_OFF,
	LIBCLI_SYSCONFIG_LLBAGENTSADDR,
	LIBCLI_SYSCONFIG_LLBAGENTDADDR,
	LIBCLI_SYSCONFIG_LLBSYSLOGSERVER,
	LIBCLI_SYSCONFIG_SET_ENABLE_ON,
	LIBCLI_SYSCONFIG_SET_ENABLE_OFF,
	LIBCLI_SYSCONFIG_SET_SHOW,
	LIBCLI_SYSCONFIG_SHOW,

	/*********** network->NTPDATE ************/
	LIBCLI_NTPDATE_MANAGE_INFO,
	LIBCLI_NTPDATE_SET_SHOW,
	LIBCLI_NTPDATE_SET_ENABLE,
	LIBCLI_NTPDATE_SET_ENABLE_ON,
	LIBCLI_NTPDATE_SET_ENABLE_OFF,
	LIBCLI_NTPDATE_SET_SERVER,
	LIBCLI_NTPDATE_SET_CYCLE,

	/************** hb **********************/
	LIBCLI_HB_MANAGE_INFO,
	LIBCLI_HB_SET_SHOW,
	LIBCLI_HB_SET_SELF_MONITOR,
	LIBCLI_HB_SET_SELF_MONITOR_ON,
	LIBCLI_HB_SET_SELF_MONITOR_OFF,
	LIBCLI_HB_SET_CONFIG_SYNC,
	LIBCLI_HB_SET_ENABLE,
	LIBCLI_HB_SET_ENABLE_ON,
	LIBCLI_HB_SET_ENABLE_OFF,
	LIBCLI_HB_SET_INTERFACE,
	LIBCLI_HB_SET_ADDIF,
	LIBCLI_HB_SET_DELIF,
	LIBCLI_HB_SET_STATE,
	LIBCLI_HB_SET_STATE_MASTER,
	LIBCLI_HB_SET_STATE_BACKUP,
	LIBCLI_HB_SET_STATE_MASTER_FORCE,
	LIBCLI_HB_SET_STATE_BACKUP_FORCE,
	LIBCLI_HB_SET_VRID,
	LIBCLI_HB_SET_VERIFYCODE,
	LIBCLI_HB_SET_VIPMASK,
	LIBCLI_HB_CONN_TABLE,
	LIBCLI_HB_CONN_TABLE_SYN,
	LIBCLI_HB_CONN_TABLE_NOSYN,

	/*************** vlan *****************/
	LIBCLI_VLAN_ADD_INFO,
	LIBCLI_VLAN_ADD_INTERFACE,
	LIBCLI_VLAN_SHOW_INFO,
	LIBCLI_VLAN_MANAGE_INFO,
	LIBCLI_VLAN_DELETE_INFO,
	LIBCLI_VLAN_SET_ADD,
	LIBCLI_VLAN_SET_DELETE,
	LIBCLI_VLAN_SET_VLANID,
	LIBCLI_VLAN_SET_WEB_ENABLE,
	LIBCLI_VLAN_SET_WEB_ENABLE_ON,
	LIBCLI_VLAN_SET_WEB_ENABLE_OFF,
	LIBCLI_VLAN_SET_SSH_ENABLE,
	LIBCLI_VLAN_SET_SSH_ENABLE_ON,
	LIBCLI_VLAN_SET_SSH_ENABLE_OFF,


	LIBCLI_VLAN_SET_GSLB_ENABLE,
	LIBCLI_VLAN_SET_GSLB_ENABLE_ON,
	LIBCLI_VLAN_SET_GSLB_ENABLE_OFF,

	LIBCLI_VLAN_SET_STP_ENABLE,
	LIBCLI_VLAN_SET_STP_ENABLE_ON,
	LIBCLI_VLAN_SET_STP_ENABLE_OFF,
	LIBCLI_VLAN_SET_STP_PROTOCOL,
	LIBCLI_VLAN_SET_STP_PROTOCOL_STP,
	LIBCLI_VLAN_SET_STP_PROTOCOL_RSTP,
	LIBCLI_VLAN_SET_STP_PRIORITY,
	LIBCLI_VLAN_SET_STP_HELLOTIME,
	LIBCLI_VLAN_SET_STP_MAXAGE,
	LIBCLI_VLAN_SET_STP_FWD_DELAY,


	/*************** protocol *****************/
	LIBCLI_PROTOCOL_TCP,
	LIBCLI_PROTOCOL_FAST_TCP,
	LIBCLI_PROTOCOL_UDP,
	LIBCLI_PROTOCOL_HTTP,
	LIBCLI_PROTOCOL_FTP,
	LIBCLI_PROTOCOL_HTTPS,
	LIBCLI_PROTOCOL_DNS,
	LIBCLI_PROTOCOL_SMTP,
/**---------------------**/
	LIBCLI_PROTOCOL_HTTP_ECV,
	LIBCLI_PROTOCOL_HTTPS_ECV,
	LIBCLI_PROTOCOL_ICMP_GW,
/**---------------------**/
	LIBCLI_PROTOCOL_SSLBRIDGE,
	LIBCLI_PROTOCOL_RDPBRIDGE,
	LIBCLI_PROTOCOL_ICMP,
	LIBCLI_PROTOCOL_DHCP,
	LIBCLI_PROTOCOL_ANY,

	/*************** cache *****************/
	LIBCLI_CACHE_OBJSIZE,
	LIBCLI_CACHE_OBJNUM,
	LIBCLI_CACHE_EXPIRE,
	// LIBCLI_CACHE_INACTIVE,
	LIBCLI_CACHE_RAMSIZE,
	LIBCLI_CACHE_DISKSIZE,

	/*************** SSL *****************/
	LIBCLI_SSL_SHOW_CERTIFICATE,
	LIBCLI_SSL_SHOW_CRLS,
	LIBCLI_SSL_ADD_CLIENT_CERTIFICATE,
	LIBCLI_SSL_ADD_SERVER_CERTIFICATE,
	LIBCLI_SSL_ADD_CRLS,
	LIBCLI_SSL_DELETE_CERTIFICATE,
	LIBCLI_SSL_DELETE_CRLS,
	LIBCLI_SSL_OFFLOADING,
	LIBCLI_SSL_OFFLOADING_ON,
	LIBCLI_SSL_OFFLOADING_OFF,
	LIBCLI_SSL_CERTIFICATE,
	LIBCLI_SSL_CLIENT_CERTIFICATE,
	LIBCLI_SSL_VERIFY_CLIENT,
	LIBCLI_SSL_VERIFY_CLIENT_ON,
	LIBCLI_SSL_VERIFY_CLIENT_OFF,
	LIBCLI_SSL_PROTOCOL,
	LIBCLI_SSL_PROTOCOL_SSLV2,
	LIBCLI_SSL_PROTOCOL_SSLV3,
	LIBCLI_SSL_PROTOCOL_TLSV1,
	LIBCLI_SSL_VSERVER_CRL,

	/*********** CLI USERS *************/
	LIBCLI_CLIUSERS_SET_PASSWD,

	/*********** CLI MGMT *************/
	LIBCLI_MGMT_MANAGE_INFO,
/************firewall*********************/
	LIBCLI_FIREWALL_ADD_INFO,
	LIBCLI_FIREWALL_SHOW_INFO,
	LIBCLI_FIREWALL_DELETE_INFO,
	LIBCLI_FIREWALL_MANAGE_INFO,
	LIBCLI_FIREWALL_SET_ENABLE,
	LIBCLI_FIREWALL_SET_ENABLE_ON,
	LIBCLI_FIREWALL_SET_ENABLE_OFF,
	LIBCLI_FIREWALL_SET_TYPE,
	LIBCLI_FIREWALL_SET_TYPE_BLACK,
	LIBCLI_FIREWALL_SET_TYPE_WHITE,
	LIBCLI_FIREWALL_ADD_IPLIST,
	LIBCLI_FIREWALL_DELETE_IPLIST,
	LIBCLI_FIREWALL_IPLIST_PROTOCOL,
	
	/********GSLB listener*************/
	LIBCLI_GSLB_LISTENER_ADD_INFO,
	LIBCLI_GSLB_LISTENER_SET_PORT,
	LIBCLI_GSLB_LISTENER_SET_PROTOCOL,
	LIBCLI_GSLB_LISTENER_SHOW_INFO,
	LIBCLI_GSLB_LISTENER_DELETE_INFO,
	LIBCLI_GSLB_LISTENER_MANAGE_INFO,
	/********GSLB vserver*************/
	LIBCLI_GSLB_VSERVER_ADD_INFO,
	LIBCLI_GSLB_VSERVER_ADD_SCHEDULER_INFO,
	LIBCLI_GSLB_VSERVER_SET_IP,
	LIBCLI_GSLB_VSERVER_SET_ENABLE,
	LIBCLI_GSLB_VSERVER_SET_ENABLE_OFF,
	LIBCLI_GSLB_VSERVER_SET_ENABLE_ON,
	LIBCLI_GSLB_VSERVER_SET_TTL,
	LIBCLI_GSLB_VSERVER_SET_MASTER_SCHEDULE,
	LIBCLI_GSLB_VSERVER_SET_SLAVE_SCHEDULE,
	LIBCLI_GSLB_VSERVER_SET_FINAL_SCHEDULE,
	LIBCLI_GSLB_VSERVER_SET_POOLNAME,
	LIBCLI_GSLB_VSERVER_SHOW_INFO,
	LIBCLI_GSLB_VSERVER_DELETE_INFO,
	LIBCLI_GSLB_VSERVER_MANAGE_INFO,
	LIBCLI_GSLB_VSERVER_SET_SCHED_RR,
	LIBCLI_GSLB_VSERVER_SET_SCHED_WRR,
	LIBCLI_GSLB_VSERVER_SET_SCHED_TOPOLOGY,
	LIBCLI_GSLB_VSERVER_SET_SCHED_GA,
	LIBCLI_GSLB_VSERVER_SET_SCHED_RETURN_TO_DNS,
	LIBCLI_GSLB_VSERVER_SET_SCHED_RTT,
	LIBCLI_GSLB_VSERVER_SET_SCHED_LEASTCONNECTION,
	LIBCLI_GSLB_VSERVER_SET_SCHED_LEASTTHROUGHT,
	LIBCLI_GSLB_VSERVER_SET_SCHED_LEASTLOAD,

	LIBCLI_GSLB_VSERVER_MULTIIPADDR_ENABLE,
	LIBCLI_GSLB_VSERVER_MULTIIPADDR_ENABLE_ON,
	LIBCLI_GSLB_VSERVER_MULTIIPADDR_ENABLE_OFF,
	LIBCLI_GSLB_VSERVER_LASTSORT_IPADDR,

	LIBCLI_GSLB_VSERVER_SET_TIMEOUT,
	LIBCLI_GSLB_VSERVER_PERSISTENT_ENABLE,
	LIBCLI_GSLB_VSERVER_PERSISTENT_ENABLE_ON,
	LIBCLI_GSLB_VSERVER_PERSISTENT_ENABLE_OFF,
	/********GSLB site*************/
	LIBCLI_GSLB_SITE_ADD_INFO,
	LIBCLI_GSLB_SITE_SET_IP,
	LIBCLI_GSLB_SITE_SET_USERNAME,
	LIBCLI_GSLB_SITE_SET_PASSWORD,
	LIBCLI_GSLB_SITE_SET_TYPE,
	LIBCLI_GSLB_SITE_SHOW_INFO,
	LIBCLI_GSLB_SITE_DELETE_INFO,
	LIBCLI_GSLB_SITE_MANAGE_INFO,
	LIBCLI_GSLB_SITE_SET_TYPE_GSLB,
	LIBCLI_GSLB_SITE_SET_TYPE_SLB,
	/******GSLB pool*****************/
	LIBCLI_GSLB_POOL_ADD_INFO,
	LIBCLI_GSLB_POOL_SHOW_INFO,
	LIBCLI_GSLB_POOL_DELETE_INFO,
	LIBCLI_GSLB_POOL_MANAGE_INFO,
	LIBCLI_GSLB_POOL_SET_HEALTHCHECK,
	/******GSLB Rserver*****************/
	LIBCLI_GSLB_RSERVER_ADD_INFO,
	LIBCLI_GSLB_RSERVER_MANAGE_INFO,
	LIBCLI_GSLB_RSERVER_SHOW_INFO,
	LIBCLI_GSLB_RSERVER_DELETE_INFO,
	LIBCLI_GSLB_RSERVER_SET_SITENAME,
	LIBCLI_GSLB_RSERVER_SET_WEIGHT,
	LIBCLI_GSLB_RSERVER_SET_HEALTHCHECK,
	LIBCLI_GSLB_RSERVER_SET_ENABLE,
	LIBCLI_GSLB_RSERVER_SET_MAXREQ,
	LIBCLI_GSLB_RSERVER_SET_TYPE,
	LIBCLI_GSLB_RSERVER_SET_VSNAME,
	LIBCLI_GSLB_RSERVER_SET_VSNAME_IP,
	LIBCLI_GSLB_RSERVER_GET_VSLIST,
	LIBCLI_GSLB_RSERVER_SET_ORDER,
	/*BIN9*/
	LIBCLI_BIND9_ADD_INFO,
	LIBCLI_BIND9_ADD_CHILD_INFO,
	LIBCLI_BIND9_DEL_CHILD_INFO,
	LIBCLI_BIND9_MANAGE_INFO,
	LIBCLI_BIND9_SHOW_INFO,
	LIBCLI_BIND9_DELETE_INFO,
	LIBCLI_BIND9_SET_NAME,
	LIBCLI_BIND9_SET_TTL,
	LIBCLI_BIND9_SET_VIEW,
	LIBCLI_BIND9_SET_ALLOW_RECURSION_INFO,
	LIBCLI_BIND9_SET_ALLOW_RECURSION_INFO_ON,
	LIBCLI_BIND9_SET_ALLOW_RECURSION_INFO_OFF,
	
	/*BIND9_RECORD*/
	LIBCLI_BIND9_RECORD_ADD_INFO,
	LIBCLI_BIND9_RECORD_ADD_SOA_INFO,
	LIBCLI_BIND9_RECORD_MANAGE_INFO,
	LIBCLI_BIND9_RECORD_SHOW_INFO,
	LIBCLI_BIND9_RECORD_DELETE_INFO,
	LIBCLI_BIND9_RECORD_SET_NAME,
	LIBCLI_BIND9_RECORD_SET_TYPE,
	LIBCLI_BIND9_RECORD_SET_PORT,
	LIBCLI_BIND9_RECORD_SET_VALUE,
	/*BIND9_ACL*/
	LIBCLI_BIND9_ACL_ADD_INFO,
	LIBCLI_BIND9_ACL_MANAGE_INFO,
	LIBCLI_BIND9_ACL_SHOW_INFO,
	LIBCLI_BIND9_ACL_DELETE_INFO,
/***bind9 soa record*******/
	LIBCLI_BIND9_SOA_RECORD_SET_MAIL,
	LIBCLI_BIND9_SOA_RECORD_SET_REFRESH,
	LIBCLI_BIND9_SOA_RECORD_SET_RETRY,
	LIBCLI_BIND9_SOA_RECORD_SET_SERIAL,
	LIBCLI_BIND9_SOA_RECORD_SET_TTL,
	LIBCLI_BIND9_SOA_RECORD_SET_EXPIRE,
	/*GROUP*/
	LIBCLI_GSLB_GROUP_SHOW_INFO,
	LIBCLI_GSLB_GROUP_MANAGE_INFO,
	LIBCLI_GSLB_GROUP_DELETE_INFO,
	LIBCLI_GSLB_GROUP_ADD_INFO,
	LIBCLI_GSLB_GROUP_ADD_DEVICE_INFO,
	LIBCLI_GSLB_GROUP_DELETE_DEVICE_INFO,
/************topology********************/
	LIBCLI_TOPOLOGY_SHOW_INFO,
	LIBCLI_TOPOLOGY_SET_INFO,
	LIBCLI_TOPOLOGY_ADD_INFO,
	LIBCLI_TOPOLOGY_DELETE_INFO,
	/*tp_node*/
	
	LIBCLI_TP_NODE_ADD_INFO,
	LIBCLI_TP_NODE_MANAGE_INFO,
	LIBCLI_TP_NODE_SHOW_INFO,
	LIBCLI_TP_NODE_DELETE_INFO,
	LIBCLI_TP_NODE_SET_NETWORK,
	LIBCLI_TP_NODE_SET_AREA,
	LIBCLI_TP_NODE_SET_CARRIER,
/*******tp_policy******************/	
	
	LIBCLI_TP_POLICY_SET_POLICY,
	LIBCLI_TP_POLICY_SET_NETWORK,
	LIBCLI_TP_POLICY_SET_POLICY_SELF,
	LIBCLI_TP_POLICY_SET_POLICY_NETWORK,
	LIBCLI_TP_POLICY_SHOW_INFO,//add show
	LIBCLI_TP_POLICY_DELETE_INFO,
	LIBCLI_TP_POLICY_MANAGE_INFO,//add manage
/*******llb_pool**********/
	LIBCLI_LLB_POOL_ADD_INFO,
	LIBCLI_LLB_POOL_SHOW_INFO,
	LIBCLI_LLB_POOL_DELETE_INFO,
 	LIBCLI_LLB_POOL_MANAGE_INFO,
	LIBCLI_LLB_POOL_SET_HEALTHCHECK,
	LIBCLI_LLB_POOL_SET_HEALTHCHECK_PING,
	LIBCLI_LLB_POOL_SET_HEALTHCHECK_PING_GW,
	LIBCLI_LLB_POOL_SET_REALSERVER,
	LIBCLI_LLB_POOL_SET_RSERVER_SHOW,
/*******llb_rserver**********/

	LIBCLI_LLB_RSERVER_ADD_INFO,
	LIBCLI_LLB_RSERVER_SHOW_INFO,
 	LIBCLI_LLB_RSERVER_MANAGE_INFO,
	LIBCLI_LLB_RSERVER_DELETE_INFO,
	LIBCLI_LLB_RSERVER_SET_HEALTHCHECK,
	LIBCLI_LLB_RSERVER_SET_BANDWIDTH,
	LIBCLI_LLB_RSERVER_SET_WEIGHT,
	LIBCLI_LLB_RSERVER_SET_ENABLE,
	LIBCLI_LLB_RSERVER_SET_ENABLE_ON,
	LIBCLI_LLB_RSERVER_SET_ENABLE_OFF,
	LIBCLI_LLB_RSERVER_SET_ORDER,

/*******llb_vserver**********/

	LIBCLI_LLB_VSERVER_ADD_INFO,
	LIBCLI_LLB_VSERVER_SHOW_INFO,
	LIBCLI_LLB_VSERVER_DELETE_INFO,
 	LIBCLI_LLB_VSERVER_MANAGE_INFO,
	LIBCLI_LLB_VSERVER_SET_PROTOCOL,
	LIBCLI_LLB_VSERVER_SET_ENABLE,
	LIBCLI_LLB_VSERVER_SET_ENABLE_ON,
	LIBCLI_LLB_VSERVER_SET_ENABLE_OFF,
	LIBCLI_LLB_VSERVER_SET_NEXT_IP,
	LIBCLI_LLB_VSERVER_SET_NEXT_PORT,
	LIBCLI_LLB_VSERVER_SET_POOL,
	LIBCLI_LLB_VSERVER_ADD_SCHEDULER,
	LIBCLI_LLB_VSERVER_SET_MASTER_SCHEDULER,
	LIBCLI_LLB_VSERVER_SET_SLAVE_SCHEDULER, 
	LIBCLI_LLB_VSERVER_SET_FINAL_SCHEDULER,
	LIBCLI_LLB_VSERVER_SET_TIMEOUT,
	LIBCLI_LLB_VSERVER_SET_RTT_TIMEOUT,
	LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE,
	LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE_OFF,
	LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE_IP_ON,
	LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE_SOURCE_DEST_IP_ON,
	LIBCLI_LLB_VSERVER_ADD_CONF,
	LIBCLI_LLB_VSERVER_ADD_SOURCEIP,
	LIBCLI_LLB_VSERVER_DEL_CONF,
	LIBCLI_LLB_VSERVER_DEL_SOURCEIP,
	LIBCLI_LLB_VSERVER_SNAT_ENABLE,
	LIBCLI_LLB_VSERVER_SNAT_ENABLE_ON,
	LIBCLI_LLB_VSERVER_SNAT_ENABLE_OFF,
	/*********** CLI VMWARE ************/
  LIBCLI_VMWARE_CONNECTION_LOW,
  LIBCLI_VMWARE_CONNECTION_HIGH,

  LIBCLI_VMWARE_NEW_CONNECTION_LOW,
  LIBCLI_VMWARE_NEW_CONNECTION_HIGH,

  LIBCLI_VMWARE_BANDWIDTH_LOW,
  LIBCLI_VMWARE_BANDWIDTH_HIGH,

  LIBCLI_VMWARE_VM_ENABLE,
  LIBCLI_VMWARE_VM_ENABLE_ON,
  LIBCLI_VMWARE_VM_ENABLE_OFF,

  /*********** CLI VCENTER ***********/
  LIBCLI_VCENTER_SHOW,
  LIBCLI_VCENTER_ADD,
  LIBCLI_VCENTER_MANAGE,
  LIBCLI_VCENTER_DEL,
  LIBCLI_VCENTER_TYPE,
  LIBCLI_VCENTER_TYPE_XENSERVER,
  LIBCLI_VCENTER_TYPE_VCENTER,
  LIBCLI_VCENTER_SERVER,
  LIBCLI_VCENTER_USERNAME,
  LIBCLI_VCENTER_PASSWORD,
  LIBCLI_VCENTER_DATACENTER_SHOW,

  /*********** CLI LLB SNAT ***********/
  LIBCLI_LLB_SNAT_DELETE_INFO,
  LIBCLI_LLB_SNAT_ADD_INFO,
  LIBCLI_LLB_SNAT_NAME_INFO,
  LIBCLI_LLB_SNAT_SET_SRCFROM_INFO,
  LIBCLI_LLB_SNAT_SET_SRCTO_INFO,
  LIBCLI_LLB_SNAT_SET_TYPE_INFO,
  LIBCLI_LLB_SNAT_SET_TYPE_SNAT_INFO,
  LIBCLI_LLB_SNAT_SET_TYPE_NONAT_INFO,
  LIBCLI_LLB_SNAT_SET_DESTFROM_INFO,
  LIBCLI_LLB_SNAT_SET_DESTTO_INFO,
  LIBCLI_LLB_SNAT_SET_BINDTO_INFO,
  LIBCLI_LLB_SNAT_SET_SCHEDULE_INFO,
  LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_IP_RR_INFO,
  LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_CONN_RR_INFO,
  LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_LC_INFO,
  LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_SRC_PORT_INFO,
  LIBCLI_LLB_SNAT_SHOW_INFO,

  /*********** snmpwalk for real server ***********/
  LIBCLI_SNMPWALK_MANAGE_INFO,
  LIBCLI_SNMPWALK_SET_ADD_NETWORK,
  LIBCLI_SNMPWALK_SET_DEL_NETWARK,
  LIBCLI_SNMPWALK_SET_SHOW,

  /******* snmpwalk set fied of real server *******/
  LIBCLI_RSERVER_SNMPWALK_CHECK,
  LIBCLI_RSERVER_SNMPWALK_VERSION,
  LIBCLI_RSERVER_SNMPWALK_SECURELEVEL,
  LIBCLI_RSERVER_SNMPWALK_AUTHPROTOCOL,
  LIBCLI_RSERVER_SNMPWALK_USER,
  LIBCLI_RSERVER_SNMPWALK_PASSWORD,
  LIBCLI_RSERVER_SNMPWALK_CPU,
  LIBCLI_RSERVER_SNMPWALK_MEMORY,
};





#endif
