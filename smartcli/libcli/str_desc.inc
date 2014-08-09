
#include "str_desc.h"



struct str_desc {
	const char *en;
	const char *cn;
};



static struct str_desc str_desc [] = {

	[ LIBCLI_COMMON_LANGUAGE_SET ] = {
		.en = "Set Language.",
		.cn = "显示语言设置",
	}, 

	[ LIBCLI_COMMON_LANGUAGE_EN_US ] = {
		.en = "English",
		.cn = "英文",
	},

	[ LIBCLI_COMMON_LANGUAGE_ZH_CN ] = {
		.en = "Simple Chinese",
		.cn = "简体中文",
	},

	[ LIBCLI_COMMON_SYSTEM_INFO ] = {
		.en = "Turn on privileged commands",
		.cn = "进入特权模式",
	},

	[ LIBCLI_COMMON_EXIT_INFO ] = {
		.en = "Exit from current direcotry.",
		.cn = "返回上级目录",
	},

	[ LIBCLI_COMMON_HELP_INFO ] = {
		.en = "Show available commands",
		.cn = "帮助",
	},

	[ LIBCLI_COMMON_QUIT_INFO ] = {
		.en = "Disconnect",
		.cn = "退出CLI系统",
	},

	[ LIBCLI_COMMON_HISTORY_INFO ] = {
		.en = "Show a list of previously run commands",
		.cn = "显示历史命令",
	},

	[ LIBCLI_COMMON_PWD_INFO ] = {
		.en = "Show command the entire path name",
		.cn = "显示命令整个路径名",
	},

	[ LIBCLI_COMMON_SHOW_INFO ] = {
		.en = "Show something",
		.cn = "显示可用的信息",
	},

	[ LIBCLI_COMMON_ADD_INFO ] ={
		.en = "Add something",
		.cn = "添加相关的信息",
	},

	[ LIBCLI_COMMON_DELETE_INFO ] ={
		.en = "Delete something",
		.cn = "删除相关的信息",
	},

	[ LIBCLI_COMMON_MANAGE_INFO ] ={
		.en = "Set something",
		.cn = "设置相关的信息",
	},

	[ LIBCLI_COMMON_SET_GSLB ] = {
		.en = "Manage GSLB",
		.cn = "全局负载均衡管理",
	},
	[ LIBCLI_COMMON_SET_LLB ] = {
		.en = "Manage LLB",
		.cn = "链路负载均衡管理",
	},
	[ LIBCLI_COMMON_SET_SLB ] = {
		.en = "Manage SLB",
		.cn = "虚拟服务器管理",
	},

	[ LIBCLI_COMMON_SET_BIND9 ] = {
		.en = "Manage BIND9",
		.cn = "BIND9服务管理",
	},

	[ LIBCLI_COMMON_SET_TOPOLOGY ] = {
		.en = "Manage Topology",
		.cn = "地理拓扑管理",
	},



	[ LIBCLI_ADMIN_RESET_PASSWD ] ={
		.en = "Change the password of wsadmin",
		.cn = "修改wsadmin的密码",
	},
	[ LIBCLI_SYSTEM_TIME ] = {
		.en = "Show time",
		.cn = "查看系统时间",
	},
	[ LIBCLI_SYSTEM_VERSION ] = {
		.en = "Show version",
		.cn = "查看系统版本",
	},
	[ LIBCLI_SYSTEM_CPU ] = {
		.en = "Show cpu information",
		.cn = "显示CPU信息",
	},
	[ LIBCLI_SYSTEM_MEMORY ] = {
		.en = "Show memory information",
		.cn = "显示内存信息",
	},
	[ LIBCLI_SYSTEM_HARDDISK ] = {
		.en = "Show harddisk information",
		.cn = "显示磁盘信息",
	},

	[ LIBCLI_SYSTEM_REBOOT ] = {
		.en = "Reboot the host",
		.cn = "重启主机",
	},

	[ LIBCLI_SYSTEM_POWEROFF ] = {
		.en = "Power off the host",
		.cn = "关闭主机电源",
	},

	[ LIBCLI_SYSTEM_RESTORE ] = {
		.en = "Restore the host",
		.cn = "主机休眠",
	},

	[ LIBCLI_SYSTEM_SHELL ] = {
		.en = "Open shell terminial",
		.cn = "打开shell终端",
	},

	[ LIBCLI_UNIX_DIAGNOSIS ] = {
		.en = "Linux diagnosis command",
		.cn = "Linux 诊断 命令",
	},

	[ LIBCLI_UNIX_PING ] = {
		.en = "Linux Ping command",
		.cn = "Linux Ping 命令",
	},

	[ LIBCLI_UNIX_TRACEROUTE ] = {
		.en = "Linux traceroute command",
		.cn = "Linux traceroute 命令",
	},

	[ LIBCLI_UNIX_NETSTAT ] = {
		.en = "Linux netstat command",
		.cn = "Linux netstat 命令",
	},

	[ LIBCLI_UNIX_SAR ] = {
		.en = "Linux sar command",
		.cn = "Linux sar 命令",
	},

	[ LIBCLI_UNIX_IOSTAT ] = {
		.en = "Linux iostat command",
		.cn = "Linux iostat command",
	},


	[LIBCLI_ADD_IP] = {
		.en = "Add ip address",
		.cn = "添加IP地址",
	},

	[LIBCLI_DEL_IP] = {
		.en = "Delete ip address",
		.cn = "删除IP地址",
	},


	[ LIBCLI_SYSTEM_UNDER_GSLB_SHOW_INFO] = {
		.en = "Show GSLB Control information",
		.cn = "显示SLB是否受控于GSLB相关信息",
	},

	[ LIBCLI_SYSTEM_UNDER_GSLB_MANAGE_INFO] = {
		.en = "Set GSLB Control information",
		.cn = "设置 GSLB对 SLB的控制配置信息",
	},

	[ LIBCLI_SYSTEM_UNDER_GSLB_SET_PASSWORD ] = {
		.en = "Set GSLB Control Password",
		.cn = "设置Gslb 认证密码",
	},
	[ LIBCLI_SYSTEM_UNDER_GSLB_ENABLE ] = {
		.en = "Set GSLB Control SLB enable",
		.cn = "设置SLB 是否受控于GSLB",
	},
	[ LIBCLI_SYSTEM_UNDER_GSLB_ENABLE_ON ] = {
		.en = "Set GSLB Control SLB Enable on",
		.cn = "开启GSLB对SLB的控制",
	},
	[ LIBCLI_SYSTEM_UNDER_GSLB_ENABLE_OFF ] = {
		.en = "Set GSLB Control SLB Enable off",
		.cn = "GSLB 对 SLB监控不可用",
	},


	[LIBCLI_ADD_INTERFACE] = {
		.en = "Add interface",
		.cn = "添加接口",
	},

	[LIBCLI_DEL_INTERFACE] = {
		.en = "Delete interface",
		.cn = "删除接口",
	},
// add --------------------
	[ LIBCLI_BIND9_RECORD_TYPE_A ] = {
		.en = "Set BIND9 Retcrd type A",
		.cn = "设置 BIND9 A 类型记录",
	},
	
	[ LIBCLI_BIND9_RECORD_TYPE_SRV ] = {
		.en = "Set BIND9 Retcrd type SRV",
		.cn = "设置 BIND9 SRV 类型记录",
	},
	
	[ LIBCLI_BIND9_RECORD_TYPE_AAAA ] = {
		.en = "Set BIND9 Retcrd type AAAA",
		.cn = "设置 BIND9 AAAA 类型记录",
	},
	[ LIBCLI_BIND9_RECORD_TYPE_MX ] = {
		.en = "Set BIND9 Retcrd type MX",
		.cn = "设置 BIND9 MX 类型记录",
	},
	[ LIBCLI_BIND9_RECORD_TYPE_CNAME ] = {
		.en = "Set BIND9 Retcrd type CNAME",
		.cn = "设置 BIND9 CNAME 类型记录",
	},
	[ LIBCLI_BIND9_RECORD_TYPE_TXT ] = {
		.en = "Set BIND9 Retcrd type TXT",
		.cn = "设置 BIND9 TXT 类型记录",
	},

	[ LIBCLI_BIND9_RECORD_TYPE_NS ] = {
		.en = "Set BIND9 Retcrd type NS",
		.cn = "设置 BIND9 NS 类型记录",
	},
	[ LIBCLI_BIND9_RECORD_TYPE_PTR ] = {
		.en = "Set BIND9 Retcrd type PTR",
		.cn = "设置 BIND9 PTR 类型记录",
	},
//end --------------------------
	[ LIBCLI_VSERVER_ADD_INFO ] = { 
		.en = "Add Vserver",
		.cn = "添加Vserver",
	},

	[ LIBCLI_VSERVER_SHOW_INFO ] = {
		.en = "Show Vserver Information",
		.cn = "显示Vserver配置信息",
	},

	[ LIBCLI_VSERVER_SHOW_IPADDR_INFO ] = {
		.en = "Show all IP address of Vlan",
		.cn = "显示所有VLAN中的IP地址信息",
	},



	[ LIBCLI_VSERVER_MANAGE_INFO ] = {
		.en = "Manage Vserver",
		.cn = "管理Vserver",
	},

	[ LIBCLI_VSERVER_DELETE_INFO ] = {
		.en = "Delete Vserver",
		.cn = "删除Vserver",
	},

	[ LIBCLI_VSERVER_SET_ADDRESS] = {
		.en = "Set Vserver ip address",
		.cn = "设置的Vserver的IP地址",
	},

	[ LIBCLI_VSERVER_SET_WEIGHT] = {
		.en = "Set GSLB Rserver Weight",
		.cn = "设置的Vserver的权重",
	},


	[ LIBCLI_VSERVER_SET_SNMP] = {
		.en = "Set SLB snmpwalk argemet",
		.cn = "设置SNMPWALK参数",
	},

	[ LIBCLI_VSERVER_SET_PROTOCOL ] = {
		.en = "Set Vserver protocol",
		.cn = "设置Vserver的网络协议",
	},

	[ LIBCLI_VSERVER_SET_ENABLE ] = {
		.en = "Set if this Vserver is enabled",
		.cn = "设置Vserver是否启用",
	},

	[ LIBCLI_VSERVER_SET_ENABLE_ON ] = {
		.en = "Set this Vserver is enabled",
		.cn = "设置Vserver为启用",
	},

	[ LIBCLI_VSERVER_SET_ENABLE_OFF ] = {
		.en = "Set if this Vserver is enabled",
		.cn = "设置Vserver为禁用",
	},


	[ LIBCLI_VSERVER_SET_SCHED_ALG ] = {
		.en = "Configuring the AppPool Sched Algorithms",
		.cn = "配置AppPool的Sched的算法",
	},

	[ LIBCLI_VSERVER_SET_SCHED_RR ] {
		.en = "Round Robin",
		.cn = "轮询",
	},

	[ LIBCLI_VSERVER_SET_SCHED_WRR ] {
		.en = "Weighted Round Robin",
		.cn = "加权轮询",
	},

	[ LIBCLI_VSERVER_SET_SCHED_LC ] {
		.en = "Least Connections",
		.cn = "最少链接",
	},

	[ LIBCLI_VSERVER_SET_SCHED_WLC ] {
		.en = "Weighted Least Connections",
		.cn = "加权最少链接",
	},

	[ LIBCLI_VSERVER_SET_SCHED_HASHIP ] {
		.en = "IP Hashing",
		.cn = "IP散列",
	},

	[ LIBCLI_VSERVER_SET_SCHED_HASHURL ] {
		.en = "URL Hashing",
		.cn = "URL散列",
	},

	[ LIBCLI_VSERVER_SET_SCHED_FAIR ] {
		.en = "The Fastest response time",
		.cn = "最快响应时间",
	},

	[ LIBCLI_VSERVER_SET_SCHED_LLCR ] {
		.en = "Locality-Based Least Connections with Replication",
		.cn = "带复制的基于局部性最少链接",
	},

	[ LIBCLI_VSERVER_SET_SCHED_SH ] {
		.en = "Source Hashing",
		.cn = "源地址散列",
	},

	[ LIBCLI_VSERVER_SET_SCHED_SED ] {
		.en = "Shortest Expected Delay",
		.cn = "最短期望延迟",
	},

	[ LIBCLI_VSERVER_SET_SCHED_NQ ] {
		.en = "Never Queue",
		.cn = "无须队列等待",
	},

	[ LIBCLI_VSERVER_SET_SCHED_LBLC ] {
		.en = "Locality-Based Least Connections",
		.cn = "基于局部性的最少链接",
	},

	[ LIBCLI_VSERVER_SET_SCHED_LBLCR ] {
		.en = "Locality-Based Least Connections with Replication",
		.cn = "带复制的基于局部性最少链接",
	},

	[ LIBCLI_VSERVER_SET_SCHED_COOKIE ] {
		.en = "Cookie",
		.cn = "Cookie",
	},



	[ LIBCLI_VSERVER_SET_TRANSPARENT ] = {
		.en = "Set if this Vserver is transparent proxy",
		.cn = "设置Vserver是否为透明代理服务器",
	},

	[ LIBCLI_VSERVER_SET_TRANSPARENT_ON ] = {
		.en = "Set this Vserver is transparent proxy",
		.cn = "设置Vserver为透明代理服务器",
	},

	[ LIBCLI_VSERVER_SET_TRANSPARENT_OFF ] = {
		.en = "Set this Vserver is not transparent proxy",
		.cn = "设置Vserver不是透明代理服务器",
	},

	[ LIBCLI_VSERVER_SET_CONTENTSWITCH ] = {
		.en = "Set if contentswitch is enabled",
		.cn = "设置Contentswitch是否启用",
	},

	[ LIBCLI_VSERVER_SET_CONTENTSWITCH_ON ] = {
		.en = "Set this contentswitch is enabled",
		.cn = "设置Contentswitch为启用",
	},

	[ LIBCLI_VSERVER_SET_CONTENTSWITCH_OFF ] = {
		.en = "Set if contentswitch is disabled",
		.cn = "设置Contentswitch为禁用",
	},

	[ LIBCLI_VSERVER_SET_XFORWARDEDFOR ] = {
		.en = "Set if x-forward-for is enabled",
		.cn = "设置Vserver的x-forward-for是否启用",
	},


	[ LIBCLI_VSERVER_SET_XFORWARDEDFOR_ON ] = {
		.en = "Set x-forward-for is enabled",
		.cn = "设置Vserver的x-forward-for为启用",
	},

	[ LIBCLI_VSERVER_SET_XFORWARDEDFOR_OFF ] = {
		.en = "Set x-forward-for is disabled",
		.cn = "设置Vserver的x-forward-for为禁用",
	},


	[ LIBCLI_VSERVER_SET_RFC2616CHECK ] = {
		.en = "Set if rfc2616-check is enabled",
		.cn = "设置Vserver的rfc2616-check是否启用",
	},

	[ LIBCLI_VSERVER_SET_RFC2616CHECK_ON ] = {
		.en = "Set rfc2616-check is enabled",
		.cn = "设置Vserver的rfc2616-check为启用",
	},

	[ LIBCLI_VSERVER_SET_RFC2616CHECK_OFF ] = {
		.en = "Set if rfc2616-check is disabled",
		.cn = "设置Vserver的rfc2616-check为禁用",
	},

	[ LIBCLI_VSERVER_SET_CONNREUSE ] = {
		.en = "Set if connreuse is enabled",
		.cn = "设置Connreuse是否启用",
	},

	[ LIBCLI_VSERVER_SET_CONNREUSE_ON ] = {
		.en = "Set connreuse is enabled",
		.cn = "设置Connreuse为启用",
	},


	[ LIBCLI_VSERVER_SET_CONNREUSE_OFF ] = {
		.en = "Set connreuse is enabled",
		.cn = "设置Connreuse为禁用",
	},

	[ LIBCLI_VSERVER_SET_ADD_RULE ] = {
		.en = "Add SmartRule to Vserver",
		.cn = "向虚拟服务器中添加SmartRule",
	},

	[ LIBCLI_VSERVER_SET_DEL_RULE ] = {
		.en = "Delete SmartRule from Vserver",
		.cn = "从虚拟服务器中删除SmartRule",
	},
	
	[ LIBCLI_VSERVER_SET_RULE_UP ] = {
		.en = "Set current rule up",
		.cn = "将当前规则向上",
	},

	[ LIBCLI_VSERVER_SET_RULE_DOWN ] = {
		.en = "Set current rule down",
		.cn = "将当前规则向下",
	},

	[ LIBCLI_VSERVER_SET_RULE_TOP ] = {
		.en = "Set current rule to top",
		.cn = "将当前规则置顶",
	},

	[ LIBCLI_VSERVER_SET_RULE_BOTTOM ] = {
		.en = "Set current rule to bottom",
		.cn = "将当前规则置底",
	},

	[ LIBCLI_VSERVER_SET_SET_RULE ] = {
		.en = "Set the order of SmartRule in Vserver",
		.cn = "设置虚拟服务器中SmartRule的顺序",
	},

	[ LIBCLI_VSERVER_SET_RULE_NAME ] = {
		.en = "Set the order of SmartRules",
		.cn = "设置SmartRules的顺序",
	},

	[ LIBCLI_VSERVER_SET_POOL ] = {
		.en = "Set the AppPool of Vserver",
		.cn = "为虚拟服务器设置应用池",
	},

	[ LIBCLI_VSERVER_SET_BACKPOOL ] = {
		.en = "Set the BackPool of Vserver",
		.cn = "为虚拟服务器设置备份池",
	},

	[ LIBCLI_VSERVER_SET_PERSISTENT ] = {
		.en = "Set Persistent",
		.cn = "设置会话保持(Persistent)的类型",
	},

	[ LIBCLI_VSERVER_SET_PERSISTENTGROUP] = {
		.en = "Set Persistent-Group",
		.cn = "设置会话保持组",
	},
	[ LIBCLI_VSERVER_SET_PERSISTENT_NETMASK ] = {
		.en = "Set Persistent-netmask",
		.cn = "设置会话保持掩码",
	},

	[ LIBCLI_VSERVER_SET_GZIP ] = {
		.en = "Set if gzip is enabled",
		.cn = "设置gzip是否启用",
	},

	[ LIBCLI_VSERVER_SET_GZIP_ON ] = {
		.en = "Set gzip is enabled",
		.cn = "设置gzip为启用",
	},

	[ LIBCLI_VSERVER_SET_GZIP_OFF ] = {
		.en = "Set gzip is disabled",
		.cn = "设置gzip为禁用",
	},

	[ LIBCLI_VSERVER_SET_DEFLATE ] = {
		.en = "Set if deflate is enabled",
		.cn = "设置Deflate是否启用",
	},

	[ LIBCLI_VSERVER_SET_DEFLATE_ON ] = {
		.en = "Set deflate is enabled",
		.cn = "设置Deflate为启用",
	},

	[ LIBCLI_VSERVER_SET_DEFLATE_OFF ] = {
		.en = "Set deflate is disabled",
		.cn = "设置Deflate为禁用",
	},

	[ LIBCLI_VSERVER_SET_CACHE ] = {
		.en = "Set if caching is enabled",
		.cn = "设置Deflate是否启用",
	},

	[ LIBCLI_VSERVER_SET_CACHE_ON ] = {
		.en = "Set caching  enabled",
		.cn = "设置Deflate为启用",
	},
	[ LIBCLI_VSERVER_SET_CACHE_OFF ] = {
		.en = "Set caching disabled",
		.cn = "设置Deflate为禁用",
	},

	[ LIBCLI_VSERVER_SET_TIMEOUT ] = {
		.en = "Connection Template Timeout.(seconds)",
		.cn = "连接模板超时",
	},

	[ LIBCLI_VSERVER_SET_LIMIT ] = {
		.en = "Set limit of Vserver",
		.cn = "启用Vserver限制",
	},
	[ LIBCLI_VSERVER_SET_LIMIT_OFF ] = {
		.en = "Set the limit off",
		.cn = "设置限制",
	},

	[ LIBCLI_VSERVER_SET_LIMIT_MAXCONN ] = {
		.en = "Set the Max Connections of Vserver",
		.cn = "设置Vserver的最大连接数",
	},

	[ LIBCLI_VSERVER_SET_LIMIT_MAXREQ ] = {
		.en = "Set the Max Requests of Vserver",
		.cn = "设置Vserver的最大请求数",
	},

	[ LIBCLI_VSERVER_SET_LIMIT_BANDWIDTH ] = {
		.en = "Set the Max Bandwidth of Vserver",
		.cn = "设置Vserver的最大带宽",
	},

	[ LIBCLI_VSERVER_SET_CIPHEADER ] = {
		.en = "Custom HTTP headers to carry the IP address",
		.cn = "自定义携带IP地址HTTP头",
	},

	[ LIBCLI_VSERVER_SET_PERSISTENT_OFF ] = {
		.en = "Turn Persistent off",
		.cn = "关闭会话保持",
	}, 

	[ LIBCLI_VSERVER_SET_PERSISTENT_IP ] = {
		.en = "Use Ip address to do session persistent",
		.cn = "使用IP地址进行会话保持",
	}, 

	[ LIBCLI_VSERVER_SET_PERSISTENT_SSLID ] = {
		.en = "Use SSL-Session-ID to do session persistent",
		.cn = "使用SSL SessionID进行会话保持",
	},

	[ LIBCLI_VSERVER_SET_PERSISTENT_COOKIE ] = {
		.en = "Use HTTP-Cookie to do session persistent",
		.cn = "使用HTTP Cookie进行会话保持",
	}, 

	[ LIBCLI_VSERVER_SET_PERSISTENT_COOKIE_NAME ] = {
		.en = "Set HTTP-Cookie's Name to do session persistent",
		.cn = "设置进行会话保持HTTP Cookie的名称",
	}, 

	[ LIBCLI_VSERVER_SET_PERSISTENT_HEADER ] = {
		.en = "Use HTTP-Header to do session persistent",
		.cn = "使用HTTP Header进行会话保持",
	}, 

	[ LIBCLI_VSERVER_SET_PERSISTENT_HEADER_NAME ] = {
		.en = "Set HTTP-Header's Name to do session persistent",
		.cn = "设置进行会话保持HTTP Header的名称",
	}, 



	[ LIBCLI_VSERVER_SET_PERSISTENT_TIMEOUT ] = {
		.en = "Set Persistent timeout",
		.cn = "设置会话保持超时时间",
	}, 

	[ LIBCLI_VSERVER_SET_DATA_PORT ] = {
		.en = "Set Data Port of FTP",
		.cn = "设置FTP协议的数据端口",
	},

	[ LIBCLI_VSERVER_SET_MODE_INFO ] = {
		.en = "Set Vserver Mode",
		.cn = "设置 Vserver的模式",
	},

	[ LIBCLI_VSERVER_SET_MODE_NAT ] = {
		.en = "Set Vserver nat mode",
		.cn = "设置 Vserver 的 NAT 模式",
	},

	[ LIBCLI_VSERVER_SET_MODE_DR ] = {
		.en = "Set Vserver dr mode",
		.cn = "设置 Vserver的 DR 模式",
	},
	[ LIBCLI_VSERVER_SET_LOG_ENABLE_INFO ] = {
		.en = "Set Vserver log_enable",
		.cn = "设置 Vserver的 log_enable ",
	},

	[ LIBCLI_VSERVER_SET_LOG_FORMAT_INFO ] = {
		.en = "Set Vserver log_format",
		.cn = "配置 Vserver的 log_format 格式 ",
	},

	[ LIBCLI_VSERVER_SET_LOG_ENABLE_ON ] = {
		.en = "Set Vserver log_enable on",
		.cn = "设置 Vserver log_enable on",
	},

	[ LIBCLI_VSERVER_SET_LOG_ENABLE_OFF ] = {
		.en = "Set Vserver log_enable off",
		.cn = "设置 Vserver log_enable off",
	},

	[ LIBCLI_VSERVER_SET_WAF_ENABLE_INFO ] = {
		.en = "Set Vserver waf_enable",
		.cn = "设置 Vserver的 waf_enable",
	},

	[ LIBCLI_VSERVER_SET_WAF_ENABLE_ON ] = {
		.en = "Set Vserver waf_enable on",
		.cn = "设置 Vserver waf_enable on",
	},

	[ LIBCLI_VSERVER_SET_WAF_ENABLE_OFF ] = {
		.en = "Set Vserver waf_enable off",
		.cn = "设置 Vserver waf_enable off",
	},

	[ LIBCLI_POOL_ADD_INFO ] = {
		.en = "Add AppPool",
		.cn = "添加AppPool",
	},

	[ LIBCLI_POOL_SHOW_INFO ] = {
		.en = "Show AppPool Information",
		.cn = "显示AppPool配置信息",
	},

	[ LIBCLI_POOL_MANAGE_INFO ] = {
		.en = "Manage AppPool",
		.cn = "管理AppPool",
	},

	[ LIBCLI_POOL_DELETE_INFO ] = {
		.en = "Delete AppPool",
		.cn = "删除AppPool",
	},

	[ LIBCLI_POOL_SET_ADD_REALSERVER ] = {
		.en = "Add a RealServer to the AppPool",
		.cn = "向应用池中添加真实服务器",
	},

	[ LIBCLI_POOL_SET_SET_REALSERVER ] = {
		.en = "Manage the RealServer",
		.cn = "对真实服务器进行配置",
	},

	[ LIBCLI_POOL_SET_DEL_REALSERVER ] = {
		.en = "Delete a RealServer from the AppPool",
		.cn = "从应用池中删除真实服务器",
	},

	[ LIBCLI_POOL_SET_SHOW_REALSERVER ] = {
		.en = "Show GSLB the Rserver",
		.cn = "显示应用池中的真实服务器",
	},

	[ LIBCLI_POOL_SET_REALSERVER_ENABLE ] = {
		.en = "Set if this RealServer enabled",
		.cn = "设置RealServer是否启用",
	},

	[ LIBCLI_POOL_SET_REALSERVER_ENABLE_ON ] = {
		.en = "Set RealServer enabled",
		.cn = "设置RealServer为启用",
	},
	[ LIBCLI_POOL_SET_REALSERVER_ENABLE_OFF ] = {
		.en = "Set RealServer disabled",
		.cn = "设置RealServer为启用",
	},

/*********for Elastic********************/
/* used for elastic */

  [ LIBCLI_POOL_SET_REALSERVER_RSCENTER ] = {
    .en = "Set the rscenter of Realserver",
    .cn = "配置Realserver的rscenter",
  },

  [ LIBCLI_POOL_SET_REALSERVER_DATACENTER  ] = {
    .en = "Set the datacenter of Realserver",
    .cn = "配置Realserver的datacenter",
  },
	
  [ LIBCLI_POOL_SET_REALSERVER_UUID ] = {
    .en = "Set the uuid of Realserver",
    .cn = "配置Realserver的uuid",
  },

  [ LIBCLI_POOL_SET_REALSERVER_VMXPATH ] = {
    .en = "Set the vmpath of Realserver",
    .cn = "配置Realserver的vmpath",
  },

  [ LIBCLI_POOL_SET_VMTYPE ] = {
    .en = "Set the vmtype of pool",
    .cn = "配置AppPool的vmtype",
  },

  [ LIBCLI_POOL_SET_VMTYPE_VMWARE ] = {
    .en = "Set the vmtype of pool to vmware",
    .cn = "配置AppPool的vmtype为vmware",
  },

  [ LIBCLI_POOL_SET_VMTYPE_XEN ] = {
    .en = "Set the vmtype of pool to xen",
    .cn = "配置AppPool的vmtype为xen",
  },

  [ LIBCLI_POOL_SET_VMTYPE_VCENTER ] = {
    .en = "Set the vmtype of pool to vcenter",
    .cn = "配置AppPool的vmtype为vcenter",
  },

  [ LIBCLI_POOL_SET_VM_ADDRESS ] = {
    .en = "Set the address of pool",
    .cn = "配置AppPool的address",
  },

  [ LIBCLI_POOL_SET_VM_ENABLE ] = {
    .en = "Set the enable of pool",
    .cn = "配置AppPool的enable",
  },

  [ LIBCLI_POOL_SET_VM_ENABLE_ON ] = {
    .en = "Set the enable of pool to on",
    .cn = "配置AppPool的enable为on",
  },

  [ LIBCLI_POOL_SET_VM_ENABLE_OFF ] = {
    .en = "Set the enable of pool to off",
    .cn = "配置AppPool的enable为off",
  },

  [ LIBCLI_POOL_SET_VM_USERNAME ] = {
    .en = "Set the username of pool",
    .cn = "配置AppPool的username",
  },

  [ LIBCLI_POOL_SET_VM_PASSWORD ] = {
    .en = "Set the password of pool",
    .cn = "配置AppPool的password",
  },

  [ LIBCLI_POOL_SET_VM_INTERVAL ] = {
    .en = "Set the interval of pool",
    .cn = "配置AppPool的interval",
  },

  [ LIBCLI_POOL_SET_VM_COUNT ] = {
    .en = "Set the vmcount of pool",
    .cn = "配置AppPool的vmcount",
  },

  [ LIBCLI_POOL_SET_VM_ALIVE_COUNT ] = {
    .en = "Set the default alive vms of pool",
    .cn = "配置AppPool默认开启多少vm",
  },

  [ LIBCLI_POOL_SET_VM_VCENTER ] = {
    .en = "Set the vcenter of pool",
    .cn = "配置AppPool的venter",
  },

  [ LIBCLI_POOL_SET_VM_DATACENTER ] = {
    .en = "Set the vmdatacenter of pool",
    .cn = "配置AppPool的vmdatacenter",
  },

  [ LIBCLI_POOL_SET_VM_PORT ] = {
    .en = "Set the vmport of pool",
    .cn = "配置AppPool的vmport",
  },



	[ LIBCLI_POOL_SET_HEALTHCHECK ] = {
		.en = "Set the HealthCheck",
		.cn = "配置AppPool的HealthCheck",
	},


	[ LIBCLI_HEALTHCHECK_ADD_INFO ] = { 
		.en = "Add  HealthCheck",
		.cn = "添加HealthCheck",
	},

	[ LIBCLI_HEALTHCHECK_SHOW_INFO ] = {
		.en = "Show HealthCheck information",
		.cn = "显示HealthCheck配置信息",
	},


	[ LIBCLI_HEALTHCHECK_MANAGE_INFO ] = {
		.en = "Manage HealthCheck",
		.cn = "管理HealthCheck",
	},

	[ LIBCLI_HEALTHCHECK_DELETE_INFO ] = {
		.en = "Delete HealthCheck",
		.cn = "删除HealthCheck",
	},

	[ LIBCLI_HEALTHCHECK_SET_TYPE ] = {
		.en = "Set the type of HealthCheck",
		.cn = "设置HealthCheck类型",
	},

	[ LIBCLI_HEALTHCHECK_SET_TIMEOUT ] = {
		.en = "Set connect timeout",
		.cn = "设置超时时间",
	},
	[ LIBCLI_HEALTHCHECK_SET_RETRY ] = {
		.en = "Set number of unsuccessful attempts before marking a RealServer down",
		.cn = "设置RealServer关闭前失败的次数",
	},

	[ LIBCLI_HEALTHCHECK_SET_INTERVAL ] = {
		.en = "Set interval",
		.cn = "设置间隔时间",
	},

	[ LIBCLI_HEALTHCHECK_SET_DOWNTIME ] = {
		.en = "Set downtime",
		.cn = "设置静默时间",
	},


	[ LIBCLI_HEALTHCHECK_SET_HTTP_PATH ] = {
		.en = "Set http path, eg:'/' or '/index.html'",
		.cn = "设置HTTP路径,例如:'/'或'/ 'index.html'"
	},

	[ LIBCLI_HEALTHCHECK_SET_HTTP_STATUSCODE ] = {
		.en = "Set http status code expected",
		.cn = "设置HTTP的状态代码"
	},

	[ LIBCLI_HEALTHCHECK_SET_SMTP_HELO ] = {
		.en = "Set smtp HELO",
		.cn = "设置SMTP的HELO"
	},

	[ LIBCLI_HEALTHCHECK_SET_DNS_DOMAIN ] = {
		.en = "Set dns domain",
		.cn = "设置DNS的DOMAIN"
	},

	[ LIBCLI_HEALTHCHECK_SET_SCRIPT] = {
		.en = "Set script name",
		.cn = "设置脚本名字"
	},
	[ LIBCLI_HEALTHCHECK_SET_HTTP_OFFSET] = {
		.en = "Set the offset of http response to be check",
		.cn = "设置HTTP字符串的偏移量"
	},
	[ LIBCLI_HEALTHCHECK_SET_HTTP_STRING] = {
		.en = "Set the string of http response to be check",
		.cn = "设置HTTP健康检查字符串"
	},
/**--------------------------------------------**/
	[ LIBCLI_HEALTHCHECK_SET_HTTP_ECV_OFFSET] = {
		.en = "Set the offset of http response to be check",
		.cn = "设置HTTP字符串的偏移量"
	},
	[ LIBCLI_HEALTHCHECK_SET_HTTP_ECV_STRING] = {
		.en = "Set the string of http response to be check",
		.cn = "设置HTTP健康检查字符串"
	},

	[ LIBCLI_HEALTHCHECK_SET_HTTP_TYPE] = {
		.en = "Set the http content testing method",
		.cn = "设置HTTP内容校验方法"
	},
	[ LIBCLI_HEALTHCHECK_SET_ICMP_GW_IP] = {
		.en = "Set the icmp health check gateway",
		.cn = "设置ICMP健康检查探测网关"
	},
/**--------------------------------------------**/



	[ LIBCLI_RULE_ADD_INFO ] = {
		.en = "Add a SmartRule",
		.cn = "为系统添加一个SmartRule",
	},

	[ LIBCLI_RULE_SHOW_INFO ] = {
		.en = "Show SmartRule Information",
		.cn = "显示SmartRule的配置信息",
	},

	[ LIBCLI_RULE_MANAGE_INFO ] = {
		.en = "Manage the SmartRule",
		.cn = "管理SmartRule",
	},
	[ LIBCLI_RULE_DELETE_INFO ] = {
		.en = "Delete the SmartRule",
		.cn = "删除SmartRule",
	},

	[ LIBCLI_RULE_SET_CONDITION ] = {
		.en = "Set condition of SmartRule",
		.cn = "设置SmartRule的condition类型",
	},

	[ LIBCLI_RULE_SET_ACTION ] = {
		.en = "Set action of SmartRule",
		.cn = "设置Rule的action类型",
	},

	[ LIBCLI_INTERFACE_MGMT_SHOW_INFO ] = {
		.en = "Show Mgmt Interface Information",
		.cn = "显示Mgmt的配置信息",
	},

	[ LIBCLI_INTERFACE_SHOW_INFO ] = {
		.en = "Show Interface Information",
		.cn = "显示Interface的配置信息",
	},

	[ LIBCLI_INTERFACE_MANAGE_INFO ] = {
		.en = "Manage Interface",
		.cn = "管理Interface",
	},

	[ LIBCLI_INTERFACE_SET_ADD ] = {
		.en = "Add ip address or interface",
		.cn = "添加IP地址或接口",
	},

	[ LIBCLI_INTERFACE_SET_ADD_IP_FLOAT ] = {
		.en = "Add float ip address ",
		.cn = "添加浮动IP地址",
	},

	[ LIBCLI_INTERFACE_SET_ADD_IP_STATIC ] = {
		.en = "Add static ip address",
		.cn = "添加静态IP地址",
	},

	[ LIBCLI_INTERFACE_SET_DELETE ] = {
		.en = "Delete ip address or interface",
		.cn = "删除IP或接口",
	},

	[ LIBCLI_INTERFACE_SET_PROTOCOL ] = {
		.en = "Set protocol, DHCP or static",
		.cn = "设置获取IP为静态或动态",
	},

	[ LIBCLI_INTERFACE_SET_PROTOCOL_STATIC ] = {
		.en = "Set ip static",
		.cn = "设置获取IP为静态",
	},

	[ LIBCLI_INTERFACE_SET_PROTOCOL_DHCP ] = {
		.en = "Set ip DHCP",
		.cn = "设置动态获取获取",
	},

	[ LIBCLI_INTERFACE_IP ] = {
		.en = "IP address",
		.cn = "IP地址"
	},

	[ LIBCLI_INTERFACE_TYPE_INFO ] = {
		.en = "Set interface mode",
		.cn = "设置接口模式"
	},

	[ LIBCLI_INTERFACE_TYPE_NORMAL_INFO ] = {
		.en = "Set interface mode normal",
		.cn = "设置interface模式类型为normal"
	},

	[ LIBCLI_INTERFACE_TYPE_TRUNK_INFO ] = {
		.en = "Set interface mode trunk",
		.cn = "设置interface模式类型为trunk"
	}, 

	[ LIBCLI_INTERFACE_SET_SPEED ] = {
		.en = "Set interface speed",
		.cn = "设置接口速度"
	},
	[ LIBCLI_INTERFACE_SET_SPEED_10HALF ] = {
		.en = "Set interface speed 10Mb half",
		.cn = "设置接口速度为半双工10Mb"
	},
	[ LIBCLI_INTERFACE_SET_SPEED_10FULL ] = {
		.en = "Set interface speed 10Mb full",
		.cn = "设置接口速度为全双工10Mb"
	},
	[ LIBCLI_INTERFACE_SET_SPEED_100HALF ] = {
		.en = "Set interface speed 100Mb half",
		.cn = "设置接口速度为半双工100Mb"
	},
	[ LIBCLI_INTERFACE_SET_SPEED_100FULL ] = {
		.en = "Set interface speed 100Mb full",
		.cn = "设置接口速度为全双工100Mb"
	},
	[ LIBCLI_INTERFACE_SET_SPEED_1000FULL ] = {
		.en = "Set interface speed 1000Mb full",
		.cn = "设置接口速度为全双工1000Mb"
	},
	[ LIBCLI_INTERFACE_SET_SPEED_AUTO ] = {
		.en = "Set interface speed auto",
		.cn = "设置接口速度为自适应模式"
	},

	[ LIBCLI_INTERFACE_PAUSE ] = {
		.en = "Set interface pause",
		.cn = "设置接口停止"
	},
	[ LIBCLI_INTERFACE_PAUSE_NONE ] = {
		.en = "Set interface autoneg off, receive off,transmit off",
		.cn = "接口自动协商关闭,发送关闭,接收关闭"
	},
	[ LIBCLI_INTERFACE_PAUSE_TX ] = {
		.en = "Set interface autoneg off, transmit on, receive off",
		.cn = "接口自动协商关闭,发送打开,接收关闭"
	},
	[ LIBCLI_INTERFACE_PAUSE_RX ] = {
		.en = "Set interface autoneg off, transmit off, receive on",
		.cn = "接口自动协商关闭,发送关闭,接收打开"
	},
	[ LIBCLI_INTERFACE_PAUSE_RX_TX ] = {
		.en = "Set interface autoneg off, transmit on, receive on",
		.cn = "接口自动协商关闭,发送打开,接收打开"
	},
	[ LIBCLI_INTERFACE_PAUSE_AUTO ] = {
		.en = "Set interface autoneg on",
		.cn = "设置接口自动协商打开"
	},

	[ LIBCLI_INTERFACE_ENABLE ] = {
		.en = "Interface up/down",
		.cn = "启用/关闭 接口"
	},
	[ LIBCLI_INTERFACE_ENABLE_ON ] = {
		.en = "Interface up",
		.cn = "启用接口"
	},
	[ LIBCLI_INTERFACE_ENABLE_OFF ] = {
		.en = "Interface down",
		.cn = "关闭接口"
	},

	[ LIBCLI_INTERFACE_METHOD ] = {
		.en = "Set Bonding Method",
		.cn = "设置链路聚合调度模式",
	},

	[LIBCLI_INTERFACE_METHOD_RR ] = {
		.en = "Set Bonding Method to RR",
		.cn = "设置链路聚合调度模式为轮询",
	},

	[LIBCLI_INTERFACE_METHOD_AB ] = {
		.en = "Set Bonding Method to Active-Backup",
		.cn = "设置链路聚合调度模式为主备",
	},

	[LIBCLI_INTERFACE_METHOD_XOR ] = {
		.en = "Set Bonding Method to XOR",
		.cn = "设置链路聚合调度模式为XOR",
	},

	[LIBCLI_INTERFACE_METHOD_BC ] = {
		.en = "Set Bonding Method to Broadcast",
		.cn = "设置链路聚合调度模式为广播",
	},

	[LIBCLI_INTERFACE_METHOD_8023AD ] = {
		.en = "Set Bonding Method to 802.3ad",
		.cn = "设置链路聚合调度模式为802.3ad",
	},

	[LIBCLI_INTERFACE_METHOD_TLB ] = {
		.en = "Set Bonding Method to TLB",
		.cn = "设置链路聚合调度模式为TLB",
	},

	[LIBCLI_INTERFACE_METHOD_ALB ] = {
		.en = "Set Bonding Method to ALB",
		.cn = "设置链路聚合调度模式为ALB",
	},

	[ LIBCLI_INTERFACE_TYPE_TRUNK_PERMIT_INFO] = {
		.en = "permit the vlan to be accessed",
		.cn = "设置通过该trunk端口所允许的vlan",
	},

	[ LIBCLI_INTERFACE_TYPE_TRUNK_PERMIT_VLAN ]= {
		.en = "permit the vlan to be accessed",
		.cn = "设置通过该trunk端口所允许的vlan",
	},

	[ LIBCLI_INTERFACE_TYPE_TRUNK_DENY_INFO ] = {
		.en = "deny the vlan to be accessed",
		.cn = "设置通过该trunk端口所禁止的vlan",
	},

	[ LIBCLI_INTERFACE_TYPE_TRUNK_DENY_VLAN ] = {
		.en = "deny the vlan to be accessed",
		.cn = "设置通过该trunk端口所禁止的vlan",
	},

	[ LIBCLI_VLAN_ADD_INFO ] = {
		.en = "Add VLAN",
		.cn = "添加VLAN"
	},

	[ LIBCLI_VLAN_MANAGE_INFO ] = {
		.en = "Manage VLAN",
		.cn = "管理VLAN"
	},
	[ LIBCLI_VLAN_ADD_INTERFACE ] = {
		.en = "Add interface to vlan",
		.cn = "添加VLAN接口"
	},


	[ LIBCLI_BONDING_ADD_INFO ] = {
		.en = "Add Bonding",
		.cn = "添加Bonding"
	},

	[ LIBCLI_BONDING_MANAGE_INFO ] = {
		.en = "Manage Bonding",
		.cn = "管理Bonding",
	},

	[ LIBCLI_BONDING_DELETE_INFO ] = {
		.en = "Delete Bonding",
		.cn = "删除Bonding"
	},


	[ LIBCLI_NETWORK_DNS_SHOW_INFO ] = {
		.en = "Show DNS information",
		.cn = "显示DNS配置信息",
	},

	[ LIBCLI_NETWORK_DNS_DEL_ADDR ] = {
		.en = "Delete DNS",
		.cn = "添加DNS",
	},

	[ LIBCLI_NETWORK_DNS_ADD_ADDR ] = {
		.en = "Add DNS",
		.cn = "添加DNS",
	},

	[ LIBCLI_NETWORK_SNAT_SHOW_INFO ] = {
		.en = "Show SNAT information",
		.cn = "显示SNAT配置信息",
	},

	[ LIBCLI_NETWORK_SNAT_ADD_INFO ] = {
		.en = "Add SNAT",
		.cn = "添加一条SNAT规则",
	},

	[ LIBCLI_NETWORK_SNAT_MANAGE_INFO ] = {
		.en = "Manage items of SNAT",
		.cn = "管理SNAT规则",
	},

	[ LIBCLI_NETWORK_SNAT_DELETE_INFO ] = {
		.en = "Delete SNAT",
		.cn = "删除一条SNAT规则",
	},

	[ LIBCLI_NETWORK_SNAT_SET_TYPE ] = {
		.en = "Set SNAT type",
		.cn = "设置SNAT的类型",
	},

	[ LIBCLI_NETWORK_SNAT_SET_TYPE_STATIC ] = {
		.en = "static SNAT",
		.cn = "静态SNAT类型",
	},

	[ LIBCLI_NETWORK_SNAT_SET_TYPE_MASQUERADE ] = {
		.en = "dynamic SNAT",
		.cn = "动态SNAT",
	},

	[ LIBCLI_NETWORK_SNAT_SET_SRCFROM ] = {
		.en = "Set SNAT start IP address",
		.cn = "设置的SNAT源地址的起始IP地址",
	},

	[ LIBCLI_NETWORK_SNAT_SET_SRCTO ] = {
		.en = "Set SNAT end IP address",
		.cn = "设置SNAT源地址的结束IP地址",
	},


	[ LIBCLI_NETWORK_SNAT_SET_DESTFROM ] = {
		.en = "Set SNAT start IP address",
		.cn = "设置的SNAT目的地址起始IP地址",
	},

	[ LIBCLI_NETWORK_SNAT_SET_DESTTO ] = {
		.en = "Set SNAT end IP address",
		.cn = "设置SNAT目的地址的结束IP地址",
	},


	[ LIBCLI_NETWORK_SNAT_SET_INTERFACE ] = {
		.en = "Set SNAT interface",
		.cn = "设置SNAT的网络端口",
	},


	[ LIBCLI_NETWORK_SNAT_SET_ENABLE ] = {
		.en = "Set if SNAT is enabled",
		.cn = "设置SNAT是否启用",
	},


	[ LIBCLI_NETWORK_SNAT_SET_ENABLE_ON ] = {
		.en = "Set SNAT is enable",
		.cn = "设置SNAT为启用",
	},


	[ LIBCLI_NETWORK_SNAT_SET_ENABLE_OFF ] = {
		.en = "Set SANT is disabled",
		.cn = "设置SNAT为禁用",
	},

	/*********** DNAT *****************/
	[ LIBCLI_NETWORK_DNAT_SHOW_INFO ] = {
		.en = "Show DNAT information",
		.cn = "显示DNAT配置信息",
	},
	[ LIBCLI_NETWORK_DNAT_ADD_INFO ] = {
		.en = "Add DNAT",
		.cn = "Add DNAT",
	},
	[ LIBCLI_NETWORK_DNAT_DEL_INFO ] = {
		.en = "Delete DNAT",
		.cn = "Delete DNAT",
	},
	[ LIBCLI_NETWORK_DNAT_SET_INFO ] = {
		.en = "Set DNAT",
		.cn = "Set DNAT",
	},
	[ LIBCLI_NETWORK_DNAT_DEST_ADD_INFO ] = {
		.en = "Add DNAT destination",
		.cn = "Add DNAT destination",
	},
	[ LIBCLI_NETWORK_DNAT_DEST_DEL_INFO ] = {
		.en = "Delete DNAT destination",
		.cn = "Delete DNAT destination",
	},

	[ LIBCLI_NETWORK_RTABLE_SHOW_INFO ] = {
		.en = "Show Route Table information",
		.cn = "显示路由表配置信息",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_INFO ] = {
		.en = "Add a Route Table",
		.cn = "添加路由表",
	},

	[ LIBCLI_NETWORK_RTABLE_DELETE_INFO ] = {
		.en = "Delete Route table",
		.cn = "删除路由表",
	},

	[ LIBCLI_NETWORK_RTABLE_MANAGE_INFO ] = {
		.en = "Manage Route table",
		.cn = "管理路由表",
	},


	[ LIBCLI_NETWORK_RTABLE_SET_RULE ] = {
		.en = "Set rule",
		.cn = "配置rule",
	},


	[ LIBCLI_NETWORK_RTABLE_SET_RULEID ] = {
		.en = "rule",
		.cn = "rule",
	},


	[ LIBCLI_NETWORK_RTABLE_SET_ADD ] = {
		.en = "Add Route",
		.cn = "添加路由",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_DELETE ] = {
		.en = "Delete Route",
		.cn = "删除路由",
	},


	[ LIBCLI_NETWORK_RTABLE_ADD_ROUTE ] = {
		.en = "Add Route",
		.cn = "添加路由条目",
	},

	[ LIBCLI_NETWORK_RTABLE_DEL_ROUTE ] = {
		.en = "Delete Route",
		.cn = "删除路由条目",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_S_ROUTE ] = {
		.en = "Add S-Route",
		.cn = "添加基于源地址的路由条目",
	},

	[ LIBCLI_NETWORK_RTABLE_DEL_S_ROUTE ] = {
		.en = "Delete S-Route",
		.cn = "删除基于源地址的路由条目",
	},

	[ LIBCLI_NETWORK_RTABLE_SHOW_S_ROUTE ] = {
		.en = "Show S-Route",
		.cn = "显示基于源地址的路由条目",
	},


	[ LIBCLI_NETWORK_RTABLE_ADD_ROUTE_GATEWAY ] = {
		.en = "Set Gateway",
		.cn = "设置网关",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_ROUTE_NEXTHOP ] = {
		.en = "Set Nexthop",
		.cn = "设置下一跳",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_OSPF ] = {
		.en = "Add OSPF Route",
		.cn = "添加OSPF动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_OSPF_AREA ] = {
		.en = "Add OSPF Route area",
		.cn = "添加OSPF动态路由域",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_OSPF6 ] = {
		.en = "Add OSPF IPv6 Route",
		.cn = "添加OSPF IPv6 动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_RIP ] = {
		.en = "Add RIP Route",
		.cn = "添加RIP 动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_RIPNG ] = {
		.en = "Add RIP IPv6 Route",
		.cn = "添加RIP IPv6 动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_ADD_NEIGHBOR ] = {
		.en = "Add RIP Route Neighbor",
		.cn = "添加RIP邻居动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_DELETE_OSPF ] = {
		.en = "Delete OSPF Route",
		.cn = "删除OSPF动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_DELETE_RIP ] = {
		.en = "Delete RIP Route",
		.cn = "删除RIP动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_DELETE_NEIGHBOR ] = {
		.en = "Delete RIP Route Neighbor",
		.cn = "删除RIP邻居动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_OSPF ] = {
		.en = "Set OSPF Route",
		.cn = "设置OSPF动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_OSPF_ON ] = {
		.en = "Set OSPF Route Enable",
		.cn = "设置OSPF动态路由为启用",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_OSPF_OFF ] = {
		.en = "Set OSPF Route Disable",
		.cn = "设置OSPF动态路由为停用",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_OSPF6 ] = {
		.en = "Set OSPF6 Route",
		.cn = "设置OSPF6动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_OSPF6_ON ] = {
		.en = "Set OSPF6 Route Enable",
		.cn = "设置OSPF6动态路由为启用",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_OSPF6_OFF ] = {
		.en = "Set OSPF6 Route Disable",
		.cn = "设置OSPF6动态路由为停用",
	},
	[ LIBCLI_NETWORK_RTABLE_SET_RIP ] = {
		.en = "Set RIP Route",
		.cn = "设置RIP动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_RIP_ON ] = {
		.en = "Set RIP Route Enable",
		.cn = "设置RIP动态路由为启用",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_RIP_OFF ] = {
		.en = "Set RIP Route Disable",
		.cn = "设置RIP动态路由为停用",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_RIPNG ] = {
		.en = "Set RIPNG Route",
		.cn = "设置RIPNG动态路由",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_RIPNG_ON ] = {
		.en = "Set RIPNG Route Enable",
		.cn = "设置RIPNG动态路由为启用",
	},

	[ LIBCLI_NETWORK_RTABLE_SET_RIPNG_OFF ] = {
		.en = "Set RIPGN Route Disable",
		.cn = "设置RIPGN动态路由为停用",
	},
	[LIBCLI_NETWORK_ARPTABLE_SHOW_INFO] = {
		.en = "Show Arp information",
		.cn = "显示arp信息",
	},


	[LIBCLI_NETWORK_ARPTABLE_MANAGE_INFO] = {
		.en = "Manage Arp table",
		.cn = "配置arp表",
	},


	[LIBCLI_NETWORK_ARPTABLE_SET_DELETE_ARP] = {
		.en = "Delete Arp",
		.cn = "删除Arp信息",
	},


	[LIBCLI_NETWORK_ARPTABLE_SET_ADD_ARP] = {
		.en = "Add Arp information",
		.cn = "添加Arp信息",
	},

	[LIBCLI_NETWORK_ARPTABLE_SET] = {
		.en = "Manage Arp",
		.cn = "配置Arp",
	},

	[LIBCLI_NETWORK_ARPTABLE_SET_ARP_MAC] = {
		.en = "Manage Arp mac address",
		.cn = "配置网络接口地址",
	},

	[LIBCLI_NETWORK_ARPTABLE_SET_ARP_INTERFACE] = {
		.en = "Manage Arp interface",
		.cn = "配置Arp网络接口",
	},

	[LIBCLI_ARP_TIMEOUT_SHOW_INFO] = {
		.en = "Show Arp entry timeout value.",
		.cn = "显示Arp条目有效时间",
	},


	[LIBCLI_NETWORK_FLOATIP_DEL_IP] = {
		.en = "Delete float ip information",
		.cn = "删除浮动IP信息",
	},


	[LIBCLI_NETWORK_FLOATIP_ADD_IP] = {
		.en = "Add float ip information",
		.cn = "添加浮动IP信息",
	},

	[LIBCLI_ARP_TIMEOUT_SET_INFO] = {
		.en = "Set Arp entry timeout value.",
		.cn = "配置arp条目有效时间",
	},

	[LIBCLI_NETWORK_FLOATIP_SHOW_INFO] = {
		.en = "Show float ip information",
		.cn = "显示浮动IP信息",
	},



	[ LIBCLI_CERTIF_SHOW_INFO ] = {
		.en = "Show cerif information",
		.cn = "显示cerif信息",
	},

	[ LIBCLI_CERTIF_DELETE_INFO ] = {
		.en = "Delete certif information",
		.cn = "删除certif信息",
	},

	[ LIBCLI_CRLS_SHOW_INFO ] = {
		.en = "Show crls information",
		.cn = "显示crls信息",
	},

	[ LIBCLI_CRLS_DELETE_INFO ] = {
		.en = "Delete crls information",
		.cn = "删除crls信息",
	},

	[ LIBCLI_SMTP_MANAGE_INFO ] = {
		.en = "Manage SMTP Service",
		.cn = "管理SMTP服务",
	},

	[ LIBCLI_SMTP_SET_SHOW ] = {
		.en = "Show SMTP information",
		.cn = "显示SMTP配置信息",
	},

	[ LIBCLI_SMTP_SET_ENABLE ] = {
		.en = "SMTP Service Control",
		.cn = "控制SMTP服务",
	},

	[ LIBCLI_SMTP_SET_ENABLE_ON ] = {
		.en = "SMTP Service enable",
		.cn = "启用SMTP服务",
	},

	[ LIBCLI_SMTP_SET_ENABLE_OFF ] = {
		.en = "SMTP Service disable",
		.cn = "禁用SMTP服务",
	},

	[ LIBCLI_SMTP_SET_SERVER ] = {
		.en = "SMTP server address",
		.cn = "SMTP 邮件服务器地址",
	},

	[ LIBCLI_SMTP_SET_PORT ] = {
		.en = "SMTP server port",
		.cn = "SMTP 邮件服务器端口",
	},

	[ LIBCLI_SMTP_SET_USERNAME ] = {
		.en = "SMTP sender username",
		.cn = "SMTP 发件人用户名",
	},

	[ LIBCLI_SMTP_SET_PASSWORD ] = {
		.en = "SMTP sender password",
		.cn = "SMTP 发件人密码",
	},

	[ LIBCLI_SMTP_SET_SSL_ENABLE ] = {
		.en = "SMTP SSL connection",
		.cn = "SMTP SSL 连接控制",
	},

	[ LIBCLI_SMTP_SET_SSL_ENABLE_ON ] = {
		.en = "SMTP SSL connection enable",
		.cn = "SMTP SSL 连接启用",
	},

	[ LIBCLI_SMTP_SET_SSL_ENABLE_OFF ] = {
		.en = "SMTP SSL connection disable",
		.cn = "SMTP SSL连接禁用",
	},

	[ LIBCLI_SMTP_SET_DESTINATION ] = {
		.en = "SMTP receiver address",
		.cn = "SMTP 邮件人地址",
	},

	[ LIBCLI_SMTP_SET_INTERVAL ] = {
		.en = "SMTP sent interval, unit is second",
		.cn = "SMTP 发送间隔时间",
	},

	[ LIBCLI_SYSCONFIG_MANAGE_INFO ] = {
		.en = "Manage LLB configuration",
		.cn = "管理LLB configuration服务",
	},

	[ LIBCLI_SYSCONFIG_SET_SHOW ] = {
		.en = "Show System Configuration information",
		.cn = "显示Sysconfig配置信息",
	},

	[ LIBCLI_SYSCONFIG_SHOW ] = {
		.en = "Show System Configuration information",
		.cn = "显示Sysconfig配置信息",
	},

	[ LIBCLI_SYSCONFIG_LLBENABLE ] = {
		.en = "Set if this llbenable is enabled",
		.cn = "控制SMTP服务",
	},

	[ LIBCLI_SYSCONFIG_SET_ENABLE_ON ] = {
		.en = "LLB Service enable",
		.cn = "启用Sysconfig服务",
	},

	[ LIBCLI_SYSCONFIG_SET_ENABLE_OFF ] = {
		.en = "LLB Service disable",
		.cn = "禁用Sysconfig服务",
	},

	[ LIBCLI_SYS_SYSLOG_SERVER_SET ] = {
		.en = "Set System syslog_server",
		.cn = "设置系统日志服务器",
	},

	[ LIBCLI_SYS_DATE_SET ] = {
		.en = "Set System date",
		.cn = "设置系统日期",
	},

	[ LIBCLI_SYS_TIME_SET ] = {
		.en = "Set System time",
		.cn = "设置系统时间",
	},

	[ LIBCLI_SYS_HOSTNAME_SET ] = {
		.en = "Set Hostname",
		.cn = "设置计算机名",
	},

	[ LIBCLI_SYS_SHOW_DATETIME ] = {
		.en = "Show system date and time",
		.cn = "显示日期和时间",
	},

	[ LIBCLI_SYS_SHOW_LICENSE ] = {
		.en = "Show license",
		.cn = "显示license",
	},
	[ LIBCLI_SYS_SHOW_SERIALNUM ] = {
		.en = "Show Serial Number",
		.cn = "显示序列号",
	},

	[ LIBCLI_SYS_SHOW_SYSLOG_SERVER_INFO ] = {
		.en = "Show Syslog_server information",
		.cn = "显示系统日志配置信息",
	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL ] = {
		.en = "Set TCP congestion control",
		.cn = "设置TCP拥堵控制算法",

	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL_BIC ] = {
		.en = "Set TCP congestion control to 'Binary Increase Congestion control'",
		.cn = "设置TCP拥堵控制算法为'Binary Increase Congestion control'",
	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL_CUBIC ] = {
		.en = "Set TCP congestion control to 'cubic tcp'",
		.cn = "设置TCP拥堵控制算法为'cubic-tcp'",
	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL_HTCP ] = {
		.en = "Set TCP congestion control to 'h-tcp'",
		.cn = "设置TCP拥堵控制算法为'h-tcp'",
	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL_HYBLA ] = {
		.en = "Set TCP congestion control to 'tcp-hybla'",
		.cn = "设置TCP拥堵控制算法为'tcp-hybla'",
	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL_VEGAS ] = {
		.en = "Set TCP congestion control to 'tcp-vegas'",
		.cn = "设置TCP拥堵控制算法为'tcp-vegas'",
	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL_VENO ] = {
		.en = "Set TCP congestion control to 'tcp-veno'",
		.cn = "设置TCP拥堵控制算法为'tcp-veno'",
	},

	[ LIBCLI_SYS_TCP_CONGESTION_CONTROL_WESTWOOD ] = {
		.en = "Set TCP congestion control to 'tcp-westwood+'",
		.cn = "设置TCP拥堵控制算法为'tcp-westwood+'",
	},

	[ LIBCLI_SNMP_MANAGE_INFO ] = {
		.en = "Manage SNMP Service",
		.cn = "管理SNMP服务",
	},

	[ LIBCLI_SNMP_SET_SHOW ] = {
		.en = "Show SNMP information",
		.cn = "显示SNMP配置信息",
	},

	[ LIBCLI_SNMP_SET_ENABLE ] = {
		.en = "SNMP Service Control",
		.cn = "控制SNMP服务",
	},

	[ LIBCLI_SNMP_SET_ENABLE_ON ] = {
		.en = "SNMP Service enable",
		.cn = "启用SNMP服务",
	},

	[ LIBCLI_SNMP_SET_ENABLE_OFF ] = {
		.en = "SNMP Service disable",
		.cn = "禁用SNMP服务",
	},

	[ LIBCLI_SNMP_SET_TRAP_ENABLE ] = {
		.en = "SNMP Trap Control",
		.cn = "控制SNMP服务",
	},

	[ LIBCLI_SNMP_SET_TRAP_ENABLE_ON ] = {
		.en = "SNMP Trap enable",
		.cn = "启用SNMP Trap",
	},

	[ LIBCLI_SNMP_SET_TRAP_ENABLE_OFF ] = {
		.en = "SNMP Trap disable",
		.cn = "禁用SNMP Trap",
	},

	[ LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PROTOCOL ] = {
		.en = "SNMP Trap v3 privacy protocol(DES,AES)",
		.cn = "SNMP Trap v3 privacy protocol(DES,AES)",
	},

	[ LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PROTOCOL_DES ] = {
		.en = "SNMP Trap v3 DES privacy protocol",
		.cn = "SNMP Trap v3 DES privacy protocol",
	},

	[ LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PROTOCOL_AES ] = {
		.en = "SNMP Trap v3 AES privacy protocol",
		.cn = "SNMP Trap v3 AES privacy protocol",
	},

	[ LIBCLI_SNMP_SET_TRAP_V3_PRIVACY_PASSWORD] = {
		.en = "SNMP Trap v3 privacy password, least 8 bytes",
		.cn = "SNMP Trap v3 privacy protocol, least 8 bytes",
	},

	[ LIBCLI_SNMP_SET_TRAP_V3_USERNAME ] = {
		.en = "SNMP Trap v3 username, least 8 bytes",
		.cn = "SNMP Trap v3 username, least 8 bytes",
	},

	[ LIBCLI_SNMP_SET_TRAP_V3_PASSWORD ] = {
		.en = "SNMP Trap v3 password, least 8 bytes",
		.cn = "SNMP Trap v3 password, least 8 bytes",
	},

	[ LIBCLI_SNMP_SET_TRAP_V3_ENGINEID ] = {
		.en = "SNMP Trap v3 engine id, least 10 bytes",
		.cn = "SNMP Trap v3 engine id, least 10 bytes",
	},

	[ LIBCLI_SNMP_SET_TRAP_MANAGER ] = {
		.en = "SNMP Trap Manager IP",
		.cn = "SNMP Trap 管理IP",
	},

	[ LIBCLI_SNMP_SET_AUTHTYPE ] = {
		.en = "SNMPv3 authenticate type",
		.cn = "设置SNMPv3认证类型",
	},

	[ LIBCLI_SNMP_SET_AUTHTYPE_MD5 ] = {
		.en = "SNMPv3 authenticate type(MD5)",
		.cn = "设置SNMPv3认证类型为MD5",
	},

	[ LIBCLI_SNMP_SET_AUTHTYPE_SHA1 ] = {
		.en = "SNMPv3 authenticate type(SHA1)",
		.cn = "设置SNMPv3认证类型为SHA1",
	},

	[ LIBCLI_SNMP_SET_COMMUNITY ] = {
		.en = "SNMP community name",
		.cn = "SNMP 共同体名称",

	},

	[ LIBCLI_SNMP_SET_ADD ] = {
		.en = "ADD SNMPv3 user or network",
		.cn = "添加SNMPv3用户或网络",
	},

	[ LIBCLI_SNMP_SET_DEL ] = {
		.en = "DEL SNMPv3 user or network",
		.cn = "删除SNMPv3用户或网络",
	},

	[ LIBCLI_SNMP_SET_USER ] = {
		.en = "ADD/DEL SNMPv3 user",
		.cn = "添加或删除SNMPv3类型用户",
	},

	[ LIBCLI_SNMP_SET_USER_ADD ] = {
		.en = "ADD accessible SNMPv3 user, password least 8 bytes",
		.cn = "添加SNMPv3类型用户, 密码最少8字节",
	},

	[ LIBCLI_SNMP_SET_USER_DEL ] = {
		.en = "DEL accessible SNMPv3 user",
		.cn = "删除SNMPv3类型用户",
	},

	[ LIBCLI_SNMP_SET_NETWORK ] = {
		.en = "ADD/DEL accessible network",
		.cn = "添加或删除可访问SNMP服务的网络",

	},

	[ LIBCLI_SNMP_SET_NETWORK_ADD ] = {
		.en = "ADD accessible network",
		.cn = "添加可访问SNMP服务的网络",
	},

	[ LIBCLI_SNMP_SET_NETWORK_DEL ] = {
		.en = "DEL accessible network",
		.cn = "删除可访问SNMP服务的网络",
	},

	[ LIBCLI_HB_MANAGE_INFO ] ={
		.en = "Manage HighAvailable",
		.cn = "管理HA",    
	},

	[ LIBCLI_HB_SET_SHOW ] = {
		.en = "Show HighAvailable Information",
		.cn = "显示HA的状态",
	},

	[ LIBCLI_HB_SET_SELF_MONITOR ] = {
		.en = "HA Local Machine core process monitor, on/off ",
		.cn = "本机核心进程监控",
	},

	[ LIBCLI_HB_SET_SELF_MONITOR_ON ] = {
		.en = "HA Local Machine core process monitor enable",
		.cn = "本机核心进程监控启用",
	},

	[ LIBCLI_HB_SET_SELF_MONITOR_OFF ] = {
		.en = "HA Local Machine core process monitor disable",
		.cn = "本机核心进程监控禁用",
	},


	[ LIBCLI_HB_SET_CONFIG_SYNC ] = {
		.en = "HA Sync config from MASTER to BACKUP",
		.cn = "同步主机配置到备机",
	},

	[ LIBCLI_HB_SET_ENABLE ] = {
		.en = "HA enable/disable, on/off",
		.cn = "设置HA是否可用",
	},

	[ LIBCLI_HB_SET_ENABLE_ON ] = {
		.en = "HA enable",
		.cn = "设置HA是可用",
	},

	[ LIBCLI_HB_SET_ENABLE_OFF ] = {
		.en = "HA disable",
		.cn = "设置HA不可用",
	},

	[ LIBCLI_HB_SET_INTERFACE ] = {
		.en = "HA communication interface",
		.cn = "设置HA的通信接口",
	},

	[ LIBCLI_HB_SET_ADDIF ] = {
		.en = "HA monitor interface(add)",
		.cn = "添加HA的监视接口",
	},

	[ LIBCLI_HB_SET_DELIF ] = {
		.en = "HA monitor interface(del)",
		.cn = "删除HA的监视接口",
	},

	[ LIBCLI_HB_SET_STATE ] = {
		.en = "HA state, master or backup",
		.cn = "设置HA的状态：master或backup",
	},

	[ LIBCLI_HB_SET_STATE_MASTER ] = {
		.en = "HA state master",
		.cn = "设置HA的状态：master",
	},

	[ LIBCLI_HB_SET_STATE_MASTER_FORCE ] = {
		.en = "HA state master force",
		.cn = "强制设置HA的状态：master",
	},

	[ LIBCLI_HB_SET_STATE_BACKUP ] = {
		.en = "HA state backup",
		.cn = "设置HA的状态：backup",
	},

	[ LIBCLI_HB_SET_STATE_BACKUP_FORCE ] = {
		.en = "HA state backup force",
		.cn = "强制设置HA的状态：backup",
	},

	[ LIBCLI_HB_SET_VRID ] = {
		.en = "HA unique id, (2-254)",
		.cn = "设置HA的编号(2-25)",
	},

	[ LIBCLI_HB_SET_VERIFYCODE ] = {
		.en = "HA communication verifycode, longest 4 bytes",
		.cn = "设置HA的verifycode,最长为4位",
	},

	[ LIBCLI_HB_SET_VIPMASK ] = {
		.en = "HA virtual IP/MASK",
		.cn = "设置HA的虚拟IP/MASK",
	},

	[ LIBCLI_HB_CONN_TABLE ] = {
		.en = "HA layer 4 connection table synchro or not",
		.cn = "设置HA的4层链接表是否同步",
	},

	[ LIBCLI_HB_CONN_TABLE_SYN ] = {
		.en = "HA layer 4 connection table synchro",
		.cn = "设置HA的4层链接表同步",
	},

	[ LIBCLI_HB_CONN_TABLE_NOSYN ] = {
		.en = "HA layer 4 connection table no synchro",
		.cn = "设置HA的4层链接表不同步",
	},


	[ LIBCLI_VLAN_ADD_INFO ] = {
		.en = "Add Virtual Local Area Network (VLAN)",
		.cn = "添加虚拟局域网(VLAN)",
	},

	[ LIBCLI_VLAN_SHOW_INFO ] = {
		.en = "Show VLAN Information",
		.cn = "显示Vlan配置信息",
	},

	[ LIBCLI_VLAN_MANAGE_INFO ] = {
		.en = "Manage Virtual Local Area Network (VLAN)",
		.cn = "管理Vlan",
	},

	[ LIBCLI_VLAN_DELETE_INFO ] = {
		.en = "Delete Virtual Local Area Network (VLAN)",
		.cn = "删除虚拟局域网(VLAN)",
	},

	[ LIBCLI_VLAN_SET_ADD ] = {
		.en = "Add ip address",
		.cn = "向VLAN中添加一个IP地址",
	},

	[ LIBCLI_VLAN_SET_DELETE ] = {
		.en = "Delete ip address",
		.cn = "从VLAN中删除一个IP",
	},

	[ LIBCLI_VLAN_SET_VLANID ] = {
		.en = "Set VlanID",
		.cn = "修改VLANID",
	},


	[ LIBCLI_VLAN_SET_WEB_ENABLE ] = {
		.en = "Set If Web Manager Enabled",
		.cn = "设置是否启用Web管理",
	},

	[ LIBCLI_VLAN_SET_WEB_ENABLE_ON ] = {
		.en = "Set Web Manager Enabled",
		.cn = "设置启用Web管理",
	},

	[ LIBCLI_VLAN_SET_WEB_ENABLE_OFF ] = {
		.en = "Set Web Manager Disabled",
		.cn = "设置禁用Web管理",
	},

	[ LIBCLI_VLAN_SET_SSH_ENABLE ] = {
		.en = "Set If SSH Manager Enabled",
		.cn = "设置是否启用SSH管理",
	} ,

	[ LIBCLI_VLAN_SET_SSH_ENABLE_ON ] = {
		.en = "Set SSH Manager Enabled",
		.cn = "设置启用SSH管理",
	},

	[ LIBCLI_VLAN_SET_SSH_ENABLE_OFF] = {
		.en = "Set SSH Manager Disabled",
		.cn = "设置禁用SSH管理",
	},



	[ LIBCLI_VLAN_SET_GSLB_ENABLE ] = {
		.en = "Set If GSLB Manager Enabled",
		.cn = "设置是否启接受GSLB管理",
	} ,

	[ LIBCLI_VLAN_SET_GSLB_ENABLE_ON ] = {
		.en = "Set GSLB Manager Enabled",
		.cn = "设置接受GSLB的管理",
	},

	[ LIBCLI_VLAN_SET_GSLB_ENABLE_OFF] = {
		.en = "Set GSLB Manager Disabled",
		.cn = "不接受GSLB的管理",
	},



	[ LIBCLI_VLAN_SET_STP_ENABLE ] = {
		.en = "Set stp/rstp enabled",
		.cn = "设置是否启用stp/rstp",
	},

	[ LIBCLI_VLAN_SET_STP_ENABLE_ON ] = {
		.en = "Enable stp/rstp",
		.cn = "启用stp/rstp",
	},

	[ LIBCLI_VLAN_SET_STP_PROTOCOL ] = {
		.en = "Use stp or rstp protocol",
		.cn = "设置使用stp或rstp协议",
	},

	[ LIBCLI_VLAN_SET_STP_PROTOCOL_STP ] = {
		.en = "Set stp protocol",
		.cn = "设置stp协议",
	},

	[ LIBCLI_VLAN_SET_STP_HELLOTIME ] = {
		.en = "Set hello time",
		.cn = "设置hello time",
	},
	[ LIBCLI_VLAN_SET_STP_PRIORITY ] = {
		.en = "Set priority ",
		.cn = "设置优先级",
	},
	[ LIBCLI_VLAN_SET_STP_MAXAGE ] = {
		.en = "Set max age ",
		.cn = "设置max age",
	},
	[ LIBCLI_VLAN_SET_STP_FWD_DELAY ] = {
		.en = "Set forward delay",
		.cn = "设置forward delay",
	},

	[ LIBCLI_PROTOCOL_TCP] = {
		.en = "TCP Protocol",
		.cn = "TCP协议",
	},
	[ LIBCLI_PROTOCOL_FTP] = {
		.en = "FTP Protocol",
		.cn = "FTP协议",
	},

	[ LIBCLI_PROTOCOL_FAST_TCP] = {
		.en = "FAST-TCP Protocol",
		.cn = "快速TCP协议",
	},

	[ LIBCLI_PROTOCOL_UDP ] = {
		.en = "UDP Protocol",
		.cn = "UDP协议",
	},

	[ LIBCLI_PROTOCOL_HTTP ] = {
		.en = "HTTP Protocol",
		.cn = "HTTP协议",
	},

	[ LIBCLI_PROTOCOL_HTTPS ] = {
		.en = "HTTPS Protocol",
		.cn = "HTTPS协议",
	},

	[ LIBCLI_PROTOCOL_SMTP ] = {
		.en = "SMTP Protocol",
		.cn = "SMTP协议",
	},
	[ LIBCLI_PROTOCOL_DNS ] = {
		.en = "DNS Protocol",
		.cn = "DNS协议",
	},
/**--------------------------------------------**/
	[ LIBCLI_PROTOCOL_HTTP_ECV ] = {
		.en = "HTTP-ECV Protocol",
		.cn = "HTTP-ECV协议",
	},
	[ LIBCLI_PROTOCOL_HTTPS_ECV ] = {
		.en = "HTTPS-ECV Protocol",
		.cn = "HTTPS-ECV协议",
	},
	[ LIBCLI_PROTOCOL_ICMP_GW ] = {
		.en = "ICMP_GW Protocol",
		.cn = "ICMP_GW协议",
	},
/**---------------------------------------------**/
	[ LIBCLI_PROTOCOL_DNS ] = {
		.en = "DNS Protocol",
		.cn = "DNS协议",
	},

	[ LIBCLI_PROTOCOL_SSLBRIDGE ] = {
		.en = "SSLBridge Protocol",
		.cn = "SSLBridge协议",
	},

	[ LIBCLI_PROTOCOL_RDPBRIDGE ] = {
		.en = "RDPBridge Protocol",
		.cn = "RDPBridge协议",
	},



	[ LIBCLI_PROTOCOL_ICMP ] = {
		.en = "ICMP Protocol",
		.cn = "ICMP协议",
	},

	[ LIBCLI_PROTOCOL_DHCP ] = {
		.en = "DHCP Protocol",
		.cn = "DHCP协议",
	},

	[ LIBCLI_PROTOCOL_ANY ] = {
		.en = "Any Protocol",
		.cn = "任何协议",
	},

	[ LIBCLI_CACHE_OBJSIZE ] = {
		.en = "Set the limit size of cached-objects",
		.cn = "设置cached-objects的长度限制",
	},

	[ LIBCLI_CACHE_OBJNUM ] = {
		.en = "Set the limit number of cached-objects",
		.cn = "设置cached-objects的数量限制",
	},

	[ LIBCLI_CACHE_EXPIRE ] = {
		.en = "Set timeout for caching expires",
		.cn = "设置缓存超时",
	},

	[ LIBCLI_CACHE_RAMSIZE ] = {
		.en = "Set memory cache size",
		.cn = "设置内存缓存大小",
	},

	[ LIBCLI_CACHE_DISKSIZE ] = {
		.en = "Set disk cache size",
		.cn = "设置硬盘的缓存大小",
	},



	[ LIBCLI_SSL_OFFLOADING ] = {
		.en = "Set if ssl offload is enabled",
		.cn = "设置SSL Offload是否为启用",
	},

	[ LIBCLI_SSL_OFFLOADING_ON ] = {
		.en = "Set ssl offload is enabled",
		.cn = "设置SSL Offload为启用",
	},

	[ LIBCLI_SSL_OFFLOADING_OFF ] = {
		.en = "Set ssl offload is disabled",
		.cn = "设置SSL Offload为禁用",
	},

	[ LIBCLI_SSL_CERTIFICATE ] = {
		.en = "Set ssl certificate name",
		.cn = "设置SSL证书的名字",
	},

	[ LIBCLI_SSL_CLIENT_CERTIFICATE ] = {
		.en = "Set ssl client certificate name",
		.cn = "设置SSL客户端的证书名字",
	},

	[ LIBCLI_SSL_VERIFY_CLIENT ] = {
		.en = "Set ssl verify client certificate or not",
		.cn = "设置是否验证客户端证书",
	},

	[ LIBCLI_SSL_VERIFY_CLIENT_ON ] = {
		.en = "Set ssl verify client certificate enabled",
		.cn = "验证客户端证书",
	},

	[ LIBCLI_SSL_VERIFY_CLIENT_OFF ] = {
		.en = "Set ssl verify client certificate disabled",
		.cn = "不验证客户端证书",
	},

	[ LIBCLI_SSL_PROTOCOL ] = {
		.en = "Set if ssl protocol, eg. SSLv2 SSLv3 TLSv1",
		.cn = "设置SSL协议为SSLv2、SSLv3、TLSv1或其它",
	},

	[ LIBCLI_SSL_PROTOCOL_SSLV2 ] = {
		.en = "Set ssl protocol is SSLv2",
		.cn = "设置支持 SSLv2 协议",
	},

	[ LIBCLI_SSL_PROTOCOL_SSLV3 ] = {
		.en = "Set ssl protocol is is SSLv3",
		.cn = "设置支持 SSLv3 协议",
	},

	[ LIBCLI_SSL_PROTOCOL_TLSV1 ] = {
		.en = "Set ssl protocol TLSv1",
		.cn = "设置支持 TLSv1 协议",
	},

	[ LIBCLI_SSL_SHOW_CERTIFICATE ] ={
		.en = "Show Certificates",
		.cn = "显示证书",
	},

	[ LIBCLI_SSL_SHOW_CRLS ] ={
		.en = "Show Certificate Revocation List",
		.cn = "显示证书吊销列表",
	},

	[ LIBCLI_SSL_ADD_CLIENT_CERTIFICATE ] ={
		.en = "Add Client Certificates",
		.cn = "添加自签名客户端证书",
	},

	[ LIBCLI_SSL_ADD_SERVER_CERTIFICATE ] ={
		.en = "Add Server Certificates",
		.cn = "添加自签名服务器证书",
	},

	[ LIBCLI_SSL_ADD_CRLS ] ={
		.en = "Add Certificate Revocation List",
		.cn = "增加证书吊销列表",
	},

	[ LIBCLI_SSL_DELETE_CERTIFICATE ] ={
		.en = "Delete Certificates",
		.cn = "删除证书",
	},

	[ LIBCLI_SSL_DELETE_CRLS ] ={
		.en = "Delete Certificate Revocation List",
		.cn = "删除证书吊销列表",
	},

	[ LIBCLI_SSL_VSERVER_CRL ] ={
		.en = "Set Certificate Revocation List",
		.cn = "设置证书吊销列表",
	},



	[ LIBCLI_CLIUSERS_SET_PASSWD ] ={
		.en = "Change system password.",
		.cn = "修改system用户密码"
	},


	[ LIBCLI_SYSTEM_SYNCOOKIE ] = {
		.en = "Set SynCookie Enabled/Disabled",
		.cn = "打开或关闭SynCookie功能",
	},

	[ LIBCLI_SYSTEM_SYNCOOKIE_ON ] = {
		.en = "Set SynCookie Enabled",
		.cn = "打开SynCookie功能",
	},

	[ LIBCLI_SYSTEM_SYNCOOKIE_OFF ] = {
		.en = "Set SynCookie Disabled",
		.cn = "关闭SynCookie功能",
	},

	[ LIBCLI_SYSTEM_FORWARD ] = {
		.en = "Set IP Forward Enabled/Disabled",
		.cn = "打开或关闭 IP Forward 功能",
	},

	[ LIBCLI_SYSTEM_FORWARD_ON ] = {
		.en = "Set IP Forward Enabled",
		.cn = "打开 IP Forward 功能",
	},

	[ LIBCLI_SYSTEM_FORWARD_OFF ] = {
		.en = "Set IP Forward Disabled",
		.cn = "关闭 IP Forward 功能",
	},

	[ LIBCLI_MGMT_MANAGE_INFO ] = {
		.en = "Manage mgmt",
		.cn = "管理mgmt",
	},
	
	[ LIBCLI_NTPDATE_MANAGE_INFO ] = {
		.en = "Manage NTPDATE Service.",
		.cn = "NTPDATE客户端服务管理",
	},

	[ LIBCLI_NTPDATE_SET_SHOW ] = {
		.en = "Set NTPDATE Show",
		.cn = "NTPDATE客户端显示配置信息",
	},
	
	[ LIBCLI_NTPDATE_SET_ENABLE ] = {
		.en = "NTPDATE Service Control",
		.cn = "NTPDATE客户端服务控制",
	},

	[ LIBCLI_NTPDATE_SET_ENABLE_ON ] = {
		.en = "NTPDATE Service enable",
		.cn = "NTPDATE客户端服务启动",
	},

	[ LIBCLI_NTPDATE_SET_ENABLE_OFF ] = {
		.en = "NTPDATE Service disable",
		.cn = "NTPDATE客户端服务禁用",
	},

	[ LIBCLI_NTPDATE_SET_SERVER ] = {
		.en = "NTPDATE Set Server Domain or IP Address",
		.cn = "NTPDATE服务端域名或IP设置",
	},

	[ LIBCLI_NTPDATE_SET_CYCLE ] = {
		.en = "NTPDATE Set Synchronous Cycle",
		.cn = "NTPDATE服务同步周期设置"
	},
/***************firewall*******************/
	[ LIBCLI_FIREWALL_ADD_INFO ] = {
		.en = "Add Firewall",
		.cn = "添加地址访问控制单",
	},

	[ LIBCLI_FIREWALL_SHOW_INFO ] = {
		.en = "Show Firewall",
		.cn = "显示地址访问控制单",
	},

  [ LIBCLI_FIREWALL_DELETE_INFO ] = {
		.en = "Delete Firewall",
		.cn = "删除地址访问控制单",
	},

  [ LIBCLI_FIREWALL_MANAGE_INFO ] = {
		.en = "Set Firewall",
		.cn = "设置地址访问控制单",
	},

  [ LIBCLI_FIREWALL_SET_ENABLE ] = {
		.en = "Set Firewall enable",
		.cn = "是否开启访问控制"
	},

  [ LIBCLI_FIREWALL_SET_ENABLE_ON ] = {
		.en = "Set Firewall enable on",
		.cn = "开启访问控制"
	},

  [ LIBCLI_FIREWALL_SET_ENABLE_OFF ] = {
		.en = "Set Firewall enable off",
		.cn = "关闭访问控制"
	},

  [ LIBCLI_FIREWALL_SET_TYPE ] = {
		.en = "Set Firewall type",
		.cn = "设置访问控制的访问类型"
	},

  [ LIBCLI_FIREWALL_SET_TYPE_BLACK ] = {
		.en = "Set Firewall type black",
		.cn = "设置访问控制黑名单"
	},

  [ LIBCLI_FIREWALL_SET_TYPE_WHITE ] = {
		.en = "Set Firewall type white",
		.cn = "设置访问控制白名单"
	},

  [ LIBCLI_FIREWALL_ADD_IPLIST ] = {
		.en = "Add ip to Firewall",
		.cn = "向访问控制中添加ip"
	},

  [ LIBCLI_FIREWALL_DELETE_IPLIST ] = {
		.en = "Del ip from Firewall",
		.cn = "从访问控制中删除ip"
	},

  [ LIBCLI_FIREWALL_IPLIST_PROTOCOL ] = {
		.en = "set ip protocol of Firewall",
		.cn = "设置所添加的ip的访问协议"
	},
/* Used for elastic */

  [ LIBCLI_VMWARE_CONNECTION_LOW ] = {
    .en = "Set connectionsi' low limit of vmware",
    .cn = "设置vmware的connections的低限"
  },

  [ LIBCLI_VMWARE_CONNECTION_HIGH ] = {
    .en = "Set connections' high limit of vmware",
    .cn = "设置vmware的connections的高限"
  },





  [ LIBCLI_VMWARE_NEW_CONNECTION_LOW ] = {
    .en = "Set new connections' low limit of vmware",
    .cn = "设置vmware的new connections的低限"
  },

  [ LIBCLI_VMWARE_NEW_CONNECTION_HIGH ] = {
    .en = "Set new connections' high limit of vmware",
    .cn = "设置vmware的new connections的高限"
  },



  [ LIBCLI_VMWARE_BANDWIDTH_LOW ] = {
    .en = "Set bandwidth' low limit of vmware",
    .cn = "设置vmware的bandwidth的低限"
  },
  [ LIBCLI_VMWARE_BANDWIDTH_HIGH ] = {
    .en = "Set bandwidth' high limit of vmware",
    .cn = "设置vmware的bandwidth的高限"
  },



  [ LIBCLI_VMWARE_VM_ENABLE ] = {
    .en = "Set enable of vmware",
    .cn = "设置vmware的开启与否"
  },

  [ LIBCLI_VMWARE_VM_ENABLE_ON ] = {
    .en = "Set enable of vmware",
    .cn = "开启vmware"
  },

  [ LIBCLI_VMWARE_VM_ENABLE_OFF ] = {
    .en = "Set enable of vmware",
    .cn = "关闭vmware"
  },



  [ LIBCLI_VCENTER_SHOW ] = {
    .en = "Show VCenter Information",
    .cn = "查看VCenter信息"
  },

  [ LIBCLI_VCENTER_ADD ] = {
    .en = "Add VCenter",
    .cn = "添加VCenter"
  },

  [ LIBCLI_VCENTER_DEL ] = {
    .en = "Delete VCenter",
    .cn = "删除sCenter"
  },

  [ LIBCLI_VCENTER_TYPE ] = {
    .en = "Set type of VCenter",
    .cn = "设置VCenter类型"
  },
	
  [ LIBCLI_VCENTER_MANAGE ] = {
    .en = "Manage VCenter",
    .cn = "设置VCenter"
  },

  [ LIBCLI_VCENTER_TYPE_XENSERVER ] = {
    .en = "Set type of VCenter to xenserver",
    .cn = "设置VCenter类型为xenserver"
  },

  [ LIBCLI_VCENTER_TYPE_VCENTER ] = {
    .en = "Set type of VCenter to vcenter",
    .cn = "设置VCenter类型为vcenter"
  },
  
  [ LIBCLI_VCENTER_SERVER ] = {
    .en = "Set server of VCenter",
    .cn = "设置VCenter的server地址"
  },

  [ LIBCLI_VCENTER_USERNAME ] = {
    .en = "Set username of VCenter",
    .cn = "设置VCenter的用户名"
  },

  [ LIBCLI_VCENTER_PASSWORD ] = {
    .en = "Set password of VCenter",
    .cn = "设置VCenter的密码"
  },

  [ LIBCLI_VCENTER_DATACENTER_SHOW ] = {
    .en = "Show datacenter of VCenter",
    .cn = "查看VCenter的datacenter的信息"
  },
/********add by zhangjie**************/
	[ LIBCLI_GSLB_LISTENER_ADD_INFO ] = {
		.en = "Add  GSLB Listener",
		.cn = "添加 GSLB Listener",
	},

	[ LIBCLI_GSLB_LISTENER_SET_PORT ] = {
		.en = "Set GSLB Listener port",
		.cn = "设置 GSLB Listener 端口",
	},

	[ LIBCLI_GSLB_LISTENER_SET_PROTOCOL ] = {
		.en = "Set GSLB Listener protocol",
		.cn = "设置 GSLB Listener 协议",
	},

	[ LIBCLI_GSLB_LISTENER_SHOW_INFO ] = {
		.en = "Show GSLB Listener information",
		.cn = "显示 GSLB Listener 的配置信息",
	},
	[ LIBCLI_GSLB_LISTENER_DELETE_INFO ] = {
		.en = "Delete GSLB Listener ",
		.cn = "删除 GSLB Listener",
	},
	[ LIBCLI_GSLB_LISTENER_MANAGE_INFO ] = {
		.en = "Manage GSLB Listener ",
		.cn = "设置 GSLB Listener",
	},
/***********GSLB_VSERVER********************/

	[ LIBCLI_GSLB_VSERVER_ADD_INFO ] = {
		.en = "Add  GSLB Vserver",
		.cn = "添加 GSLB Vserver",
	},

	[ LIBCLI_GSLB_VSERVER_ADD_SCHEDULER_INFO ] = {
		.en = "Add  GSLB Vserver Scheduler",
		.cn = "添加 GSLB Vserver Scheduler",
	},


	[ LIBCLI_GSLB_VSERVER_SET_ENABLE ] = {
		.en = "Set GSLB Vserver Enable",
		.cn = "设置 GSLB Vserver 开关",
	},

	[ LIBCLI_GSLB_VSERVER_SET_ENABLE_OFF ] = {
		.en = "Set GSLB Vserver Enable OFF",
		.cn = "设置 GSLB Vserver 关闭",
	},
	[ LIBCLI_GSLB_VSERVER_SET_ENABLE_ON ] = {
		.en = "Set GSLB Vserver Enable ON",
		.cn = "设置 GSLB Vserver 开启",
	},


	[ LIBCLI_GSLB_VSERVER_SET_TTL ] = {
		.en = "Set GSLB Vserver TTL",
		.cn = "设置 GSLB Vserver 有效期TTL",
	},

	[ LIBCLI_GSLB_VSERVER_SET_MASTER_SCHEDULE ] = {
		.en = "Set GSLB Vserver Master_scheduler",
		.cn = "设置 GSLB Vserver 主选决策算法名称",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SLAVE_SCHEDULE ] = {
		.en = "Set GSLB Vserver Slave_scheduler",
		.cn = "设置 GSLB Vserver 备选决策算法名称",
	},

	[ LIBCLI_GSLB_VSERVER_SET_FINAL_SCHEDULE ] = {
		.en = "Set GSLB Vserver Final_scheduler",
		.cn = "设置 GSLB Vserver 备选决策算法名称",
	},

	[ LIBCLI_GSLB_VSERVER_SET_POOLNAME ] = {
		.en = "Set GSLB Vserver Poolname",
		.cn = "设置 GSLB Vserver 和vserver关联的应用池名称",
	},

	[ LIBCLI_GSLB_VSERVER_SHOW_INFO ] = {
		.en = "Show GSLB Vserver information",
		.cn = "显示 GSLB Vserver 配置信息",
	},

	[ LIBCLI_GSLB_VSERVER_DELETE_INFO ] = {
		.en = "Delete GSLB Vserver ",
		.cn = "删除 GSLB Vserver",
	},

	[ LIBCLI_GSLB_VSERVER_MANAGE_INFO ] = {
		.en = "Manage GSLB Vserver ",
		.cn = "设置 GSLB Vserver",
	},
	[ LIBCLI_GSLB_VSERVER_SET_SCHED_RR ] = {
		.en = "Round Robin",
		.cn = "轮询",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SCHED_WRR ] = {
		.en = "wrr",
		.cn = "加权轮询",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SCHED_TOPOLOGY ] = {
		.en = "topology",
		.cn = "拓扑",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SCHED_GA ] = {
		.en = "Global Availability",
		.cn = "全局高可用",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SCHED_RETURN_TO_DNS ] = {
		.en = "Return to DNs",
		.cn = "标准DNS",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SCHED_RTT ] = {
		.en = "rtt",
		.cn = "最快响应",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SCHED_LEASTCONNECTION ] = {
		.en = "least Connection",
		.cn = "最小连接",
	},

	[ LIBCLI_GSLB_VSERVER_SET_SCHED_LEASTTHROUGHT ] = {
		.en = "least Throughout",
		.cn = "最小流量",
	},
	[ LIBCLI_GSLB_VSERVER_SET_SCHED_LEASTLOAD ] = {
		.en = "least load",
		.cn = "最小负载",
	},

	[ LIBCLI_GSLB_VSERVER_MULTIIPADDR_ENABLE ] = {
		.en = "Set Multiipaddr_enable",
		.cn = "返回多IP",
	},

	[ LIBCLI_GSLB_VSERVER_MULTIIPADDR_ENABLE_ON ] = {
		.en = "Set Multiipaddr_enable on",
		.cn = "开启返回多IP",
	},

	[ LIBCLI_GSLB_VSERVER_MULTIIPADDR_ENABLE_OFF ] = {
		.en = "Set Multiipaddr_enable off",
		.cn = "关闭返回多IP",
	},
	[ LIBCLI_GSLB_VSERVER_LASTSORT_IPADDR ] = {
		.en = "Set Lastsort_ipaddr",
		.cn = "失效保障IP",
	},

	[ LIBCLI_GSLB_VSERVER_SET_TIMEOUT ] = {
		.en = "Set Persistent timeout",
		.cn = "设置会话保持超时时间",
	},

	[ LIBCLI_GSLB_VSERVER_PERSISTENT_ENABLE ] = {
		.en = "Set Persistent",
		.cn = "设置会话保持",
	},

	[ LIBCLI_GSLB_VSERVER_PERSISTENT_ENABLE_ON ] = {
		.en = "Set Persistent on",
		.cn = "开启基于源地址IP的会话保持",
	},

	[ LIBCLI_GSLB_VSERVER_PERSISTENT_ENABLE_OFF ] = {
		.en = "Set Persistent off",
		.cn = "关闭会话保持功能",
	},

/*************GSLB_SITE*************************/

	[ LIBCLI_GSLB_SITE_ADD_INFO ] = {
		.en = "Add  GSLB Device",
		.cn = "添加 GSLB Device",
	},

	[ LIBCLI_GSLB_SITE_SET_IP ] = {
		.en = "Set GSLB Device IP",
		.cn = "设置 GSLB Device ip地址",
	},

	[ LIBCLI_GSLB_SITE_SET_USERNAME ] = {
		.en = "Set GSLB Device Username",
		.cn = "设置 GSLB Device 用户名",
	},

	[ LIBCLI_GSLB_SITE_SET_PASSWORD ] = {
		.en = "Set GSLB Device Password",
		.cn = "设置 GSLB Device 密码",
	},

	[ LIBCLI_GSLB_SITE_SET_TYPE ] = {
		.en = "Set GSLB Device TYPE",
		.cn = "设置 GSLB Device 类型",
	},

	[ LIBCLI_GSLB_SITE_SET_TYPE_SLB ] = {
		.en = "Set GSLB Device TYPE SLB",
		.cn = "设置 GSLB Device 为虚拟服务器类型",
	},

	[ LIBCLI_GSLB_SITE_SET_TYPE_GSLB ] = {
		.en = "Set GSLB Device TYPE GSLB",
		.cn = "设置 GSLB Device 为全局虚拟服务器类型",
	},

	[ LIBCLI_GSLB_SITE_SHOW_INFO ] = {
		.en = "Show GSLB Device information",
		.cn = "显示 GSLB Device 信息",
	},
	[ LIBCLI_GSLB_SITE_DELETE_INFO ] = {
		.en = "Delete GSLB Device ",
		.cn = "删除 GSLB Device",
	},

	[ LIBCLI_GSLB_SITE_MANAGE_INFO ] = {
		.en = "Manage GSLB Device ",
		.cn = "设置 GSLB Device",
	},
	/*********GSLB POOL**********************/
	[ LIBCLI_GSLB_POOL_ADD_INFO ] = {
		.en = "Add  GSLB Pool",
		.cn = "添加 GSLB Pool",
	},

	[ LIBCLI_GSLB_POOL_SHOW_INFO ] = {
		.en = "Show GSLB Pool information",
		.cn = "显示 GSLB Pool的配置信息",
	},
	[ LIBCLI_GSLB_POOL_DELETE_INFO ] = {
		.en = "Delete GSLB Pool ",
		.cn = "删除 GSLB Pool",
	},

	[ LIBCLI_GSLB_POOL_MANAGE_INFO ] = {
		.en = "Manage GSLB Pool ",
		.cn = "设置 GSLB Pool",
	},
	/**********GSLB RSERVER********************/
	[ LIBCLI_GSLB_RSERVER_ADD_INFO ] = {
		.en = "Add GSLB Rserver",
		.cn = "添加 GSLB Rserver",
	},

	[ LIBCLI_GSLB_RSERVER_SHOW_INFO ] = {
		.en = "Show GSLB Rserver information",
		.cn = "显示 GSLB Rserver的配置信息",
	},
	[ LIBCLI_GSLB_RSERVER_DELETE_INFO ] = {
		.en = "Delete GSLB Rserver",
		.cn = "删除 GSLB Rserver",
	},
	[ LIBCLI_GSLB_RSERVER_MANAGE_INFO ] = {
		.en = "Manage GSLB Rserver",
		.cn = "设置 GSLB Rserver",
	},
	[ LIBCLI_GSLB_RSERVER_SET_SITENAME ] = {
		.en = "Set GSLB Rserver sitename",
		.cn = "设置 GSLB Rserver 站点",
	},
	[ LIBCLI_GSLB_RSERVER_SET_WEIGHT ] = {
		.en = "Set GSLB Rserver weight",
		.cn = "设置 GSLB Rserver 权重",
	},
	[ LIBCLI_GSLB_RSERVER_SET_HEALTHCHECK ] = {
		.en = "Set GSLB Rserver healthcheck",
		.cn = "设置 GSLB Rserver 健康检查",
	},
	[ LIBCLI_GSLB_POOL_SET_HEALTHCHECK ] = {
		.en = "Set GSLB Pool healthcheck",
		.cn = "设置 GSLB Pool 健康检查",
	},
	[ LIBCLI_GSLB_RSERVER_SET_ENABLE ] = {
		.en = "Set GSLB Rserver Enable",
		.cn = "设置 GSLB Rserver 开关",
	},
	[ LIBCLI_GSLB_RSERVER_SET_MAXREQ ] = {
		.en = "Set GSLB Rserver maxreq",
		.cn = "设置 GSLB Rserver 最大请求数",
	},
	[ LIBCLI_GSLB_RSERVER_SET_TYPE ] = {
		.en = "Set GSLB Rserver Type",
		.cn = "设置 GSLB Rserver 类型",
	},

	[ LIBCLI_GSLB_RSERVER_SET_VSNAME ] = {
		.en = "Set GSLB Rserver Vs Name",
		.cn = "设置 GSLB Rserver 真实服务器的名称",
	},

	[ LIBCLI_GSLB_RSERVER_SET_VSNAME_IP ] = {
		.en = "Set GSLB Rserver Vs IP",
		.cn = "设置 GSLB Rserver 真实服务器的ip",
	},
	
  	[ LIBCLI_GSLB_RSERVER_SET_ORDER ] = {
		.en = "Set GSLB Rserver Order",
		.cn = "设置 真实服务器 GA调度算法的顺序",
	},
	[ LIBCLI_GSLB_RSERVER_GET_VSLIST ] = {
		.en = "Get SLB Vserver List",
		.cn = "获得SLB Rserver列表",
	},
/************BIND9***************************/	
	[ LIBCLI_BIND9_ADD_INFO ] = {
		.en = "Add  BIND9 Domain",
		.cn = "添加 BIND9",
	},

	[ LIBCLI_BIND9_ADD_CHILD_INFO ] = {
		.en = "Add  BIND9 record or acl",
		.cn = "添加 BIND9 record,acl",
	},

	[ LIBCLI_BIND9_DEL_CHILD_INFO ] = {
		.en = "Del  BIND9 record or acl",
		.cn = "删除 BIND9 record,acl",
	},

	[ LIBCLI_BIND9_MANAGE_INFO ] = {
		.en = "Set  BIND9 Domain",
		.cn = "设置 BIND9 的配置信息",
	},

	[ LIBCLI_BIND9_SHOW_INFO ] = {
		.en = "Show BIND9 Domain information",
		.cn = "设置 BIND9 协的配置信息",
	},

	[ LIBCLI_BIND9_DELETE_INFO ] = {
		.en = "Delete BIND9 Domain",
		.cn = "删除 BIND9",
	},
	[ LIBCLI_BIND9_SET_NAME ] = {
		.en = "Set  BIND9 Name",
		.cn = "设置 BIND9 的Name属性",
	},
	[ LIBCLI_BIND9_SET_TTL ] = {
		.en = "Set  BIND9 TTL",
		.cn = "设置 BIND9 的TTL属性",
	},

	[ LIBCLI_BIND9_SET_VIEW ] = {
		.en = "Set  BIND9 VIEW",
		.cn = "设置 BIND9 的VIEW属性",
	},

	[ LIBCLI_BIND9_SET_ALLOW_RECURSION_INFO ] = {
		.en = "Set  BIND9 Allow_Recursion",
		.cn = "设置 BIND9 的Allow_Recursion属性",
	},
	[ LIBCLI_BIND9_SET_ALLOW_RECURSION_INFO_ON ] = {
		.en = "Set  BIND9 Allow_Recursion on",
		.cn = "开启 BIND9 递归查询",
	},
	[ LIBCLI_BIND9_SET_ALLOW_RECURSION_INFO_OFF ] = {
		.en = "Set  BIND9 Allow_Recursion off",
		.cn = "关闭 BIND9 递归查询",
	},
/***********BIND9 RECORD**********************/
	[ LIBCLI_BIND9_RECORD_ADD_INFO ] = {
		.en = "Add  BIND9 resource_record",
		.cn = "添加 BIND9_RECORD",
	},

	[ LIBCLI_BIND9_RECORD_ADD_SOA_INFO ] = {
		.en = "Add  BIND9 SOA_record",
		.cn = "添加 BIND9_RECORD",
	},


	[ LIBCLI_BIND9_RECORD_MANAGE_INFO ] = {
		.en = "Set  BIND9 record ",
		.cn = "设置 BIND9_RECORD 的配置信息",
	},

	[ LIBCLI_BIND9_RECORD_SHOW_INFO ] = {
		.en = "Show BIND9_RECORD Info",
		.cn = "设置 BIND9_RECORD 协的配置信息",
	},

	[ LIBCLI_BIND9_RECORD_DELETE_INFO ] = {
		.en = "Delete BIND9 record ",
		.cn = "删除 BIND9_RECORD",
	},
	[ LIBCLI_BIND9_RECORD_SET_NAME ] = {
		.en = "Set BIND9_RECORD Name",
		.cn = "设置 BIND9_RECORD 的Name属性",
	},
	[ LIBCLI_BIND9_RECORD_SET_TYPE ] = {
		.en = "Set BIND9_RECORD TYPE",
		.cn = "设置 BIND9_RECORD 的TYPE属性",
	},
	[ LIBCLI_BIND9_RECORD_SET_PORT] = {
		.en = "Set BIND9_RECORD PORT",
		.cn = "设置 BIND9_RECORD 的PORT属性",
	},


	[ LIBCLI_BIND9_RECORD_SET_VALUE ] = {
		.en = "Set BIND9_RECORD VALUE",
		.cn = "设置 BIND9_RECORD 的VALUE属性",
	},
/***********BIND9 ACL*************************/
	[ LIBCLI_BIND9_ACL_ADD_INFO ] = {
		.en = "Add  BIND9 acl",
		.cn = "添加 BIND9_ACL",
	},

	[ LIBCLI_BIND9_ACL_MANAGE_INFO ] = {
		.en = "Set  BIND9_ACL ",
		.cn = "设置 BIND9_ACL 的配置信息",
	},

	[ LIBCLI_BIND9_ACL_SHOW_INFO ] = {
		.en = "Show BIND9_ACL Info",
		.cn = "设置 BIND9_ACL 协的配置信息",
	},

	[ LIBCLI_BIND9_ACL_DELETE_INFO ] = {
		.en = "Delete BIND9 acl ",
		.cn = "删除 BIND9_ACL",
	},

/*********bind9 soa record********************/

  [ LIBCLI_BIND9_SOA_RECORD_SET_MAIL ] = {
		.en = "Set  Soa Mail ",
		.cn = "设置 Soa记录的邮件",
	},

  [ LIBCLI_BIND9_SOA_RECORD_SET_REFRESH ] = {
		.en = "Set  Soa Refresh ",
		.cn = "设置 Soa 的更新频率",
	},

  [ LIBCLI_BIND9_SOA_RECORD_SET_RETRY ] = {
		.en = "Set  Soa Retry ",
		.cn = "设置 Soa记录的失败重新尝试时间",
	},

  [ LIBCLI_BIND9_SOA_RECORD_SET_SERIAL ] = {
		.en = "Set  Soa Serial ",
		.cn = "设置 Soa记录的序列号",
	},

  [ LIBCLI_BIND9_SOA_RECORD_SET_TTL ] = {
		.en = "Set  Soa Ttl",
		.cn = "设置 Soa 记录的最小存活时间",
	},

  [ LIBCLI_BIND9_SOA_RECORD_SET_EXPIRE ] = {
		.en = "Set  Soa Expire ",
		.cn = "设置 Soa 的超时时间",
	},

/***********BIND9 ACL*************************/
	[ LIBCLI_GSLB_GROUP_SHOW_INFO ] = {
		.en = "Show Device of GSLB Group information",
		.cn = "显示 GSLB GROUP 信息",
	},

	[ LIBCLI_GSLB_GROUP_MANAGE_INFO ] = {
		.en = "Manage GSLB GROUP ",
		.cn = "设置 GSLB_GROUP 的配置信息",
	},

	[ LIBCLI_GSLB_GROUP_ADD_INFO ] = {
		.en = "ADD GSLB_GROUP",
		.cn = " 添加同步组",
	},

	[ LIBCLI_GSLB_GROUP_DELETE_INFO ] = {
		.en = "Delete GSLB Group ",
		.cn = "删除 同步组",
	},
	[ LIBCLI_GSLB_GROUP_DELETE_DEVICE_INFO ] = {
		.en = "Delete Device of GSLB Group ",
		.cn = "删除 同步组中的设备",
	},
	[ LIBCLI_GSLB_GROUP_ADD_DEVICE_INFO ] = {
		.en = "Add Device of GSLB Group ",
		.cn = "向同步组中添加设备",
	},
/*************TOPOLOGY*******************************/
	[ LIBCLI_TOPOLOGY_SHOW_INFO ] = {
		.en = "Show Topology information",
		.cn = "显示 地理拓扑的配置信息",
	},

	[ LIBCLI_TOPOLOGY_SET_INFO ] = {
		.en = "Set Topology information",
		.cn = "设置地理拓扑的相关的配置信息",
	},

	[ LIBCLI_TOPOLOGY_ADD_INFO ] = {
		.en = "Add Topology information",
		.cn = "添加地理拓扑的相关的配置信息",
	},

	[ LIBCLI_TOPOLOGY_DELETE_INFO ] = {
		.en = "Delete Topology information",
		.cn = "删除地理拓扑中的相关配置信息",
	},
	
/**************tp_node******************************/
	[ LIBCLI_TP_NODE_ADD_INFO ] = {
		.en = "Add  TP_NODE",
		.cn = "添加 TP_NODE",
	},

	[ LIBCLI_TP_NODE_MANAGE_INFO ] = {
		.en = "Set TP_NODE information",
		.cn = "设置 TP_NODE 的配置信息",
	},

	[ LIBCLI_TP_NODE_SHOW_INFO ] = {
		.en = "Show TP_NODE information",
		.cn = "设置 TP_NODE 协的配置信息",
	},

	[ LIBCLI_TP_NODE_SET_NETWORK ] = {
		.en = "Set TP_NODE network ",
		.cn = "设置地理拓扑的ip地址",
	},

	[ LIBCLI_TP_NODE_SET_AREA ] = {
		.en = "Set TP_NODE area ",
		.cn = "设置地理拓扑的地理区域",
	},

	[ LIBCLI_TP_NODE_SET_CARRIER ] = {
		.en = "Set TP_NODE carrier",
		.cn = "设置地理拓扑的代理运营商",
	},
/************tp_policy******************************/
	[ LIBCLI_TP_POLICY_SET_POLICY ] = {
		.en = "Set TP_POLICY policy",
		.cn = "设置 TP_POLICY 的解析策略",
	},

	[ LIBCLI_TP_POLICY_SET_NETWORK ] = {
		.en = "Set IP_POLICY network ",
		.cn = "设置 TP_POLICY的 网络",
	},

	[ LIBCLI_TP_POLICY_SET_POLICY_SELF ] = {
		.en = "Set TP_POLICY policy to self",
		.cn = "设置 TP_POLICY 的解析策略为self",
	},

	[ LIBCLI_TP_POLICY_SET_POLICY_NETWORK ] = {
		.en = "Set TP_POLICY policy to Special network",
		.cn = "设置 TP_POLICY 的解析策略Special network",
	},

	[ LIBCLI_TP_POLICY_SET_POLICY_SELF ] = {
		.en = "Set TP_POLICY policy to network",
		.cn = "设置 TP_POLICY 的解析策略为network",
	},
// add show		
	[ LIBCLI_TP_POLICY_SHOW_INFO ] = {
		.en = "Show TP_POLICY information",
		.cn = "设置 TP_POLICY 协的配置信息",
	},
// add manage
	[ LIBCLI_TP_POLICY_MANAGE_INFO ] = {
		.en = "Manage TP_POLICY ",
		.cn = "设置 TP_POLICY 的配置信息",
	},
/*****************llb_pool***************************/
	[ LIBCLI_LLB_POOL_ADD_INFO ] = {
		.en = "Add  LLB Pool",
		.cn = "添加 链路负载均衡应用池",
	},

	[ LIBCLI_LLB_POOL_MANAGE_INFO ] = {
		.en = "Manage LLB Pool ",
		.cn = "设置 链路负载均衡应用池 的配置信息",
	},

	[ LIBCLI_LLB_POOL_SHOW_INFO ] = {
		.en = "Show LLB POOL information",
		.cn = "显示 应用池 的配置信息",
	},

	[ LIBCLI_LLB_POOL_DELETE_INFO ] = {
		.en = "Delete LLB Pool ",
		.cn = "删除 LLB POOL",
	},
	
	[ LIBCLI_LLB_POOL_SET_HEALTHCHECK ] = {
		.en = "Set LLB POOL Healthcheck",
		.cn = "设置应用池的健康检查",
	},
	[ LIBCLI_LLB_POOL_SET_REALSERVER ] = {
		.en = "Set LLB RealServer of LLB Pool",
		.cn = "设置应用池中的真实服务器",
	},
/*****************llb_rserver************************/
	[ LIBCLI_LLB_RSERVER_ADD_INFO ] = {
		.en = "Add  LLB Rserver to a LLB Pool",
		.cn = "向应用池添加真实服务器",
	},

	[ LIBCLI_LLB_POOL_SET_RSERVER_SHOW ] = {
		.en = "Show LLB the Rserver",
		.cn = "显示应用池中的真实服务器",
	},

	[ LIBCLI_LLB_RSERVER_MANAGE_INFO ] = {
		.en = "Set LLB Rserver",
		.cn = "设置 应用池中真是服务器的配置信息",
	},

	[ LIBCLI_LLB_RSERVER_SHOW_INFO ] = {
		.en = "Show LLB Rserver Info",
		.cn = "显示 应用池中真实服务器的配置信息",
	},

	[ LIBCLI_LLB_RSERVER_DELETE_INFO ] = {
		.en = "Delete LLB Rserver From the LLB Pool ",
		.cn = "从应用池中删除真实服务器 ",
	},
  [ LIBCLI_LLB_RSERVER_SET_HEALTHCHECK ] = {
		.en = "Set LLB Rserver Healthcheck ",
		.cn = "设置 真实服务器 的健康检查 ",
	},
  [ LIBCLI_LLB_RSERVER_SET_BANDWIDTH ] = {
		.en = "Set LLB Rserver Bandwidth ",
		.cn = "设置 真实服务器 的最大带宽 ",
	},
  [ LIBCLI_LLB_RSERVER_SET_WEIGHT ] = {
		.en = "Set LLB Rserver Weight ",
		.cn = "设置 真实服务器 的权重 ",
	},
  [ LIBCLI_LLB_RSERVER_SET_ENABLE ] = {
		.en = "Set LLB Rserver Enable ",
		.cn = "设置 真实服务器 的开关 ",
	},
  [ LIBCLI_LLB_RSERVER_SET_ENABLE_ON ] = {
		.en = "Set LLB Rserver Enable On",
		.cn = "开启 真实服务器 ",
	},
  [ LIBCLI_LLB_RSERVER_SET_ENABLE_OFF ] = {
		.en = "Set LLB Rserver Enable Off",
		.cn = "关闭 真实服务器 ",
	},
  [ LIBCLI_LLB_RSERVER_SET_ORDER ] = {
		.en = "Set LLB Rserver Order",
		.cn = "设置 真实服务器 GA调度算法的顺序",
	},

/*****************llb_vserver************************/
	[ LIBCLI_LLB_VSERVER_ADD_INFO ] = {
		.en = "Add  LLB Vserver information",
		.cn = "添加 虚拟服务器",
	},
	[ LIBCLI_LLB_VSERVER_SHOW_INFO ] = {
		.en = "Show LLB Vserver information",
		.cn = "显示虚拟服务器的配置信息",
	},
	[ LIBCLI_LLB_VSERVER_DELETE_INFO ] = {
		.en = "Delete LLB Vserver",
		.cn = "删除虚拟服务器",
	},
	[ LIBCLI_LLB_VSERVER_MANAGE_INFO ] = {
		.en = "Manage LLB Vserver",
		.cn = "设置虚拟服务器",
	},
	[ LIBCLI_LLB_VSERVER_SET_PROTOCOL ] = {
		.en = "Set LLB Vserver protocol",
		.cn = "设置 虚拟服务器的协议",
	},
	[ LIBCLI_LLB_VSERVER_SET_ENABLE ] = {
		.en = "Set Vserver Enable",
		.cn = "设置虚拟服务器的开关",
	},
	[ LIBCLI_LLB_VSERVER_SET_ENABLE_ON ] = {
		.en = "Set Vserver Enable on",
		.cn = "开启虚拟服务器",
	},
	[ LIBCLI_LLB_VSERVER_SET_ENABLE_OFF ] = {
		.en = "Set Vserver Enable off",
		.cn = "关闭虚拟服务器",
	},
	[ LIBCLI_LLB_VSERVER_SET_NEXT_IP ] = {
		.en = "Set Vserver Next ip",
		.cn = "设置、虚拟服务器的下一跳IP",
	},
	[ LIBCLI_LLB_VSERVER_SET_NEXT_PORT ] = {
		.en = "Set Vserver destport",
		.cn = "设置、虚拟服务器的下一跳PORT",
	},

	[ LIBCLI_LLB_VSERVER_SET_POOL ] = {
		.en = "Set LLB Vserver poolname",
		.cn = "设置 LLB Vserver 和vserver关联的应用池名称",
	} ,
	[ LIBCLI_LLB_VSERVER_ADD_CONF ] = {
		.en = "Add LLB Vserver configuration",
		.cn = "添加 LLB Vserver configuration",
	}, 
	[ LIBCLI_LLB_VSERVER_ADD_SCHEDULER ] = {
		.en = "Add LLB Vserver Scheduler",
		.cn = "添加 LLB Vserver Scheduler",
	}, 
	[ LIBCLI_LLB_VSERVER_ADD_SOURCEIP ] = {
		.en = "Add LLB Vserver sourceip",
		.cn = "添加 LLB Vserver sourceip",
	}, 
	[ LIBCLI_LLB_VSERVER_DEL_CONF ] = {
		.en = "Del LLB Vserver configuration",
		.cn = "删除LLB VSERVER configuration",
	}, 
	[ LIBCLI_LLB_VSERVER_DEL_SOURCEIP ] = {
		.en = "Del LLB Vserver sourceip",
		.cn = "删除LLB Vserver sourceip",
	}, 
	[ LIBCLI_LLB_VSERVER_SNAT_ENABLE ] = {
		.en = "LLB VSERVER SNAT enable",
		.cn = "开启或关闭 LLB VSERVER SNAT",
	}, 
	[ LIBCLI_LLB_VSERVER_SNAT_ENABLE_ON ] = {
		.en = "LLB VSERVER SNAT enable on",
		.cn = "开启 LLB VSERVER SNAT",
	}, 
	[ LIBCLI_LLB_VSERVER_SNAT_ENABLE_OFF ] = {
		.en = "LLB VSERVER SNAT enable off",
		.cn = "关闭 LLB VSERVER SNAT",
	}, 

	[ LIBCLI_LLB_VSERVER_SET_MASTER_SCHEDULER ] = {
		.en = "Set Vserver Master Scheduler",
		.cn = "设置虚拟服务器的第一调度算法",
	},
	[ LIBCLI_LLB_VSERVER_SET_SLAVE_SCHEDULER ] = {
		.en = "Set Vserver Slave Scheduler",
		.cn = "设置虚拟服务器的第二调度算法",
	},
	[ LIBCLI_LLB_VSERVER_SET_FINAL_SCHEDULER ] = {
		.en = "Set Vserver Final Scheduler",
		.cn = "设置虚拟服务器的最终调度算法",
	},
	[ LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE ] = {
		.en = "Set Persistent",
		.cn = "设置会话保持",
	},
	[ LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE_OFF ] = {
		.en = "Close Persistent",
		.cn = "关闭会话保持",
	},

	[ LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE_IP_ON ] = {
		.en = "Set Persistent ip on",
		.cn = "开启会话保持",
	},

	[ LIBCLI_LLB_VSERVER_PERSISTENT_ENABLE_SOURCE_DEST_IP_ON ] = {
		.en = "Set Persistent source_dest_ip on",
		.cn = "开启会话保持",
	},

	[ LIBCLI_LLB_VSERVER_SET_TIMEOUT ] = {
		.en = "Set Persistent timeout",
		.cn = "设置会话保持超时时间",
	},

	[ LIBCLI_LLB_VSERVER_SET_RTT_TIMEOUT ] = {
		.en = "Set RTT schedule timeout",
		.cn = "Set RTT schedule timeout",
	},

	/****** LLB SNAT  ***************/
	[ LIBCLI_LLB_SNAT_DELETE_INFO ] = {
		.en = "Delete LLB SNAT",
		.cn = "删除 LLB SNA_INFO",
	},
	[ LIBCLI_LLB_SNAT_ADD_INFO ] = {
		.en = "Add  LLB SNAT",
		.cn = "添加智能SNAT",
	},
	[ LIBCLI_LLB_SNAT_SET_SRCFROM_INFO ] = {
		.en = "Set LLB SNAT source start address",
		.cn = "设置智能SNAT源地址开始地址",
	},
	[ LIBCLI_LLB_SNAT_SET_SRCTO_INFO ] = {
		.en = "Set LLB SNAT source end address",
		.cn = "设置智能SNAT源地址结束地址",
	},
	[ LIBCLI_LLB_SNAT_SET_TYPE_INFO ] = {
		.en = "Set LLB SNAT type",
		.cn = "设置智能SNAT类型",
	},
	[ LIBCLI_LLB_SNAT_SET_TYPE_SNAT_INFO ] = {
		.en = "Set LLB SNAT type SNAT",
		.cn = "设置智能SNAT静态SNAT",
	},
	[ LIBCLI_LLB_SNAT_SET_TYPE_NONAT_INFO ] = {
		.en = "Set LLB SNAT type no SNAT",
		.cn = "设置智能SNAT无NAT",
	},
	[ LIBCLI_LLB_SNAT_SET_DESTFROM_INFO ] = {
		.en = "Set LLB SNAT destfrom info",
		.cn = "设置智能SNAT翻译起始地址",
	},
	[ LIBCLI_LLB_SNAT_SET_DESTTO_INFO ] = {
		.en = "Set LLB SNAT destto infoc",
		.cn = "设置智能SNAT翻译结束地址",
	},
	[ LIBCLI_LLB_SNAT_SET_BINDTO_INFO ] = {
		.en = "Set LLB SNAT bind to link",
		.cn = "设置智能SNAT绑定的链路",
	},
	[ LIBCLI_LLB_SNAT_SET_SCHEDULE_INFO ] = {
		.en = "Set LLB SNAT schedule type",
		.cn = "设置智能SNAT调度类型",
	},
	[ LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_IP_RR_INFO ] = {
		.en = "Set LLB SNAT schedule type for IP RR",
		.cn = "设置智能SNAT的调度类型为IP轮询",
	},
	[ LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_CONN_RR_INFO ] = {
		.en = "Set LLB SNAT schedule type for connection RR",
		.cn = "设置智能SNAT调度类型为连接轮询",
	},
	[ LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_LC_INFO ] = {
		.en = "Set LLB SNAT schedule type for least connetions",
		.cn = "设置智能SNAT的调度类型为最小连接",
	},
	[ LIBCLI_LLB_SNAT_SET_SCHEDULE_TYPE_SRC_PORT_INFO ] = {
		.en = "Set LLB SNAT schedule type for source port persistent",
		.cn = "设置智能SNAT的调度类型为源端口保持",
	},
	[ LIBCLI_LLB_SNAT_SHOW_INFO ] = {
		.en = "Show LLB SNAT information",
		.cn = "展示智能SNAT的信息",
	},
};
