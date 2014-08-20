/* 
 * The file subjoin snmpwalk.c jointly get info cpu and memory
 * information etc.
 * @auther:zhangly
 * @date:2014.7.31
 */
#ifndef __snmpwalk_h__
#define __snmpwalk_h__
#include "common/common.h"
#include "loadbalance/apppool.h"
struct get_info{
	/* hold node of mib */
	char *oid;
	/*
	 * hold function for handle info assign into
	 * pointer of function global varialbe global_get_info
	 */
	int (*get_handle)(const u_char *buf);
};
/* snmp show promty infomation */
enum snmp_show{
	SNMP_HIDE = 0,
	SNMP_SHOW,
};

struct mibarg {
	char *mib;
	int num;
};
#define ORIGIN_WEGHT	(20)

/* 
 * in function snmpwalk of snmpwalk.c handle data
 * .e.g : global_get_info = cpu.get_handle get info for cpu
 */
extern int mibs_snmpwalk(int snmp_argc, char *snmp_argv[], int mib_argc, struct mibarg *mib_argv, int flag);
extern int check_snmp(struct rserver *rserver);
#endif
