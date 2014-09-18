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
/* snmp show promty infomation */
enum snmp_show{
	SNMP_HIDE = 0,
	SNMP_SHOW,
};

extern long int check_snmp(struct rserver *rserver, int mode);
#endif
