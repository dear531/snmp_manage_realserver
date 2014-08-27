#ifndef __WALK4RS_H__
#define __WALK4RS_H__
#define log_message(format, args...) \
	do{ \
		SMT_LOG_INFO( SMT_NAME_VMWARE_DAEMON, format, ##args); \
	}while(0)
#endif
