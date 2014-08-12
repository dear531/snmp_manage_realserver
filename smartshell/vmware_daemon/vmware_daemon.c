
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <time.h>
#include <pwd.h>
#include <pthread.h>
#include <syslog.h>

#include "vmware_daemon.h"

/* vmware */
#include "vmware_if.h"
#include "vmware.h"

/* xen */
#include "xenserver_if.h"

/* vcenter */
#include "vcenter_if.h"

#include "common/base64.h"
#include "common/common.h"
#include "common/event.h"
#include "common/module.h"
#include "common/logger.h"
#include "common/list.h"
#include "loadbalance/vserver.h"
#include "loadbalance/apppool.h"
#include "loadbalance/vcenter.h"
#include "loadbalance/rule.h"
#include "license/license.h"
#include "smartlog.h"

#define DEFAULT_COUNT 60  /** sampling count **/  /* 取样次数 */

#define DEFAULT_INTERVAL 3 /** sampling interval **/  /* 取样间隔 */

static pthread_mutex_t vcenter_flush_lock = PTHREAD_MUTEX_INITIALIZER;

static int restart = 0;
static LIST_HEAD(statistics);
static LIST_HEAD(vcenter_queue);
static LIST_HEAD(vs_queue);
static LIST_HEAD(pool_queue);
static LIST_HEAD(rule_queue);

static struct vs_stat *vs_stat_search(char *name);
static void pool_stat_clear(struct vs_stat *stat);
static void __pool_stat_remove(struct pool_stat *stat);
static void __vs_stat_remove(struct vs_stat *vs_stat);
static void sync_vs_stat(struct list_head *vs_queue, struct list_head *pool_queue);
static void sync_pool_stat(struct vs_stat *stat, struct vserver *vs,
		struct list_head *pool_queue);
//static int vm_stop(struct pool_stat *stat, struct apppool *pool, struct rserver *rs);
static void * vm_stop(void *data);
static int apppool_all_down_check(struct apppool *pool);
//static int apppool_stat_switch_check(struct pool_stat *stat);
static void * start_vm(void *vdata /* vm_start_data_t */);
//static void * start_vm_for_master_pool(void *vdata /* vm_start_data_t */);
static int stop_realserver(struct pool_stat *stat, struct apppool *pool, struct vserver *vs);
static unsigned short elastic_value_valid_check( unsigned long vm_conn_low, unsigned long vm_conn_high, 
		unsigned long vm_newconn_low, unsigned long vm_newconn_high, unsigned long vm_band_low, unsigned long vm_band_high);
static int notify_daemon4(char *poolname, struct rserver *rs, int action);


static void vs_stat_print()
{
	DP("func:%s line:%d\n", __func__, __LINE__);
	struct vs_stat *vs_stat;
	struct pool_stat *pool_stat;
	struct vmx_stat *vmx;

	list_for_each_entry(vs_stat, &statistics, list) {
		DP("func:%s line:%d vs_stat:%s\n", __func__, __LINE__, vs_stat->name);
		list_for_each_entry(pool_stat, &vs_stat->pool_head, list) {
			DP("func:%s line:%d vs_stat:%s pool_stat:%s\n", __func__, __LINE__, vs_stat->name, pool_stat->name);
			list_for_each_entry(vmx, &pool_stat->vmx_head, list) {
				DP("func:%s line:%d vs_stat:%s pool_stat:%s vmx:%s mode:%d retry:%d\n", __func__, __LINE__, vs_stat->name, pool_stat->name, vmx->address, vmx->mode, vmx->retry);
			}
		}
	}
}

/* 功能说明：删除enable=off 或vm_enable=off的vs_stat和VS已经删除的 vs_stat */
static int sync_vserver_to_vserver_stat(struct list_head *vs_head, struct list_head *vs_stat_head)
{
	DP("func:%s line:%d\n", __func__, __LINE__);
	struct vserver *vs;
	struct vs_stat *vs_stat;
	/* 1. 删除enable=off的vs_stat */
	list_for_each_entry(vs, vs_head, list) {
		if(strcmp(vs->enable, "off") == 0 ||
				strcmp(vs->vm_enable, "off") == 0 ) {
			if ((vs_stat = vs_stat_search(vs->name)) != NULL) {
				DP("func:%s line:%d 删除enable=off的vs_stat :%s \n", __func__, __LINE__, vs->name);
				__vs_stat_remove(vs_stat);
			}
		}
	}

	/* 2. 删除vs已经不存在的vs_stat */
	list_for_each_entry(vs_stat, vs_stat_head, list) {
		if ((vs = vserver_search(vs_head, vs_stat->name)) == NULL) {
			DP("func:%s line:%d 删除vs已经删除的vs_stat :%s \n", __func__, __LINE__, vs_stat->name);
			__vs_stat_remove(vs_stat);
		}
	}

	return 0;
}

#if 0
int get_balance_rserver(
		struct pool_stat *stat, 
		struct apppool *pool , 
		struct vmx_stat *vmx_out, 
		struct rserver *rs_out, 
		int mode)
{
	struct vmx_stat *vmx;
	struct rserver *rs;

	list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
		if (vmx_stat->mode != mode) {
			continue;
		}

		list_for_each_entry(rs, &pool->realserver_head, list) {
			memset(address, 0, sizeof(address));
			if (!rserver_enable(rs)) {
				continue;
			}
			if (inet_sockaddr2address(&rs->address, address) == -1) {
				continue;
			}
			if (strcmp(address, vmx_stat->address) != 0) {
				continue;
			}
			if (!rs_out) {
				vmx_out = vmx_stat;
				rs_out = rs;
			}
			if (vmx_stat->retry <= 0) {
				rs_out = rs;
				vmx_out = vmx_stat;
			} else {
				if (vmx_stat->retry < vmx_out->retry) {
					rs_out = rs;
					vmx_out = vmx_stat;
				}
			}
		}
	}

	return 0;
}
#endif

static int apppool_suspend(struct list_head *pool_queue, struct vs_stat *vs_stat, struct vserver *vs) 
{
	DP ("func:%s line:%d\n", __func__, __LINE__);

	int alive = 0, found = 0;
	char address[BUFSIZ];
	struct pool_stat *stat;
	struct vmx_stat *vmx_stat;
	struct rserver *rs;
	struct apppool *pool;

	if ((pool = apppool_search(pool_queue, vs->backpool)) == NULL) {
		DP("func:%s line:%d search pool fail!\n", __func__, __LINE__);
		return -1;
	}

	if (!(stat = pool_stat_search(vs_stat, vs->backpool))) {
		DP("func:%s line:%d\n", __func__, __LINE__);
		return -1;
	}

	list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
		if (vmx_stat->mode == MODE_UP) {
			alive++;
		}
	}

	stat->nr_server = alive;
	if (alive <= 1) {
		DP("func:%s line:%d alive=%d return\n", __func__, __LINE__, alive);
		return 0;
	}

	list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
		found = 0;
		if (vmx_stat->mode != MODE_UP) {
			continue;
		}

		list_for_each_entry(rs, &pool->realserver_head, list) {
			memset(address, 0, sizeof(address));
			if (!rserver_enable(rs)) {
				continue;
			}
			if (inet_sockaddr2address(&rs->address, address) == -1) {
				continue;
			}
			if (strcmp(address, vmx_stat->address) == 0) {
				found = 1;
				break;
			}
		}

		if (!found) {
			continue;
		}

		if (vmx_stat->silence > 0) {
			if (--vmx_stat->silence == 0) {
				vmx_stat->retry=  0;
			}
			continue;
		}
		DP("func:%s line:%d alive:%d stop continue\n", __func__, __LINE__, alive);
		if (notify_daemon4(stat->name, rs, 0) < 0) {
			if (++vmx_stat->retry > VMWARE_MAX_RETRY) {
				vmx_stat->silence = VMWARE_MAX_SILENCE;
			}
			return -1;
		} 	
		if (--alive <= 1) {
			break;
		}
	}

	return 0;
}
	__attribute__((unused))
static void stat_print()
{
	struct vserver *vs;
	DP("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	DP("==func:%s\n", __func__);
	struct vs_stat *vs_stat;
	struct pool_stat *pool_stat;
	struct vmx_stat *vmx_stat;

	list_for_each_entry(vs_stat, &statistics, list) {
		list_for_each_entry(vs, &vs_queue, list) {
			if (strcmp(vs->name, vs_stat->name) == 0) {
				if (strcmp(vs->enable, "on") == 0) {
					DP("vs_stat:%s\n", vs_stat->name);
					list_for_each_entry(pool_stat, &vs_stat->pool_head, list) {
						DP("pool_stat: %s mode=%d\n", pool_stat->name, pool_stat->mode);
						list_for_each_entry(vmx_stat, &pool_stat->vmx_head, list) {
							DP("*******address%s mode:%d retry:%d flag:%d silence:%d\n", 
									vmx_stat->address, vmx_stat->mode, vmx_stat->retry, vmx_stat->flag, vmx_stat->silence);
						}
					}
				}
				break;
			}
		}

	}
}

static void *thr_fn(void *arg) 
{
	pthread_data_t *th;
	th = (pthread_data_t *)arg;
	th->handler(th->data);

	/* free data */
	if (th->data != NULL) {
		free(th->data);
	}
	if (th != NULL) {
		free(th);
	}

	return ((void *)0);
}

static void pthread_execute( void *data)
{
	int rc;
	pthread_t ntid;
	pthread_attr_t attr;

	if ((rc = pthread_attr_init(&attr)) != 0) {
		return ;
	}
	if ((rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) == 0) {
		rc = pthread_create(&ntid, &attr, thr_fn, data);
	}
	pthread_attr_destroy(&attr);
}

static inline void update_sample_timer(struct pool_stat *stat)
{
	stat->sample = time(NULL) + stat->vm_interval;
}

extern void reset_timer(struct pool_stat *stat)
{
	stat->connections      = 0;
	stat->new_connections  = 0;
	stat->bandwidths       = 0;
	stat->count            = 0;
	time(&stat->start);
	stat->sample = stat->start + stat->vm_interval;
}

static int timer_expired(struct pool_stat *stat)
{
	time_t now;

	time(&now);
	DP("Timer_expired remain time=%ld(s)\n", (stat->start + stat->vm_interval * stat->vm_count) - now );
	return (stat->start + stat->vm_interval * stat->vm_count <= now);
}

static void sync_vs_stat(struct list_head *vs_queue, struct list_head *pool_queue)
{
	DP("===func:%s line:%d",__func__, __LINE__);
	struct vserver *vs;
	struct vs_stat *stat, *tmp;
	char address[512];
	int got = 0;

	list_for_each_entry_safe(stat, tmp, &statistics, list) {
		got = 0;
		list_for_each_entry(vs, vs_queue, list) {
			if (!strcmp(vs->name, stat->name)) {
				memset(address, 0, sizeof(address));
				if (inet_sockaddr2address(&vs->address, address) == -1) {
					continue;
				}
				if (!list_empty(&vs->apppool_desc_head) && (address[0] != '\0') && !strcmp(vs->enable, "on")) {
					sync_pool_stat(stat, vs, pool_queue);

				}
#if 0 
				else if(list_empty(&vs->apppool_desc_head)){
					DP("===func:%s line:%d",__func__, __LINE__);
					pool_stat_clear(stat);	
					stat->pool_cur[0] = 0;
				}
#endif
				got = 1;
				break;
			}
		}
		if (!got) {
			list_del(&stat->list);
			__vs_stat_remove(stat);
		}
	}
}

static void sync_pool_stat(struct vs_stat *vs_stat, struct vserver *vs,
		struct list_head *pool_queue)
{
	DP("===func:%s line:%d",__func__, __LINE__);
	struct pool_stat *stat, *tmp;
	struct apppool_desc *pool_desc;
	struct list_head *list;
	struct apppool *pool;
	int got = 0;

	list_for_each_entry_safe(stat, tmp, &vs_stat->pool_head, list) {
		got = 0;
		list_for_each_entry(pool_desc, &vs->apppool_desc_head, list) {
			if (!strcmp(pool_desc->name, stat->name)) {
				list = module_queue_search("apppool",
						pool_queue, pool_desc->name);
				if (list) {
					pool = list_entry(list, struct apppool, list);
					if (!strcmp(pool->vmenable, "on")) {
						got = 1;
						break;
					}
				}
			}
		}
		if (!got) {
			list_del(&stat->list);
			__pool_stat_remove(stat);
		}
	}
}

static struct vs_stat *vs_stat_add(char *name)
{
	struct vs_stat *stat = NULL;

	stat = calloc(sizeof(struct vs_stat), 1);
	if (!stat)
		goto end;

	INIT_LIST_HEAD(&stat->list);
	INIT_LIST_HEAD(&stat->pool_head);
	memset(stat->name, 0, 64);
	strncpy(stat->name, name, 63);
	pthread_mutex_init(&stat->mutex, NULL);
	list_add_tail(&stat->list, &statistics);
end:
	return stat;
}

static struct vs_stat *vs_stat_search(char *name)
{
	struct vs_stat *stat = NULL;
	list_for_each_entry(stat, &statistics, list) {
		if (!strcmp(name, stat->name))
			return stat;
	}
	return NULL;
}

static void __vs_stat_remove(struct vs_stat *vs_stat) {
	pool_stat_clear(vs_stat);
	free(vs_stat);
}

static struct pool_stat *pool_stat_add(struct vs_stat *vs_stat , struct apppool *pool)
{
	struct pool_stat *stat = NULL;

	stat = calloc(sizeof(struct pool_stat), 1);
	if (!stat)
		goto end;

	INIT_LIST_HEAD(&stat->list);
	INIT_LIST_HEAD(&stat->vmx_head);
	memset(stat->name, 0, 64);
	strcpy(stat->name, pool->name);
	strcpy(stat->vmtype, pool->vmtype);
	stat->mode = MODE_NOMORE;
	reset_timer(stat);
	stat->sample = stat->start;
	pthread_mutex_init(&stat->mutex, NULL);
	list_add_tail(&stat->list, &vs_stat->pool_head);

#if 0
	strncpy(stat->conn.vmaddress, pool->vmaddress, 
			sizeof(stat->conn.vmaddress) - 1);
	strncpy(stat->conn.vmusername, pool->vmusername, 
			sizeof(stat->conn.vmusername) - 1);
	strncpy(stat->conn.vmpassword, pool->vmpassword, 
			sizeof(stat->conn.vmpassword) - 1);
#endif

end:
	return stat;
}

struct pool_stat *pool_stat_search(struct vs_stat *vs_stat, char *name)
{
	struct pool_stat *stat = NULL;
	list_for_each_entry(stat, &vs_stat->pool_head, list) {
		if (!strcmp(name, stat->name))
			return stat;
	}
	return NULL;
}

static void __pool_stat_remove(struct pool_stat *stat)
{
	vmx_stat_clear(stat);
	free(stat);
	return;
}

static void pool_stat_clear(struct vs_stat *vs_stat)
{
	struct pool_stat *stat = NULL, *tmp = NULL;

	list_for_each_entry_safe(stat, tmp, &vs_stat->pool_head, list) {
		list_del(&stat->list);
		pthread_mutex_destroy(&stat->mutex);
		__pool_stat_remove(stat);
	}
	return;
}

static int vmx_stat_data_set(struct pool_stat *pool_stat, struct rserver *rs, struct vmx_stat *stat)
{
	if ( strcmp(pool_stat->vmtype,ELASTIC_POOL_TYPE_VMWARE)==0) {
		vmware_stat_data_set(rs, &stat->data);
	} else if (strcmp(pool_stat->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
		xenserver_stat_data_set(rs, &stat->data);
	} else if (strcmp(pool_stat->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
		vcenter_stat_data_set(rs, &stat->data);
	}

	return 0;
}

#if 0
	__attribute__((unused))
static void vmx_state_print(struct pool_stat *pool_stat)
{
	struct vmx_stat *vmx;
	struct vmware_stat *vmware;
	struct xenserver_stat *xen;
	struct vcenter_stat *vcenter;

	list_for_each_entry(vmx, &pool_stat->vmx_head, list) {
		if (strcmp(pool_stat->vmtype, "vmware")==0) {
			vmware = (struct vmware_stat *)vmx->data;
		} else if (strcmp(pool_stat->vmtype, "xen")==0) {
			xen = (struct xenserver_stat *)vmx->data;
		} else if (strcmp(pool_stat->vmtype, "vcenter")==0) {
			vcenter = (struct vcenter_stat *)vmx->data;
		}
	}
}
#endif

extern struct vmx_stat *vmx_stat_add(struct pool_stat *stat, struct rserver *rs)
{
	struct vmx_stat *vmx_stat = NULL;

	DP("func:%s line:%d  add new vmx_stat:%s\n", __func__, __LINE__, rs->vmname);

	vmx_stat = calloc(sizeof(struct vmx_stat), 1);
	if (!vmx_stat) {
		DP("Error: func:%s line:%d\n", __func__, __LINE__);
		goto end;
	}

	INIT_LIST_HEAD(&vmx_stat->list);

	vmx_stat_data_set( stat, rs, vmx_stat);

	memset(vmx_stat->address, 0, 512);
	if (inet_sockaddr2address(&rs->address, vmx_stat->address) == -1) {
		DP("Error: func:%s line:%d\n", __func__, __LINE__);
		return NULL;
	}

	if (rs->rscenter[0] != 0) {
		strcpy(vmx_stat->rscenter, rs->rscenter);
	}

	if (rs->vmdatacenter[0] != 0) {
		strcpy(vmx_stat->datacenter, rs->vmdatacenter);
	}

#if 0
	if (strcmp(stat->vmtype, "vcenter") == 0) {
		if (strcmp(rs->vmstate, "poweredOn") == 0) {
			vmx_stat->mode = MODE_UP;
		} else if (strcmp(rs->vmstate, "poweredOff") == 0){
			vmx_stat->mode = MODE_DOWN;
		} else {
			vmx_stat->mode = MODE_NONE;
		}

	} else {
		if (strcmp(rs->state, "on") == 0 ) {
			vmx_stat->mode = MODE_UP;
		} else if (strcmp(rs->state, "down") == 0) {
			vmx_stat->mode = MODE_DOWN;
		} else {
			vmx_stat->mode = MODE_NONE;
		}
	}
#endif

	if (strcmp(rs->state, "up") == 0 ) {
		vmx_stat->mode = MODE_UP;
	} else if (strcmp(rs->state, "down") == 0) {
		vmx_stat->mode = MODE_DOWN;
	} else {
		vmx_stat->mode = MODE_NONE;
	}

	DP("==func:%s line:%d stat:%s vmstate:%s mode:%d\n", __func__, __LINE__, rs->state, rs->vmstate, vmx_stat->mode);

	pthread_mutex_init(&vmx_stat->mutex, NULL);
	list_add_tail(&vmx_stat->list, &stat->vmx_head);
end:
	return vmx_stat;
}

extern struct vmx_stat *vmx_stat_search(struct pool_stat *stat, char *address)
{
	struct vmx_stat *vmx_stat = NULL;

	list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
		if (!strcmp(address, vmx_stat->address))
			return vmx_stat;
	}
	return NULL;
}

static void vm_stat_data_free(struct vmx_stat *stat, struct pool_stat *pool_stat)
{
	if (stat == NULL) {
		return ;
	}

	if (strcmp(pool_stat->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0) {
		vmware_stat_data_free(stat->data);
	} else if (strcmp(pool_stat->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
		xenserver_stat_data_free(stat->data);
	} else if (strcmp(pool_stat->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
		vcenter_stat_data_free(stat->data);
	}

	pthread_mutex_destroy(&stat->mutex);
	free(stat);
	stat =  NULL;
}

void __vmx_stat_remove(struct vmx_stat *stat, struct pool_stat *pool_stat)
{
	DP("func:%s line:%d vmx:%s\n", __func__, __LINE__, stat->address);
	if (stat != NULL) {
		list_del(&stat->list);
		vm_stat_data_free(stat, pool_stat);
	}

	return;
}

extern void vmx_stat_clear(struct pool_stat *stat)
{
	DP("==func:%s line:%d\n", __func__, __LINE__);

	struct vmx_stat *vmx_stat = NULL, *tmp = NULL;

	list_for_each_entry_safe(vmx_stat, tmp, &stat->vmx_head, list) {
		__vmx_stat_remove(vmx_stat, stat);
	}
	DP("func:%s line:%d set mode=MODE_NOMORE!", __func__, __LINE__);
	stat->mode = MODE_NOMORE;
	return;
}

extern void adjust_pool_stat_mode(struct pool_stat *stat)
{
	if (list_empty(&stat->vmx_head)) {
		stat->mode = MODE_NOMORE;
		DP("func:%s line:%d set mode=MODE_NOMORE!", __func__, __LINE__);
	} else {
		stat->mode = MODE_NONE;
	}
}

static void * vm_stat_init(void *data)
{
	int ret = 0;
	struct apppool *pool, *tmp;
	struct rserver *rs;
	vm_init_data_t *vid;
	char address[512];

	if ((vid = (vm_init_data_t *)data) == NULL) {
		return (void *)-1;
	}

	list_for_each_entry(pool, &vid->pool_head, list) {
		DP("func:%s line:%d pool:%s\n", __func__, __LINE__, pool->name);
		list_for_each_entry(rs, &pool->realserver_head, list) {
			memset(address, 0, sizeof(address));
			if (inet_sockaddr2address(&rs->address, address) == -1) {
				continue;
			}
			DP("func:%s line:%d rs:%s\n", __func__, __LINE__, address);
		}
	}

	pool = list_first_entry(&vid->pool_head, struct apppool, list);
	DP("func:%s line:%d pool:%s vs:%s\n", __func__, __LINE__, pool->name, vid->vs_stat->name);

	if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0) {
#if 0
		ret = vmware_stat_init(vs_stat, pool);
#endif
	} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
		ret = xenserver_stat_init(vid->vs_stat, &vid->pool_head, &vcenter_queue);
	} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
		ret = vcenter_stat_init(vid->vs_stat, &vid->pool_head, &vcenter_queue);
	}

	if (!ret) {
		/* 初始化成功 */
		vid->vs_stat->init = STAT_INITED;
		vid->vs_stat->init_times = 0;
	} else {
		vid->vs_stat->init = STAT_INIT_FAIL;
		vid->vs_stat->init_times++;
	}

	DP("初始化完成, 接锁! init:%d\n", vid->vs_stat->init);
	pthread_mutex_unlock(&vid->vs_stat->mutex);

	list_for_each_entry_safe(pool, tmp, &vid->pool_head, list) {
		list_del(&pool->list);
		apppool_free(&pool->list);
	}

#if 0
	if (ret) {
		apppool_free(&pool->list);
		return (void *)(-1);
	} else {
		apppool_free(&pool->list);
		return (void *)0;
	}
#endif
	return 0;
}

static inline int cal_load(struct pool_stat *stat)
{
	DP("===func:%s===\n", __func__);

	int avg_ec = 0, avg_band = 0, avg_nc = 0;
	int divisor = 1;
	unsigned short value;

	if (stat->nr_server == 0) {
		DP("func:%s line:%d\n", __func__, __LINE__);
		return VMWARE_VM_DO_START;
	}

	if (stat->count < stat->vm_count / 2) {
		DP("func:%s line:%d\n", __func__, __LINE__);
		return VMWARE_VM_DO_NONE;
	}

	if (stat->count > 0) {
		divisor = (stat->count > 0 ? stat->count : 1) * (stat->nr_server > 0 ? stat->nr_server : 1);
	}	

	/* 阀值检测 */
	value = elastic_value_valid_check( stat->vm_conn_low, stat->vm_conn_high, 
			stat->vm_newconn_low, stat->vm_newconn_high, stat->vm_band_low, stat->vm_band_high);
	if (value == VMWARE_VALUE_INVALID) {
		DP("func:%s line:%d 所有阀值检测无效!\n", __func__, __LINE__);
		return VMWARE_VM_DO_NONE;
	}
	if (value & VMWARE_VALUE_CONN_VALID) {
		DP("conn检测有效\n");
	}
	if (value & VMWARE_VALUE_NEWCONN_VALID) {
		DP("newconn检测有效\n");
	}
	if (value & VMWARE_VALUE_BAND_VALID) {
		DP("band检测有效\n");
	}

	/* 均值计算 */
	avg_ec = stat->connections/divisor;
	avg_nc = stat->new_connections/divisor;
	avg_band = stat->bandwidths/divisor;

	DP("vm_conn_low:%d vm_conn_high:%d\n", stat->vm_conn_low, stat->vm_conn_high);
	DP("vm_newconn_low:%d vm_newconn_high:%d\n", stat->vm_newconn_low, stat->vm_newconn_high);
	DP("vm_band_low:%d vm_band_high:%d\n", stat->vm_band_low, stat->vm_band_high);
	DP("divisor=%d count:%d nr_server:%d avg_ec=%d avg_nc=%d avg_band=%d\n", divisor, stat->count, stat->nr_server, avg_ec, avg_nc, avg_band);

	/* 开启：任意一个均值超出上限*/
	if ((value & VMWARE_VALUE_CONN_VALID)) {
		if (avg_ec > stat->vm_conn_high) {
			DP("conn start\n");
			return VMWARE_VM_DO_START;
		}
	}
	if ((value & VMWARE_VALUE_NEWCONN_VALID)) {
		if (avg_nc > stat->vm_newconn_high) {
			DP("newconn start\n");
			return VMWARE_VM_DO_START;
		}
	}
	if ((value & VMWARE_VALUE_BAND_VALID)) {
		if (avg_band > stat->vm_band_high) {
			DP("band start\n");
			return VMWARE_VM_DO_START;
		}
	}

	/* 关闭：所有有效均值均低于下限 */
	if ((value & VMWARE_VALUE_CONN_VALID) && 
			(value & VMWARE_VALUE_NEWCONN_VALID) && 
			(value & VMWARE_VALUE_BAND_VALID)) {
		/* case 1. vm_conn && vm_newconnn && vm_band */
		if ((avg_ec < stat->vm_conn_low) && 
				(avg_nc < stat->vm_newconn_low) && 
				(avg_band < stat->vm_band_low)) {
			DP("case 1. vm_conn && vm_newconnn && vm_band stop\n");
			return VMWARE_VM_DO_STOP;
		}
	} else if ((value & VMWARE_VALUE_CONN_VALID) && (value & VMWARE_VALUE_NEWCONN_VALID)) {
		/* case 2. vm_conn && vm_newconn  */
		if ((avg_ec < stat->vm_conn_low) && (avg_nc < stat->vm_newconn_low)) {
			DP("case 2. vm_conn && vm_newconn stop\n");
			return VMWARE_VM_DO_STOP;
		}
	} else if ((value & VMWARE_VALUE_CONN_VALID) && (value & VMWARE_VALUE_BAND_VALID)) {
		/* case 3. vm_conn && vm_band */
		if ((avg_ec < stat->vm_conn_low) && (avg_band < stat->vm_band_low)) {
			DP("case 3. vm_conn && vm_band stop\n");
			return VMWARE_VM_DO_STOP;
		}
	} else if ((value & VMWARE_VALUE_NEWCONN_VALID) && (value & VMWARE_VALUE_BAND_VALID)) {
		/* case 4. vm_newconn && vm_band */
		if ((avg_nc < stat->vm_newconn_low) && (avg_band < stat->vm_band_low)) {
			DP("case 4. vm_newconn && vm_band stop\n");
			return VMWARE_VM_DO_STOP;
		}
	} else if ((value & VMWARE_VALUE_CONN_VALID)) {
		/* case 5. vm_conn */
		if (avg_ec < stat->vm_conn_low) {
			DP("case 5. vm_conn stop\n");
			return VMWARE_VM_DO_STOP;
		}
	} else if ((value & VMWARE_VALUE_NEWCONN_VALID)) {
		/* case 6. vm_newconn */
		if (avg_nc < stat->vm_newconn_low) {
			DP("case 6. vm_newconn stop\n");
			return VMWARE_VM_DO_STOP;
		}
	} else if ((value & VMWARE_VALUE_BAND_VALID)) {
		/* case 7. vm_band */
		if (avg_band < stat->vm_band_low) {
			DP("case 7. vm_band stop\n");
			return VMWARE_VM_DO_STOP;
		}
	}

	DP("func:%s line:%d\n", __func__, __LINE__);
	return  VMWARE_VM_DO_NONE;
}
/* 在增加或关闭VM行为发证之后，系统静默2个采样周期后，继续采样进行阀值判断 */
/* we wait 6 miniutes if we had just powered on or powered off
 * a vmware machine. 
 * RETURN: *	0 - do noning; other - do your action
 */
static inline int try_process_server(struct pool_stat *stat, int action)
{
	DP("func:%s silence:%d\n", __func__, (int)stat->silence);
	if (!stat->silence) {
		return action;
	}

	if (--stat->silence) {
		return 0;
	} 
	return action;
}

static inline int try_start_server(struct pool_stat *stat)
{
	DP("==func:%s\n", __func__);
	return try_process_server(stat, 1);
}

static inline int try_stop_server(struct pool_stat *stat)
{
	DP("==func:%s\n", __func__);
	if (stat->nr_server <= 1) {
		return 0;
	}
	return try_process_server(stat, -1);
}


static int vm_update_private_data( struct vmx_stat *vmx_stat, struct pool_stat *stat, struct rserver *rs)
{
	if (strcmp(stat->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0){
		vmware_update_private_data(vmx_stat, rs);
	} else if (strcmp(stat->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
		xenserver_update_private_data(vmx_stat, rs);
	} else if (strcmp(stat->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
		vcenter_update_private_data(vmx_stat, rs);
	}

	return 0;
}

static int vm_check_pool_stat_need_update (struct apppool *pool, struct pool_stat * stat)
{
	DP("func:%s line:%d\n", __func__, __LINE__);
	int ret = 0;

	if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0) {
		ret = vmware_check_pool_stat_need_update(pool, stat);
	} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
		ret = xenserver_check_pool_stat_need_update(pool, stat);
	} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
		ret = vcenter_check_pool_stat_need_update(pool, stat);
	}

	DP("func:%s line:%d ret:%d\n", __func__, __LINE__, ret);

	return ret;
}

/** 1. process_request接收请求，关闭vmx_stat对应的vm, 之后将mode=MODE_DOWN
 *  2. 删除vcenter中vmx_stat mode=MODE_DOWN 的vmx_stat, 以进行同步  */
	__attribute__((unused))
static int vcenter_stat_adjust(struct vs_stat * vs_stat)
{
	struct pool_stat *pool_stat;
	struct vmx_stat *vmx_stat, *tmp;

	list_for_each_entry(pool_stat, &vs_stat->pool_head, list) {
		list_for_each_entry_safe(vmx_stat, tmp, &pool_stat->vmx_head, list) {
			if (vmx_stat->mode == MODE_DOWN) {
				__vmx_stat_remove(vmx_stat, pool_stat);
			}
		}
	}

	return 0;
}

/* 功能：
 * 1. 同步健康检查状态到vmx_stat
 * 2. 更新pool中rs数据到vmx_stat
 * 3. 删除pool中没有但pool_stat有的vmx 
 * */
static int sync_pool_to_stat(struct vs_stat *vs_stat, struct list_head  *pool_queue)
{
	DP("func:%s line:%d\n", __func__, __LINE__);
	int found;
	char address[512];
	struct vmx_stat *vmx_stat, *tmp;
	struct pool_stat *stat;
	struct apppool *pool;
	struct rserver *rs;

	/* 更新pool中的最新数据到pool_stat  */
	list_for_each_entry(stat, &vs_stat->pool_head, list) {
		list_for_each_entry_safe(vmx_stat, tmp, &stat->vmx_head, list) {
			found = 0;
			/* search pool */
			if ((pool = apppool_search(pool_queue, stat->name)) == NULL) {
				continue;
			}
			list_for_each_entry(rs, &pool->realserver_head, list) {
				memset(address, 0, sizeof(address));
				if (inet_sockaddr2address(&rs->address, address) == -1) {
					continue;
				}
				if (!strcmp(vmx_stat->address, address)) {
					found = 1;
					vm_update_private_data(vmx_stat, stat, rs);
					/* 更新rs健康检查状态到vmx */
					if (strcmp(rs->state, "down") == 0) {
						vmx_stat->mode = MODE_DOWN;
					} else if (strcmp(rs->state, "up") == 0) {
						vmx_stat->mode = MODE_UP;
					}

					break;
				}
			}
			if (!found) {
				/* 删除pool_stat中有， pool中没有的vmx */
				__vmx_stat_remove(vmx_stat, stat);
			}
		}
	}

	return 0;
}

int update_pool_stat_threshold(struct vserver *vs, struct pool_stat *pool_stat)
{
	int ret = 0;	
	//vm_conn_low/high
	if (atol(vs->vm_conn_high) != pool_stat->vm_conn_high) {
		DP("func:%s line:%d vm_conn_high由%d修改为%s\n",__func__, __LINE__, pool_stat->vm_conn_high, vs->vm_conn_high);
		pool_stat->vm_conn_high     = atol(vs->vm_conn_high);
		ret = 1;
	}

	if (atol(vs->vm_conn_low) != pool_stat->vm_conn_low) {
		DP("func:%s line:%d vm_conn_low由%d修改为%s\n",__func__, __LINE__, pool_stat->vm_conn_low, vs->vm_conn_low);
		pool_stat->vm_conn_low     = atol(vs->vm_conn_low);
		ret = 1;
	}
	//vm_newconn_low/high
	if (atol(vs->vm_newconn_high) != pool_stat->vm_newconn_high) {
		DP("func:%s line:%d vm_newconn_high由%d修改为%s\n",__func__, __LINE__, pool_stat->vm_newconn_high, vs->vm_newconn_high);
		pool_stat->vm_newconn_high     = atol(vs->vm_newconn_high);
		ret = 1;
	}

	if (atol(vs->vm_newconn_low) != pool_stat->vm_newconn_low) {
		DP("func:%s line:%d vm_newconn_low由%d修改为%s\n",__func__, __LINE__, pool_stat->vm_newconn_low, vs->vm_newconn_low);
		pool_stat->vm_newconn_low     = atol(vs->vm_newconn_low);
		ret = 1;
	}
	//vm_band_low/high
	if (atol(vs->vm_band_high) != pool_stat->vm_band_high) {
		DP("func:%s line:%d vm_band_high由%d修改为%s\n",__func__, __LINE__, pool_stat->vm_band_high, vs->vm_band_high);
		pool_stat->vm_band_high     = atol(vs->vm_band_high);
		ret = 1;
	}
	if (atol(vs->vm_band_low) != pool_stat->vm_band_low) {
		DP("func:%s line:%d vm_band_low由%d修改为%s\n",__func__, __LINE__, pool_stat->vm_band_low, vs->vm_band_low);
		pool_stat->vm_band_low     = atol(vs->vm_band_low);
		ret = 1;
	}

	return ret;
}


static int pool_stat_update( 
		struct vserver *vs, 
		struct vs_stat * vs_stat, 
		struct apppool *pool, 
		struct pool_stat *stat) 
{
	DP("func:%s line:%d\n", __func__, __LINE__);

	char address[512] = {0};
	int ret = 0, alive = 0, need_up = 0;
	uint64_t connection = 0, bandwidth = 0, new_connection = 0;
	struct apppool_desc *pool_desc = NULL;
	struct rserver_desc *rs_desc = NULL;
	DP(" func:%s line:%d pool:%s stat:%s\n", __func__, __LINE__, pool->name, stat->name);

	/* TODO: 修改验证 */
	if ((need_up=vm_check_pool_stat_need_update(pool, stat)) == 1) {
		DP("func:%s line:%d pool:%s stat:%s NEED_UPDATE=1\n", __func__, __LINE__, pool->name, stat->name);
		reset_timer(stat);
		adjust_pool_stat_mode(stat);
		return 1;
	}

	/****add by zhangjie ****************/
	if(update_pool_stat_threshold(vs, stat) == 1) {
		DP("func:%s line:%d pool:%s stat:%s NEED_UPDATE=1\n", __func__, __LINE__, pool->name, stat->name);
		//reset_timer(stat);
		adjust_pool_stat_mode(stat);
		return 1;
	}
	/********************/

	DP(" func:%s line:%d pool:%s stat:%s\n", __func__, __LINE__, pool->name, stat->name);
	/* 获取统计信息 */
	if ((pool_desc = apppool_desc_search(&vs->apppool_desc_head, pool->name))) {
		if (!list_empty(&pool_desc->rserver_desc_head)) {
			list_for_each_entry(rs_desc, &pool_desc->rserver_desc_head, list) {
				if (strcmp(rs_desc->alive_state, "up")) {
					continue;
				}
				++alive;
				memset(address, 0, sizeof(address));
				if (inet_sockaddr2address(&rs_desc->address, address) == -1) {
					continue;
				}
				DP("获取统计信息: %s : %s %s %s %s\n", address, rs_desc->connections,
						rs_desc->new_connections, rs_desc->flowin, rs_desc->flowout);
				connection       += atol(rs_desc->connections);
				new_connection   += atol(rs_desc->new_connections);
				bandwidth        += atol(rs_desc->flowin);
				bandwidth				 += atol(rs_desc->flowout);
			}
		}
	}

	DP("alive:%d EC:%d NC:%d Band:%d\n", alive, connection, new_connection, bandwidth);

	if (!alive || alive < atoi(pool->alive_vm) ) {
		DP("=====================>> (char)alive=%s, (int)alive=%d", pool->alive_vm, atoi(pool->alive_vm));
		if (!timer_expired(stat)) {
			return 0;
		}
		reset_timer(stat);
		if ((ret=try_start_server(stat)) > 0) {
			goto start_vm;
		}
	}

	if ( alive != stat->nr_server) {
		DP("Nr of rserver changed, reset timer and statistics,"
				"old alive nr_server = %d, alive = %d\n",
				stat->nr_server, alive);
		stat->nr_server = alive;

		reset_timer(stat);
		stat->nr_server	      = alive;
		stat->connections     = connection;
		stat->new_connections = new_connection;
		stat->bandwidths      = bandwidth;
		stat->count           = 1;

		return 0;
	}

	stat->connections     += connection;
	stat->new_connections += new_connection;
	stat->bandwidths      += bandwidth;
	++stat->count;

	/* 日志打印记录均值 */
	int avg_ec, avg_nc, avg_band, divisor;
	divisor = (stat->count > 0 ? stat->count : 1) * ( stat->nr_server > 0 ? stat->nr_server : 1);
	avg_ec = stat->connections / divisor;
	avg_nc = stat->new_connections / divisor;
	avg_band = stat->bandwidths / divisor;
	DP("本次均值： divisor:%d nr_server:%d stat->count:%d AVG_EC=%d AVG_NC=%d AVG_BAND=%d\n", divisor, stat->nr_server, stat->count, avg_ec, avg_nc, avg_band);
	DP("总计: EC:%d NC:%d BW:%d count:%d\n", (int)stat->connections, (int)stat->new_connections, (int)stat->bandwidths, (int)stat->count);
	DP("本次: EC:%d NC:%d BW:%d\n", (int)connection, (int)new_connection, (int)bandwidth);

	/* calculate the load and reset the timer */
	if (vs_stat->init == STAT_INITED && timer_expired(stat)) {
		ret = cal_load(stat);
		DP("=== OVER decision over === ret:[%d]\n", ret);
		if (ret == VMWARE_VM_DO_START ) {
			ret = try_start_server(stat);
		} else if (ret == VMWARE_VM_DO_STOP ) {
			ret = try_stop_server(stat);
		}

		/* 如果当前使用主池，备份池只留一个活动的VM */
		if (strcmp(vs_stat->pool_cur, vs->pool) == 0 && vs->backpool[0] != 0) {
			if (apppool_suspend(&pool_queue, vs_stat, vs) == -1) {
				DP("func:%s line:%d apppool_suspend fail!\n", __func__, __LINE__);
			}
		}
		reset_timer(stat);
	} else {
		DP("=== NOT OVER decision init:%d===\n", vs_stat->init);
		update_sample_timer(stat);
	}

	if (!ret) {
		DP("overload === %d\n", ret);
		return 0;
	} else if (ret > 0) {
start_vm:
		DP("overload high ================== %d\n", ret);
		/* start thread to start vm */
		pthread_data_t *th;
		vm_start_data_t *vsd;

		if (pthread_mutex_trylock(&stat->mutex) != 0) {
			DP("Error: func:%s line:%d have been locked!\n", __func__, __LINE__);
			return -1;
		}
		if ((th = calloc(1, sizeof(pthread_data_t))) == NULL ||
				(vsd = calloc(1, sizeof(vm_start_data_t)))== NULL ) {
			pthread_mutex_unlock(&stat->mutex);
			DP("Error: func:%s line:%d\n", __func__, __LINE__);
			return -1;
		}
		th->data = vsd;
		th->handler = start_vm;
		vsd->pool_stat = stat;
		apppool_copy(pool, &vsd->pool);

		DP("func:%s line:%d pool:%s\n", __func__, __LINE__, pool->name);

		pthread_execute(th);
	} else {
		DP("overload low ================== %d\n", ret);
		ret =stop_realserver(stat, pool, vs);
	}

	return ret;
}


/* 完成pool中的每个pool_stat的初始化 */
static int vs_stat_update(struct vs_stat *vs_stat, struct vserver *vs) 
{
	int ret = 0;
	struct pool_stat *stat = NULL;
	struct apppool *pool = NULL, *ap = NULL;

	DP("==function:%s \n", __func__);

	if (pthread_mutex_trylock(&vs_stat->mutex) != 0) {
		/* 正在初始化，返回 */
		DP("正在初始化，返回!\n");
		return 0;
	}

	if ( vs_stat->init == STAT_UNINIT || 
			(vs_stat->init != STAT_INITED  && 
			 vs_stat->init_times < VMWARE_MAX_INIT_TIMES ) ) {
		/* 首次初始化, 当前使用池为主池 */
		DP("首次初始化, init:%d\n", vs_stat->init);
		strcpy(vs_stat->pool_cur, vs->pool);

		/* 线程处理 */
		pthread_data_t *pd = NULL;
		vm_init_data_t *vid = NULL;
		if ((pd = calloc(1, sizeof(pthread_data_t))) == NULL ||
				(vid = calloc(1, sizeof(vm_init_data_t))) == NULL ) {
		}

		INIT_LIST_HEAD(&vid->pool_head);
		list_for_each_entry(stat, &vs_stat->pool_head, list) {
			if ((pool = apppool_search(&pool_queue, stat->name)) == NULL) {
				continue;
			}
			apppool_copy(pool, &ap);
			list_add_tail(&ap->list, &vid->pool_head);
			continue;
		}
		vid->vs_stat = vs_stat;
		pd->handler = vm_stat_init;
		pd->data = vid;
		pthread_execute(pd);

		return 0;
	}

	if ( vs_stat->init != STAT_INITED ) {
		DP("Error: func:%s line:%d vs_stat init:%d\n", __func__, __LINE__, vs_stat->init);
	}

	if (vs->pool[0] != 0) {
		/* Not contentswitch */
		stat = list_first_entry(&vs_stat->pool_head, struct pool_stat, list);

#if 0
		if (strcmp(stat->vmtype, ELASTIC_POOL_TYPE_VCENTER) == 0 ) {
			vcenter_stat_adjust(vs_stat);
		}
#endif

		if ((pool = apppool_search(&pool_queue, vs->pool)) == NULL) {
			DP("Error: current pool:%s find fail!\n", vs_stat->pool_cur);
			pthread_mutex_unlock(&vs_stat->mutex);
			return 0;
		}


		if ( vs->backpool[0] != 0 && apppool_all_down_check(pool)) {
			/* 主池全down使用备份池 */
			/** 使用备份池 **/
			if ((pool = apppool_search(&pool_queue, vs->backpool)) == NULL) {
				pthread_mutex_unlock(&vs_stat->mutex);
				return 0;
			}
			if ((stat = pool_stat_search(vs_stat, vs->backpool)) == NULL) {
				pthread_mutex_unlock(&vs_stat->mutex);
				return 0;
			}

			if (strcmp(vs_stat->pool_cur, vs->backpool) != 0) {
				/* 当前池非备份池, 切换，重置timer */
				strcpy(vs_stat->pool_cur, vs->backpool);
				DP("XXXXXXXXXXXXXXXXXXXXXX 进行 主->备 切换\n");
				reset_timer(stat);
				pthread_mutex_unlock(&vs_stat->mutex);
				return 0;
			}
		} else {
			/* 使用主池 */
			if ((pool = apppool_search(&pool_queue, vs->pool)) == NULL) {
				return 0;
			}
			if ((stat = pool_stat_search(vs_stat, vs->pool)) == NULL) {
				return 0;
			}
			if (strcmp(vs_stat->pool_cur, vs->pool) != 0) {
				/* 当前池非主池，切换，重置timer */
				strcpy(vs_stat->pool_cur, vs->pool);
				DP("XXXXXXXXXXXXXXXXXXXXXX 进行 备->主 切换\n");
				reset_timer(stat);
				pthread_mutex_unlock(&vs_stat->mutex);
				return 0;
			}
		}
		DP("func:%s line:%d 当前使用应用池:%s\n", __func__, __LINE__, vs_stat->pool_cur);
		sync_pool_to_stat(vs_stat, &pool_queue);
		ret = pool_stat_update(vs, vs_stat, pool, stat);
#if 0
		if (strcmp(vs_stat->pool_cur, vs->pool) == 0 && vs->backpool[0] != 0) {
			/* 如果当前使用主池，备份池只留一个活动的VM */
			if (apppool_suspend(&pool_queue, vs_stat, vs) == -1) {
				DP("apppool_suspend return -1\n");
			}
		}
#endif
		pthread_mutex_unlock(&vs_stat->mutex);
	} else if (vs->pool[0] == 0 && strcmp(vs->contentswitch, "on") == 0) {
		/* 内容交换 */
		list_for_each_entry(stat, &vs_stat->pool_head, list) {
			if ((pool = apppool_search(&pool_queue, stat->name)) == NULL) {
				continue;
			}
			DP("func:%s line:%d 当前使用应用池:%s\n", __func__, __LINE__, vs_stat->pool_cur);
			sync_pool_to_stat(vs_stat, &pool_queue);
			ret = pool_stat_update(vs, vs_stat, pool, stat);
		}
		pthread_mutex_unlock(&vs_stat->mutex);
	}
	
	/**************************
	add by zhangjie;
	循环判断主池是否位全Down,兵尝试开启主池中的vm
	***************************/
		if ((pool = apppool_search(&pool_queue, vs->pool)) != NULL && vs->backpool[0] != 0) {
			static time_t now;
			static time_t start;
			static time_t i = 0;
			if(apppool_all_down_check(pool) == 0) {
				goto out;
			}
			if ((stat = pool_stat_search(vs_stat, vs->pool)) == NULL) {
				goto out;
			}
			
			time(&now);
			
			if(i ==0) {
				start = now;
				i++;
			}
			
			DP("=== other round remain time=%ld(s)\n", (start + stat->vm_interval * stat->vm_count * 2) - now );
			if(start + stat->vm_interval * stat->vm_count * 2 >  now){
				goto out;
			}
			
			i = 0;
			
			if (pthread_mutex_trylock(&stat->mutex) != 0) {
				DP("====line:%d boss, can not get the lock!");
				goto out;
			}
			DP("==================================line:%d boss, we get the lock now!===================================================");
			pthread_data_t *th;
			vm_start_data_t *vsd;
			if ((th = calloc(1, sizeof(pthread_data_t))) == NULL ||
				(vsd = calloc(1, sizeof(vm_start_data_t)))== NULL ) {
				pthread_mutex_unlock(&stat->mutex);
				goto out;	
			}
			th->data = vsd;
			th->handler = start_vm;
			vsd->pool_stat = stat;
			apppool_copy(pool, &vsd->pool);

			DP("func:%s line:%d pool:%s\n", __func__, __LINE__, pool->name);

			pthread_execute(th);
			}
out:
	return ret;
}

static int vm_set_private_data(struct rserver * rs, char *poolname, char *buff)
{
	int ret = 0;
	struct apppool *apppool;
	/** get pool **/
	LIST_HEAD(pool_head);
	module_get_queue(&pool_head, "apppool", poolname);
	if (list_empty(&pool_head)) {
		return -1;
	}
	apppool = list_first_entry(&pool_head, struct apppool, list);

	if (strcmp(apppool->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0) {
		vmware_set_private_data(rs, buff);

	} else if (strcmp(apppool->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
		xenserver_set_private_data(rs, buff);

	} else if (strcmp(apppool->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
		vcenter_set_private_data(rs, buff);

	} else {
		ret = -1;
	}

	module_purge_queue(&pool_head, "apppool");

	return ret;
}

static int vm_set_common_data(struct rserver *rserver, int action, char *buff)
{

	RSERVER_SET_VALUE("weight", rserver->weight);
	RSERVER_SET_VALUE("maxconn", rserver->maxconn);
	RSERVER_SET_VALUE("maxreq", rserver->maxreq);
	RSERVER_SET_VALUE("bandwidth", rserver->bandwidth);
	RSERVER_SET_VALUE("healthcheck", rserver->healthcheck);
	RSERVER_SET_VALUE("state", "disabling");
	RSERVER_SET_VALUE("enable", "on");
	RSERVER_SET_VALUE("rscenter", rserver->rscenter);
	RSERVER_SET_VALUE("vmdatacenter", rserver->vmdatacenter);

	/** action = 1添加rserver, action = 0关闭rserver **/
	/* 自动关闭，设置state=disabling */

#if 0
	if (action) {
		RSERVER_SET_VALUE("enable", "on");
	} else {
		RSERVER_SET_VALUE("enable", "off");
	}
#endif

	return 0;
}
/** 
	@action: 1-enable rserver, 0-disable rserver 
 **/
static int notify_daemon4(char *poolname, struct rserver *rs, int action)
{
	DP("===func:%s line:%d\n", __func__, __LINE__);

	FILE *fp = NULL;
	char buff[1024] = {0}, address[512] = {0};

	DP("===func:%s line:%d\n", __func__, __LINE__);
	if (inet_sockaddr2address(&rs->address, address) ==-1) {
		DP("===func:%s line:%d\n", __func__, __LINE__);
		return -1;
	}

	DP("===func:%s line:%d\n", __func__, __LINE__);
	snprintf(buff, 1023, "script4 system pool %s add realserver %s", poolname, address);
	DP("===func:%s line:%d\n", __func__, __LINE__);
	vm_set_common_data(rs, action, buff);
	DP("===func:%s line:%d\n", __func__, __LINE__);
	vm_set_private_data(rs, poolname, buff);
	DP("===func:%s line:%d\n", __func__, __LINE__);
	DP("private data ?  BUFF:%s\n", buff);

	DP("===func:%s line:%d\n", __func__, __LINE__);
	fp = popen(buff, "r");
	if (fp == NULL) {
		DP("Internal Error.\r\n");
		return -1;
	}
	while (fgets(buff, BUFSIZ, fp) != NULL) {}
	pclose(fp);

	return 0;
}

static int vm_on_off(struct apppool *pool,  void *data, int op, struct vcenter *vcenter)
{
	int ret = -1;
	int count = 0;

	while(count < 3) {
		DP("==func:%s line:%d 第[%d]次 pool[%s]\n", __func__, __LINE__, count + 1, pool->name);
		if (count > 0) {
			usleep(count*VMWARE_MIN_RETRY_INTERVAL);
		}
		if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0) {
			/* data -> vmxpath */
			ret = vmware_on_off(pool, (char *)data, op);
		} else if(strcmp(pool->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
			/* data -> uuid */
			ret = xenserver_on_off(pool, (char *)data, op, vcenter);
		} else if(strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
			/* data -> vmname */
			ret = vcenter_on_off(pool, (char *)data, op, vcenter);
		}
		if (!ret) {
			break;
		}
		count++;
	}

	return ret;
}	
static int Is_vm_powerOn(const char *vcenter_name, const char *vmdatacenter, const char *vmname)
{
	LIST_HEAD(queue);
	struct vcenter *vcenter;
	struct vcenter_datacenter *datacenter;
	struct vcenter_vm *vm;

	module_get_queue(&queue, "vcenter", NULL);
	list_for_each_entry(vcenter, &queue, list){
		if(strcmp(vcenter_name, vcenter->name) != 0) {
			continue;
		}
		list_for_each_entry(datacenter, &vcenter->datacenter_head, list){
			if(strcmp(datacenter->name, vmdatacenter) != 0) {
				continue;
			}
			list_for_each_entry(vm, &datacenter->vm_head, list) {
				if(strcmp(vm->name, vmname) != 0) {
					continue;
				}

				if(strcmp(vm->state, "poweredOn") == 0) {
					module_purge_queue(&queue, "vcenter");
					return 1;
				}
			}
		}
	}
	module_purge_queue(&queue, "vcenter");
	return 0;
}

/* 此函数返回结果暂时没用 */
static void * start_vm(void *vdata /* vm_start_data_t */)
{
	DP("== func:%s", __func__);
	int ret = 0;
	char address[512];
	struct vmx_stat *vmx_stat = NULL, *vmx_stat_tmp = NULL;
	struct pool_stat *stat = NULL;
	struct rserver *rs = NULL;
	struct apppool *pool = NULL;
	struct vcenter *vcenter;
	vm_start_data_t *vsd = NULL;

	vsd = ( vm_start_data_t *)vdata;
	stat = vsd->pool_stat;
	pool = vsd->pool;

	DP("func:%s line:%d stat:%s mode:%d\n", __func__, __LINE__, stat->name, stat->mode); 
	if (stat->mode == MODE_NOMORE && strcmp(stat->vmtype, ELASTIC_POOL_TYPE_VCENTER)!= 0 ) {
		DP("%s =========================, no more server  stat:%s mode:%d\n", 
				__func__, stat->name, stat->mode); 
		goto out;
	}

	if (stat->silence > 0) {
		DP("%s =========================, silence time %lu \n",
				__func__, stat->silence); 
		--stat->silence;
		goto out;
	}

	/* 以前根据pool类型启动VM, 修改之后根据RS类型启动VM */
	DP("func:%s line:%d pooltype:%s\n", __func__, __LINE__, stat->vmtype);

	/* vmware && xenserver */
	if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0 || 
			strcmp(pool->vmtype, ELASTIC_POOL_TYPE_XENSERVER) == 0) {
		list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
			DP("func:%s line:%d vmx_stat:%s\n", __func__, __LINE__, vmx_stat->address);
			if ( vmx_stat->mode == MODE_UP ) {
				continue;
			}
			if (vmx_stat->silence > 0) {
				if (vmx_stat->silence-- == 0) {
					/* 解除沉默 */
					vmx_stat->retry = 0;
				}
				continue;
			}

			DP("func:%s line:%d rscenter:%s\n", __func__, __LINE__, vmx_stat->rscenter);
			/* get login info */
			if ((vcenter = vcenter_search(&vcenter_queue, vmx_stat->rscenter)) == NULL) {
				DP("func:%s line:%d vmx_stat:%s\n", __func__, __LINE__, vmx_stat->address);
				continue;
			}

			DP("func:%s line:%d\n", __func__, __LINE__);
			/* start vm */
			ret = vm_on_off(pool, vmx_stat->data, 1, vcenter);
			if (ret < 0) {
				DP("启动VM失败!\n");
				if (++vmx_stat->retry > VMWARE_MAX_RETRY) {
					vmx_stat->silence = VMWARE_MAX_SILENCE;
				}
			} else {
				DP("启动VM成功!\n");
				list_for_each_entry(rs, &pool->realserver_head, list) {
					memset(address, 0, sizeof(address));
					if (inet_sockaddr2address(&rs->address, address) == -1) {
						continue;
					}
					if (!strcmp(vmx_stat->address, address)) {
						vmx_stat->mode = MODE_UP;
						vmx_stat->retry = 0;
						vmx_stat->silence = 0;
						stat->silence = 2;
						goto adjust;
					}
				}
			} 		
		}
	} 
	/* vcenter */
	else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER) == 0) {
		struct vcenter *vcenter = NULL;

		/* 查找重试次数最少的VM */
		list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
			if (vmx_stat->mode == MODE_UP) {
				continue;
			}
			/*当vm映射的rs的状态为down的时候且vm为up的时候，此时这个vm因健康检查失败而不参与决策*/
			if(Is_vm_powerOn(vmx_stat->rscenter, vmx_stat->datacenter, ((struct vcenter_stat *)vmx_stat->data)->vmname)) {
				continue;
			}

			if (vmx_stat->silence > 0) {
				if (vmx_stat->silence-- == 0) {
					/* 解除沉默 */
					vmx_stat->retry = 0;	
				}
				continue;
			}

			if (vmx_stat->mode == MODE_DOWN ) {
				vmx_stat_tmp = vmx_stat;
				break;	
			} else if (vmx_stat->retry < VMWARE_MAX_RETRY) {
				if (vmx_stat_tmp == NULL) {
					vmx_stat_tmp = vmx_stat;
				} else if ( vmx_stat_tmp != NULL && (vmx_stat->retry < vmx_stat_tmp->retry)) {
					vmx_stat_tmp = vmx_stat;	
				}
			}
		} 

		if (vmx_stat_tmp == NULL) {
			DP("func:%s line:%d pool:%s find vmx fail!\n", __func__, __LINE__, pool->name);
			goto out;
		}


		DP("func:%s line:%d pool:%s found vmx :%s !\n", __func__, __LINE__, pool->name, vmx_stat->address);

		if ((vcenter = vcenter_search(&vcenter_queue, vmx_stat->rscenter)) == NULL) {
			DP("func:%s line:%d pool:%s \n", __func__, __LINE__, pool->name);
			goto out;
		}

		DP("func:%s line:%d start_vm %s\n", __func__, __LINE__, ((struct vcenter_stat *)vmx_stat->data)->vmname);
		/* start vm */
		if ((ret = vm_on_off(pool, vmx_stat->data, 1, vcenter)) < 0) {
			DP("启动VM失败!\n");
			if (++vmx_stat->retry > VMWARE_MAX_RETRY) {
				vmx_stat->silence = VMWARE_MAX_SILENCE;
			}
		} else {
			DP("启动VM成功!\n");
			vmx_stat->retry = 0;
			vmx_stat->mode = MODE_UP;
			vmx_stat->silence = 0;
			stat->silence = 2;
		}
	} else {
		ret = -1;
		goto out;
	}

	ret = 0;

adjust:
	adjust_pool_stat_mode(stat);

out:

	if (!pool) {
		apppool_free(&pool->list);
	}

	if ( stat != NULL ) {
		pthread_mutex_unlock(&stat->mutex);
	}

	if (!ret) {
		return (void *)0;
	}

	return (void *) -1;
}
__attribute__((unused))
static void * start_vm_for_master_pool(void *vdata /* vm_start_data_t */)
{
//	DP("== func:%s", __func__);
	int ret = 0;
	char address[512];
	struct vmx_stat *vmx_stat = NULL, *vmx_stat_tmp = NULL;
	struct pool_stat *stat = NULL;
	struct rserver *rs = NULL;
	struct apppool *pool = NULL;
	struct vcenter *vcenter;
	vm_start_data_t *vsd = NULL;

	vsd = ( vm_start_data_t *)vdata;
	stat = vsd->pool_stat;
	pool = vsd->pool;
	
	usleep(10*VMWARE_MIN_RETRY_INTERVAL);
	
	//DP("func:%s line:%d stat:%s mode:%d\n", __func__, __LINE__, stat->name, stat->mode); 
	if (stat->mode == MODE_NOMORE && strcmp(stat->vmtype, ELASTIC_POOL_TYPE_VCENTER)!= 0 ) {
		//DP("%s =========================, no more server  stat:%s mode:%d\n", 
			//	__func__, stat->name, stat->mode); 
		goto out;
	}

	if (stat->silence > 0) {
		DP("%s =========================, silence time %lu \n",
				__func__, stat->silence); 
		--stat->silence;
		goto out;
	}

	/* 以前根据pool类型启动VM, 修改之后根据RS类型启动VM */
	//DP("func:%s line:%d pooltype:%s\n", __func__, __LINE__, stat->vmtype);

	/* vmware && xenserver */
	if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0 || 
			strcmp(pool->vmtype, ELASTIC_POOL_TYPE_XENSERVER) == 0) {
		list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
		//	DP("func:%s line:%d vmx_stat:%s\n", __func__, __LINE__, vmx_stat->address);
			if ( vmx_stat->mode == MODE_UP ) {
				continue;
			}
			if (vmx_stat->silence > 0) {
				if (vmx_stat->silence-- == 0) {
					/* 解除沉默 */
					vmx_stat->retry = 0;
				}
				continue;
			}

			//DP("func:%s line:%d rscenter:%s\n", __func__, __LINE__, vmx_stat->rscenter);
			/* get login info */
			if ((vcenter = vcenter_search(&vcenter_queue, vmx_stat->rscenter)) == NULL) {
				//DP("func:%s line:%d vmx_stat:%s\n", __func__, __LINE__, vmx_stat->address);
				continue;
			}

			//DP("func:%s line:%d\n", __func__, __LINE__);
			/* start vm */
			ret = vm_on_off(pool, vmx_stat->data, 1, vcenter);
			if (ret < 0) {
				//DP("启动VM失败!\n");
				if (++vmx_stat->retry > VMWARE_MAX_RETRY) {
					vmx_stat->silence = VMWARE_MAX_SILENCE;
				}
			} else {
				//DP("启动VM成功!\n");
				list_for_each_entry(rs, &pool->realserver_head, list) {
					memset(address, 0, sizeof(address));
					if (inet_sockaddr2address(&rs->address, address) == -1) {
						continue;
					}
					if (!strcmp(vmx_stat->address, address)) {
						vmx_stat->mode = MODE_UP;
						vmx_stat->retry = 0;
						vmx_stat->silence = 0;
						stat->silence = 2;
						goto adjust;
					}
				}
			} 		
		}
	} 
	/* vcenter */
	else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER) == 0) {
		struct vcenter *vcenter = NULL;

		/* 查找重试次数最少的VM */
		list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
			if (vmx_stat->mode == MODE_UP) {
				continue;
			}
			/*当vm映射的rs的状态为down的时候且vm为up的时候，此时这个vm因健康检查失败而不参与决策*/
			if(Is_vm_powerOn(vmx_stat->rscenter, vmx_stat->datacenter, ((struct vcenter_stat *)vmx_stat->data)->vmname)) {
				continue;
			}

			if (vmx_stat->silence > 0) {
				if (vmx_stat->silence-- == 0) {
					/* 解除沉默 */
					vmx_stat->retry = 0;	
				}
				continue;
			}

			if (vmx_stat->mode == MODE_DOWN ) {
				vmx_stat_tmp = vmx_stat;
				break;	
			} else if (vmx_stat->retry < VMWARE_MAX_RETRY) {
				if (vmx_stat_tmp == NULL) {
					vmx_stat_tmp = vmx_stat;
				} else if ( vmx_stat_tmp != NULL && (vmx_stat->retry < vmx_stat_tmp->retry)) {
					vmx_stat_tmp = vmx_stat;	
				}
			}
		} 

		if (vmx_stat_tmp == NULL) {
			//DP("func:%s line:%d pool:%s find vmx fail!\n", __func__, __LINE__, pool->name);
			goto out;
		}


		//DP("func:%s line:%d pool:%s found vmx :%s !\n", __func__, __LINE__, pool->name, vmx_stat->address);

		if ((vcenter = vcenter_search(&vcenter_queue, vmx_stat->rscenter)) == NULL) {
			//DP("func:%s line:%d pool:%s \n", __func__, __LINE__, pool->name);
			goto out;
		}

		//DP("func:%s line:%d start_vm %s\n", __func__, __LINE__, ((struct vcenter_stat *)vmx_stat->data)->vmname);
		/* start vm */
		if ((ret = vm_on_off(pool, vmx_stat->data, 1, vcenter)) < 0) {
			//DP("启动VM失败!\n");
			if (++vmx_stat->retry > VMWARE_MAX_RETRY) {
				vmx_stat->silence = VMWARE_MAX_SILENCE;
			}
		} else {
			//DP("启动VM成功!\n");
			vmx_stat->retry = 0;
			vmx_stat->mode = MODE_UP;
			vmx_stat->silence = 0;
			stat->silence = 2;
		}
	} else {
		ret = -1;
		goto out;
	}

	ret = 0;

adjust:
	adjust_pool_stat_mode(stat);

out:

	if (!pool) {
		apppool_free(&pool->list);
	}


	if (!ret) {
		return (void *)0;
	}

	return (void *) -1;
}

/* 返回值 ： -1:失败  0-未操作  1-成功停止 */
static int stop_realserver(struct pool_stat *stat, struct apppool *pool, struct vserver *vs)
{
	int total = 0;
	char address[512];
	struct rserver *rs = NULL, *rs_last = NULL;
	struct apppool_desc *pool_desc = NULL;
	struct rserver_desc *rs_desc = NULL;
	struct vmx_stat *vmx_stat = NULL, *vmx_stat_last = NULL;

	if (!(pool_desc = apppool_desc_search(&vs->apppool_desc_head, pool->name))) {
		return -1;
	}

	DP("=========%s", __func__);
	if (stat->silence > 0) {
		DP("=========%s ======= silence time %lu \n", __func__, stat->silence);
		--stat->silence;
		return 0;
	}

	/* estimate the number of alive realservers.
	 * if only one realserver in this pool, we do nothing. */
	list_for_each_entry(rs_desc, &pool_desc->rserver_desc_head, list) {
		if (!strcmp(rs_desc->alive_state, "up")) {
			++total;
			if (total > 2)
				break;
		}
	}

	if (total <= atoi(pool->alive_vm)) {
		return 0;
	}

	total = 0;

	list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
		DP(" mode = %d\n", vmx_stat->mode);
		if (vmx_stat->mode != MODE_UP) {
			continue;
		}

		if (vmx_stat->silence > 0) {
			if (vmx_stat->silence-- == 0) {
				/* 下一轮解除沉默 */
				vmx_stat->retry = 0;
			}
			continue;
		}

		list_for_each_entry(rs, &pool->realserver_head, list) {
			memset(address, 0, sizeof(address));
			/* 手动关闭的不参与停止决策 */
			if (!rserver_enable(rs)) {
				continue;
			}
			if (inet_sockaddr2address(&rs->address, address) == -1) {
				continue;
			}
			if (!strcmp(address, vmx_stat->address)) {
				/* find least retry rserver */
				if (rs_last == NULL) {
					/* first */
					vmx_stat_last = vmx_stat;
					rs_last = rs;
				}
				if (vmx_stat->retry <= 0) {
					rs_last = rs;
					vmx_stat_last = vmx_stat;
					DP("func:%s line:%d find rs :%s retry:%d!\n", __func__, __LINE__, vmx_stat->address, vmx_stat->retry);
					goto notify_daemon4;
				} else {
					if (vmx_stat->retry < vmx_stat_last->retry) {
						DP("func:%s line:%d find rs again: last:%s retry:%d new:%s retry:%d!\n", 
								__func__, __LINE__, vmx_stat_last->address, vmx_stat_last->retry, vmx_stat->address, vmx_stat->retry);
						rs_last = rs;
						vmx_stat_last = vmx_stat;
					}
				}
			}
		}
	}

notify_daemon4:
	if (rs_last) {
		DP("==func:%s line:%d will stop vmx_stat:%s retry:%d\n", __func__, __LINE__, vmx_stat_last->address, vmx_stat_last->retry);
		if (notify_daemon4(stat->name, rs_last, 0) < 0) {
			if (++vmx_stat->retry > VMWARE_MAX_RETRY) {
				vmx_stat->silence = VMWARE_MAX_SILENCE;
			}
			DP("can't notify daemon4 retry:%d silenc:%d\n", vmx_stat_last->retry, vmx_stat_last->silence);
			return -1;
		}

		stat->mode = MODE_NONE;
		stat->silence = 3;
	} else {
		DP("func:%s line:%d find rs fail!\n", __func__, __LINE__);
	}

	return 0;
}


static int pool_stat_init(
		struct pool_stat *pool_stat, 
		struct apppool *pool, 
		struct vserver *vs
		)
{
	int val, count;
	time_t now;

	DP("func:%s line:%d pool:%s vs:%s pool_stat:%s\n", __func__, __LINE__, pool->name, vs->name, pool_stat->name);

	/* set new limits */
	pool_stat->vm_conn_high     = atol(vs->vm_conn_high);
	pool_stat->vm_conn_low      = atol(vs->vm_conn_low);

	if (!pool_stat->vm_conn_high || 
			!pool_stat->vm_conn_low || 
			pool_stat->vm_conn_high <= pool_stat->vm_conn_low) {
		pool_stat->vm_conn_high = pool_stat->vm_conn_low = 0;
	}

	pool_stat->vm_band_high     = atol(vs->vm_band_high);
	pool_stat->vm_band_low      = atol(vs->vm_band_low);

	if (!pool_stat->vm_band_high || 
			!pool_stat->vm_band_low  ||
			pool_stat->vm_band_high <= pool_stat->vm_band_low ) {
		pool_stat->vm_band_high = pool_stat->vm_band_low = 0;
	}

	pool_stat->vm_newconn_high  = atol(vs->vm_newconn_high);
	pool_stat->vm_newconn_low   = atol(vs->vm_newconn_low);

	if (!pool_stat->vm_newconn_high || 
			!pool_stat->vm_newconn_low ||
			pool_stat->vm_newconn_high <= pool_stat->vm_newconn_low ) {
		pool_stat->vm_newconn_high = pool_stat->vm_newconn_low = 0;
	}

	if (!pool_stat->vm_conn_high && 
			!pool_stat->vm_band_high && 
			!pool_stat->vm_newconn_high) {
		return -1;
	}

	val = DEFAULT_INTERVAL;

	if (strlen(pool->vminterval)) {
		val = atol(pool->vminterval);
		if (val < 2)
			val = DEFAULT_INTERVAL;
	} else {
		pool_stat->vm_interval = val;
	}
	/** Here: vm_interval(default) or val(set) **/
	count = DEFAULT_COUNT;
	if (strlen(pool->vmcount)) {
		count = atol(pool->vmcount);
		if (count < 1)
			count = DEFAULT_COUNT;
	} else {
		pool_stat->vm_count = count;
	}

	if ((pool_stat->vm_interval && pool_stat->vm_interval != val) || 
			(pool_stat->vm_count && pool_stat->vm_count != count)) {
		pool_stat->vm_interval = val; 
		pool_stat->vm_count = count;
		reset_timer(pool_stat);
		return -1;
	}

	pool_stat->vm_interval = val;
	pool_stat->vm_count = count;

	now = time(NULL);
	if (pool_stat->sample > now) {
		/* 未到取样时间返回 -1 */
		return -1;
	}

	return 0;
}

static int apppool_all_down_check(struct apppool *pool)
{
	int ret = 1;
	struct rserver *rs;

	DP("func:%s line:%d pool:%s\n", __func__, __LINE__, pool->name);

	list_for_each_entry(rs, &pool->realserver_head, list) {
		if (strcmp(rs->state, "up") == 0) {
			ret = 0;
			break;
		}
	}

	DP("func:%s line:%d ret:%d\n", __func__, __LINE__, ret);

	return ret;
}

static int handle_vserver ( struct vserver *vs)
{
	DP("====func:%s vserver:%s\n", __func__, vs->name);

	struct apppool *pool = NULL, *backpool = NULL, *rulepool = NULL;
	struct vs_stat *vs_stat = NULL;
	struct pool_stat *pool_stat = NULL, *pool_stat_back = NULL, *pool_stat_rule = NULL;
	struct rule *rule;
	struct rule_name *rule_name;
	char poolname[512];

	if ((vs_stat = vs_stat_search(vs->name)) == NULL) {
		if ((vs_stat = vs_stat_add(vs->name)) == NULL) {
			DP("Error func:%s line:%d\n", __func__, __LINE__);
			return -1;
		}
	}

	/* 初始化pool参数 */
	if (vs->pool[0] != 0) {
		/* 非内容交换 */
		/* main pool */
		if ((pool = apppool_search(&pool_queue, vs->pool)) == NULL ||
				strcmp(pool->vmenable, "on") != 0 ||
				(strcmp(pool->vmtype, "vcenter") != 0 && 
				 list_empty(&pool->realserver_head))) {
			DP("Error func:%s line:%d\n", __func__, __LINE__);
			return -1;
		}

		if ((pool_stat = pool_stat_search(vs_stat, pool->name)) == NULL ) {
			if ((pool_stat = pool_stat_add(vs_stat, pool)) == NULL ) {
				DP("Error func:%s line:%d\n", __func__, __LINE__);
				return -1;
			}
			if ( pool_stat_init(pool_stat, pool, vs) != 0 ) {
				DP("Error func:%s line:%d\n", __func__, __LINE__);
				return -1;
			}
			/**************************/
			if(vs_stat->init != STAT_UNINIT) {
				int ret = 0;
				if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
					ret = xenserver_stat_init_for_one(vs_stat, pool, &vcenter_queue);
				} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
					ret = vcenter_stat_init_for_one(vs_stat, pool, &vcenter_queue);
				}
				if(ret == -1) {
					DP("Error func:%s line:%d\n", __func__, __LINE__);
					return -1;
				}
			}
			/***************************/
		}

		/* backpool */
		if ( pool != NULL && vs->backpool[0] != 0 ) {
			DP("func:%s line:%d add backpool\n", __func__, __LINE__);
			if ((backpool = apppool_search(&pool_queue, vs->backpool)) == NULL) {
				DP("Error func:%s line:%d\n", __func__, __LINE__);
				return -1;
			}

			if ((pool_stat_back = pool_stat_search(vs_stat, backpool->name)) == NULL ) {
				DP("func:%s line:%d add backpool\n", __func__, __LINE__);
				if ( (pool_stat_back = pool_stat_add(vs_stat, backpool)) == NULL ) {
					DP("Error func:%s line:%d\n", __func__, __LINE__);
					return -1;
				} 
				if ( pool_stat_init(pool_stat_back, backpool, vs) != 0 ) {
					DP("Error func:%s line:%d\n", __func__, __LINE__);
					return -1;
				}
				/**************************/
				if(vs_stat->init != STAT_UNINIT){
					int ret = 0;
					if (strcmp(backpool->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
						ret = xenserver_stat_init_for_one(vs_stat, backpool, &vcenter_queue);
					} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
						ret = vcenter_stat_init_for_one(vs_stat, backpool, &vcenter_queue);
					}
					if(ret == -1) {
						DP("Error func:%s line:%d\n", __func__, __LINE__);
						return -1;
					}
				}
				/***************************/
			}
			DP("func:%s line:%d add backpool\n", __func__, __LINE__);
		}
	} else if (vs->pool[0] == 0 && strcmp(vs->contentswitch, "on") == 0) {
		/* 内容交换 */
		list_for_each_entry(rule_name, &vs->rule_head, list) {
			memset(poolname, 0, sizeof(poolname));
			if ((rule = rule_search(&rule_queue, rule_name->name)) == NULL) {
				continue;
			}

			if(strcmp(rule->type, "cswitch") != 0) { //过滤掉不是内容交换的
				continue;
			}

			if ((get_poolname_from_rule(rule, poolname, sizeof(poolname) - 1 )) == NULL) {
				continue;
			}
			DP("Contentswitch: init rule pool:%s\n", poolname);

			if ((rulepool = apppool_search(&pool_queue, poolname)) == NULL) {
				continue;
			}

			if ((pool_stat_rule = pool_stat_search(vs_stat, poolname)) == NULL ) {
				if ( (pool_stat_rule = pool_stat_add(vs_stat, rulepool)) == NULL ) {
					continue;
				} 
				if ( pool_stat_init(pool_stat_rule, rulepool, vs) != 0 ) {
					DP("Error func:%s line:%d\n", __func__, __LINE__);
					return -1;
				}
			}
		}
	}

	DP("func:%s line:%d\n", __func__, __LINE__);
	vs_stat_update(vs_stat, vs);

	return 0;
}

static void * vm_stop(void *data)
{
	int count = 0;
	char address[512];
	int ret = 0, found = 0;
	vm_stop_data_t *vsd;
	vsd = (vm_stop_data_t *)data;

	struct pool_stat *stat;
	struct apppool *pool;
	struct rserver *rs;
	struct vmx_stat *vmx_stat = NULL;
	struct vcenter *vcenter;

	DP("==func:%s\n", __func__);

	stat = vsd->pool_stat;
	if ((pool = vsd->pool) == NULL) {
		DP("ERROR: func:%s line:%d pool is NULL!\n", __func__, __LINE__);
		ret = -1;
		goto out;
	}

	/* find rserver */
	list_for_each_entry(rs, &pool->realserver_head, list) {
		memset(address, 0, sizeof(address));
		if (inet_sockaddr2address(&rs->address, address) == -1) {
			continue;
		}	
		if (strcmp(address, vsd->rsname) != 0) {
			continue;
		}
		found = 1;
		break;
	}

	DP("func:%s line:%d found:%d\n", __func__, __LINE__, found);

	if (!found) {
		DP("func:%s line:%d found:%d\n", __func__, __LINE__, found);
		goto out;
	}

	/* find vcenter */
	if ((vcenter = vcenter_search(&vcenter_queue, rs->rscenter)) == NULL) {
		DP("func:%s line:%d found:%d rs->rscenter:%s\n", __func__, __LINE__, found, rs->rscenter);
		goto out;
	}

	/* find vmx_stat */
	list_for_each_entry(vmx_stat, &stat->vmx_head, list) {
		if (strcmp(vmx_stat->address, address) == 0) {
			break;
		}
	}

	DP("func:%s line:%d found:%d\n", __func__, __LINE__, found);
	while(count < 3) {
		DP("func:%s line:%d 第[%d]次停止 rs:[%s]\n", __func__, __LINE__, count + 1, address);
		if (count > 0) {
			usleep(count*VMWARE_MIN_RETRY_INTERVAL);
		}
		if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VMWARE)==0) {
			/* vmware */
			ret =  vmware_stop(vsd->pool_stat, pool, rs);
		} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_XENSERVER)==0) {
			/* xenserver */
			ret = xenserver_stop(vsd->pool_stat, pool, rs, vcenter);
		} else if (strcmp(pool->vmtype, ELASTIC_POOL_TYPE_VCENTER)==0) {
			/* vcenter */
			ret = vcenter_stop(vsd->pool_stat, pool, rs, vcenter);
		}
		if (!ret) {
			/* stop ok! */
			break;
		}
		count++;
	}

	reset_timer(stat);
	if (!ret) {
		DP("func:%s line:%d 停止成功: stat:%s vmx_Stat:%s\n", __func__, __LINE__, vsd->pool_stat->name, vmx_stat->address);
		/* 停止成功 */
		vmx_stat->retry = 0;
		vmx_stat->mode = MODE_DOWN;
		vmx_stat->silence = 0;
		vsd->pool_stat->silence = 2;
	} else {
		/* 停止失败 */
		DP("func:%s line:%d 停止失败: stat:%s vmx_Stat:%s\n", __func__, __LINE__, vsd->pool_stat->name, vmx_stat->address);
		if (++vmx_stat->retry > VMWARE_MAX_RETRY) {
			vmx_stat->silence = VMWARE_MAX_SILENCE;
		}
	}


out:
	//pthread_mutex_unlock(&vsd->pool_stat->mutex);

	/** 释放apppool_copy的内存 */
	if (vsd->pool != NULL) {
		apppool_free(&vsd->pool->list);
		vsd->pool = NULL;
	}

	return NULL;
}

static int process_request(char *buff)
{
	char poolname[1024] = {0}, op[1024] = {0}, tmp[1024] = {};
	struct vs_stat *vs_stat = NULL;
	struct pool_stat *stat = NULL;
	struct apppool *pool = NULL;
	int found  = 0;

	/** buff: stop pool vmxpath **/
	/** changed to stop pool rs->address **/
	DP("%s : buff = %s\n", __func__, buff);

	sscanf(buff, "%s %s %s", op, poolname, tmp); /** tmp rs->address **/

	/** get stat **/
	list_for_each_entry(vs_stat, &statistics, list) {
		list_for_each_entry(stat, &vs_stat->pool_head, list) {
			if (strcmp(stat->name, poolname)==0) {
				found =1; 
				break;
			}
		}
		if (found) {
			break;
		}
	}

	if (!found) {
		return -1;
	}

	if (!strcmp(op, "stop")) {
		pthread_data_t *th;
		vm_stop_data_t *vdata;
		if ((th = calloc(1, sizeof(pthread_data_t))) == NULL||
				(vdata = calloc(1, sizeof(vm_stop_data_t)))==NULL ) {
			return -1;
		}

		strcpy(vdata->poolname, poolname);
		strcpy(vdata->rsname, tmp);
		vdata->pool_stat = stat;

		if (list_empty(&pool_queue)) {
			DP("@@@@@@@@@@@@@@@@ERROR: func:%s line:%d pool_queue is NULL!\n", __func__, __LINE__);
		}

		if ((pool = apppool_search(&pool_queue, poolname)) == NULL) {
			free(vdata);
			free(th);
			return -1;
		}
		apppool_copy(pool, &vdata->pool);

		th->data = vdata;
		th->handler = vm_stop;
		pthread_execute((void *)th);
	}

	DP("func:%s line:%d\n", __func__, __LINE__);
	return 0;
}

static void callback_connection(int epfd, int fd, struct event *e)
{
	char buf[BUFSIZ];
	int  len;

	memset(buf, '\0', sizeof(buf));
	if ((len = read(fd, buf, sizeof(buf))) <= 0)
		goto out;

	/** when flush_vserver_state , if rserver is draining or disabled 
	 * daemon4 notify_vmware_daemon stop the rserver **/

	if (list_empty(&pool_queue)) {
		DP("@@@@@@@@@@@@@@@@ 2222222222222 ERROR: func:%s line:%d pool_queue is NULL!\n", __func__, __LINE__);
	}


	process_request(buf);
out:
	event_destroy(epfd, fd, e); /** close(fd) and free(e) **/
	return;
}

static int fd_cloexec(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFD, 0)) == -1)
		return -1;

	return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/*
 * callback_listen: listen callback function
 * @e: connection event
 */
static void callback_listen(int epfd, int fd, struct event *e)
{
	struct event *tmp;
	int connfd;

	if ((connfd = accept(fd, NULL, NULL)) == -1) {
		err("accept");
		goto out;
	}

	fd_cloexec(connfd);

	/* event_set: allocate event memory */
	tmp = event_set(epfd, connfd, EPOLLIN, callback_connection);
	if (tmp == NULL) {
		perror("event_set");
		goto err;
	}

	if (event_add(tmp) == -1) {
		perror("event_add");
		goto err1;
	}
	return;
err1:
	free(tmp);
err:
	close(connfd);
out:
	return;
}

static int __event_dispatch_loop(int epfd)
{
	struct epoll_event ev[1024];
	int count;
	int i;
	struct event *e;

	memset(&ev, '\0', sizeof(ev));
	count = epoll_wait(epfd, ev, 1024, 1000);
	if (count <= 0)
		goto out;

	for (i = 0; i < count; i++) {
		e = (struct event *)ev[i].data.ptr;
		if (e && e->callback) {
			e->events = ev[i].events;	/* current events */
			e->callback(e->event_epfd, e->event_fd, e);
		}
	}
out:
	return count;
}


/* 检查弹性计算VS参数配置 
 * 返回值: 1-有效; 0-无效 */
static unsigned short elastic_value_valid_check(
		unsigned long vm_conn_low, 
		unsigned long vm_conn_high, 
		unsigned long vm_newconn_low, 
		unsigned long vm_newconn_high, 
		unsigned long vm_band_low, 
		unsigned long vm_band_high)
{
	/* 配置弹性计算阀值时，“服务器并发连接”和“服务器新建“服务器流量带宽”三种阀值类型中至少选择一种，
	 * 且高限/低限阀值参数同时捆绑配置（不能只设置高限，或只设置低限），此时弹性计算引擎方可工作；
	 * 任意阀值类型未输入配置数据，视为不参与决策，阀值参数值必须大于零。
	 */
	unsigned short ret;
	DP("conn_low:%d conn_high:%d newconn_low:%d newconn_high:%d band_low:%d band_high:%d\n",
			vm_conn_low, vm_conn_high, vm_newconn_low, vm_newconn_high, vm_band_low, vm_band_high);

	ret &= VMWARE_VALUE_INVALID;
	/* 服务器并发 */
	if (vm_conn_high > 0 && vm_conn_low > 0 && vm_conn_high > vm_conn_low) {
		ret |= VMWARE_VALUE_CONN_VALID;
	}

	/* 服务器新建 */
	if (vm_newconn_high > 0 && vm_newconn_low > 0 && vm_newconn_high > vm_newconn_low) {
		ret |= VMWARE_VALUE_NEWCONN_VALID;
	}

	/* 流量带宽 */
	if (vm_band_high > 0 && vm_band_low > 0 && vm_band_high > vm_band_low ) {
		ret |= VMWARE_VALUE_BAND_VALID;
	}

	return ret;
}

/* entrance */
static void child_main()
{
	char address[512];
	//	unsigned long i = 0;

	struct vserver *vs = NULL;
	struct event *e;
	int epoll_fd;
	int listen_fd;
	int is_license_ok;
	time_t last_time, now;

	if ((epoll_fd = event_init()) < 0)
		goto err;

	if ((listen_fd = tcp_unix_listen(VMWARE_DAEMON)) == -1)
		goto err1;

	e = event_set(epoll_fd, listen_fd, EPOLLIN, callback_listen);
	if (e == NULL) {
		DP("event_set");
		goto err2;
	}

	if (event_add(e) == -1) {
		DP("event_add");
		goto err3;
	}

	//	for (i=0;;i++) {
	while(1){
		last_time = time(NULL);
		__event_dispatch_loop(epoll_fd);
		now = time(NULL);

		if (now - last_time > 10) {
			DP("usleep start\n");
			usleep(now - last_time);
			DP("usleep over\n");
		}

		if((is_license_ok = license_check()) == -1){
#if 0
			static long int count = 0;
			if(count == 0){
				fprintf(stderr, "There is no license!\n\n");
			}
			count++;
#endif
			continue;
		}

		/* TODO: 放到线程里处理 ？*/
		vcenter_flush(&vcenter_queue);

		DP("开始刷新vcenter_flush_config\n");
		if (pthread_mutex_trylock(&vcenter_flush_lock) == 0) {
			pthread_data_t *pd = NULL;
			if ((pd = calloc(1, sizeof(pthread_data_t))) != NULL) {
				struct vcenter_flush_lock_s *vf;
				if ((vf = calloc(1, sizeof(struct vcenter_flush_lock_s))) != NULL) {
					vf->lock = &vcenter_flush_lock;
					vf->vcenter_queue = &vcenter_queue;
					pd->data = vf;
					pd->handler = vcenter_flush_config;
				}
				pthread_execute(pd);
			} else {
				free(pd);
				pd = NULL;
				pthread_mutex_unlock(&vcenter_flush_lock);
			}
		}  else {
			DP("已经vcenter_flush_config锁定, 跳出\n");
		}
		DP("刷新结束!\n");


		//DP("\n=%ld==========%s loop===\n", i,  __func__);

		time_t t0  = time((time_t *)NULL);
		cli_send_flush_state_command("vserver");
		DP("flush vserver use :%d\n", (int)time((time_t *)NULL) - (int)t0);
		t0 = time((time_t *)NULL);
		cli_send_flush_state_command("apppool");
		DP("flush pool use :%d\n", (int)time((time_t *)NULL) - (int)t0);
		cli_send_flush_state_command("rule");
		DP("flush rule use: %d\n", (int)time((time_t *)NULL) - (int)t0);



		//cli_send_flush_state_command("vcenter");


		/* free old */
		if (!list_empty(&vs_queue)) {
			module_purge_queue(&vs_queue, "vserver");
		} 

		if (!list_empty(&pool_queue)) {
			module_purge_queue(&pool_queue, "apppool");
		}

		if (!list_empty(&rule_queue)) {
			module_purge_queue(&rule_queue, "rule");
		}

		/* flush vs_queue, pool_queue */
		module_get_queue(&vs_queue, "vserver", NULL);
		module_get_queue(&pool_queue, "apppool", NULL);
		module_get_queue(&rule_queue, "rule", NULL);

		sync_vs_stat(&vs_queue /** vserver_queue **/, &pool_queue);

		DP("########stat print start #################\n");
		stat_print();
		DP("########stat print end   #################\n");

		/* FOR Debug: printf vs_stat */
		vs_stat_print();

		list_for_each_entry(vs, &vs_queue, list) {
			memset(address, 0, sizeof(address));
			if (inet_sockaddr2address(&vs->address, address) == -1) {
				continue;
			}
			if ((address[0] == '\0') ||
					(vs->pool[0] == 0 && strcmp(vs->contentswitch, "on")!=0) ||
					strcmp(vs->enable, "off") == 0 ||
					strcmp(vs->vm_enable, "off") == 0 )
				continue;

			/* 阀值检测 */
			if ( elastic_value_valid_check(atol(vs->vm_conn_low), 
						atol(vs->vm_conn_high), atol(vs->vm_newconn_low), 
						atol(vs->vm_newconn_high), atol(vs->vm_band_low), 
						atol(vs->vm_band_high)) == VMWARE_VALUE_INVALID) {
				DP("Error: vs:%s 阀值检测无效!\n", vs->name);
				continue;
			}

			handle_vserver(vs);
		}

		sync_vserver_to_vserver_stat(&vs_queue, &statistics);
	}

	if (!list_empty(&vs_queue)) {
		module_purge_queue(&vs_queue, "vserver");
	}

	if (!list_empty(&pool_queue)) {
		module_purge_queue(&pool_queue, "apppool");
	}

	if (!list_empty(&rule_queue)) {
		module_purge_queue(&rule_queue, "rule");
	}

err3:
	free(e);
err2:
	close(listen_fd);
err1:
	close(epoll_fd);
err:
	return;
}

#define NDEBUG
#ifdef NDEBUG

static pid_t child_pid;
static void sigusr1_child_handler(int signo)
{
	restart = 1;
}
#endif
static void start_child_process(void)
{
#ifdef NDEBUG

	child_pid = fork();
	if (child_pid == -1) {
		err("fork");
		return;
	} else if (child_pid == 0) {
		signal_handler(SIGCHLD, SIG_DFL);
		signal_handler(SIGUSR1, sigusr1_child_handler);
		child_main();
	}
#else
	child_main();
#endif
}

#ifdef NDEBUG
static void signal_chld(int signo)
{
	pid_t pid;

	pid = waitpid(-1, NULL, 0);
	if (pid == -1 || pid == 0 || pid != child_pid)
		return;

	start_child_process();
}
#endif

static void sigusr1_handler(int signo)
{
#ifdef DEBUG
	write(STDERR_FILENO, "sigusr1\n", 8);
#endif
#ifdef NDEBUG
	if (child_pid != -1) {
		kill(child_pid, SIGUSR1);
	}
#else
	restart = 1;
#endif
	return;
}

int main(int argc, char *argv[])
{
	/* smartlog init */
	SMT_LOG_INIT();

	log_message("vmware_daemon start!");

#ifdef NDEBUG
	daemon(1, 1);
#endif
	if (lock_file("/var/run/vmware_daemon.pid") == -1) {
		fprintf(stderr, "Message: %s is already running.\n", argv[0]);
		goto out;
	}

	system("chmod 777 /var/tmp");
#if 0	
	if (getuid() == 0) {
		struct passwd *p = getpwnam("wsadmin");
		if (p == NULL) {
			printf("Create user \"wsadmin\" first.\n");
			exit(-1);
		}
		system("chown wsadmin /var/run/vmware_daemon.pid");
		setuid(p->pw_uid);
	}
#endif

	init_libcomm();

	/** init for log4c **/
	ulog_init("/SmartGrid/shell");
	signal_handler(SIGPIPE, SIG_IGN);
	signal_handler(SIGUSR1, sigusr1_handler);
#ifdef NDEBUG
	signal_handler(SIGCHLD, signal_chld);
#endif
	start_child_process();
	for (;;)
		sleep(100);
out:
	ulog_fini();

	log_message("vmware_daemon finish!");
	SMT_LOG_FINI();

	return 0;
}
