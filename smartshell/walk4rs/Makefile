

CFLAGS ?= -g -Wall -Werror

CFLAGS += -I ../../smartcommon -I /usr/include/libxml2 -I../../smartcommon/ -I../../smartlog 
LDFLAGS = -lxml2 -lssl -lcrypto -lpthread -llog4c 
CFLAGS += -I ../../vmware/
CFLAGS += -I ../../vcenter/vm_vcenter/
CFLAGS += -I /usr/include/vmware-vix
CFLAGS += -I ../../xenserver/xenserver/

LDFLAGS = -lxml2 -lssl -lcrypto -lpthread -llog4c
LDFLAGS += -lxensrv -lxenserver
LDFLAGS += -lvmware  -lvixAllProducts -ldl
LDFLAGS += -lnetsnmp -L/SmartGrid/snmp/lib

VPATH := ../../smartcommon/

ifneq ($(ACTION), release)
CFLAGS += -DDEBUG
endif


ifdef VERSION
CFLAGS += -DVERSION=\"$(VERSION)\"
endif

_OBJS = $(shell ls *.c)
OBJS = $(_OBJS:.c=.o)


all:walk4rs

walk4rs: $(OBJS) ../../smartcommon/libcomm.a  ../../smartlog/liblog4c_user.a ../../vcenter/libvm_vcenter.a
	cc $(LDFLAGS) -o $@ $^
	@if [  -e /etc/ld.so.conf.d/netsnmp.conf -a "`cat /etc/ld.so.conf.d/netsnmp.conf`" == "/SmartGrid/snmp/lib/" ];\
	then\
		echo "" > /dev/null;\
	else\
		echo "/SmartGrid/snmp/lib/" > /etc/ld.so.conf.d/netsnmp.conf;\
	ldconfig;\
	fi


-include .depend

%.o: %.c
	cc $(CFLAGS) -o $@ -c $<

../../smartcommon/libcomm.a:
	make -C ../../smartcommon ACTION=$(ACTION) VERSION=$(VERSION)


../../gslbagent/libgetslb_info.a:
	make -C ../../gslbagent ACTION=$(ACTION) VERSION=$(VERSION)

clean:
	rm -fr $(OBJS) walk4rs

distclean: clean
	rm -fr .depend

dep depend:
	cc $(CFLAGS) -M -MM $(_OBJS) > .depend
