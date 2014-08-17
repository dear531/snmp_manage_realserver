SHELL := /bin/bash

LDFLAGS = -lcrypt -lxml2 -lssl -lpthread -lcrypto -lnetsnmp -L/SmartGrid/snmp/lib/
VPATH :=  ../../smartcommon/

TARGET = cli
OBJS = $(shell ls *.o) ../../smartcommon/libcomm.a

$(TARGET): $(OBJS) ../../vcenter/libvm_vcenter.a
	     cc $(LDFLAGS) -o $@ $^
		@if [  -e /etc/ld.so.conf.d/netsnmp.conf -a "`cat /etc/ld.so.conf.d/netsnmp.conf`" == "/SmartGrid/snmp/lib/" ];\
		then\
			echo "" > /dev/null;\
		else\
			 echo "/SmartGrid/snmp/lib/" > /etc/ld.so.conf.d/netsnmp.conf;\
			 ldconfig;\
		fi


../../smartcommon/libcomm.a:
	make -C ../../smartcommon ACTION=$(ACTION) VERSION=$(VERSION)

clean distclean:
	rm -fr $(TARGET) $(OBJS)
dep depend:


