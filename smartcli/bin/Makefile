

LDFLAGS = -lcrypt -lxml2 -lssl -lpthread -lcrypto -lnetsnmp -L/SmartGrid/snmp/lib/
VPATH :=  ../../smartcommon/

TARGET = cli
OBJS = $(shell ls *.o) ../../smartcommon/libcomm.a

$(TARGET): $(OBJS) ../../vcenter/libvm_vcenter.a
	     echo "/SmartGrid/snmp/lib/" > /etc/ld.so.conf.d/netsnmp.conf
	     ldconfig
	     cc $(LDFLAGS) -o $@ $^


../../smartcommon/libcomm.a:
	make -C ../../smartcommon ACTION=$(ACTION) VERSION=$(VERSION)

clean distclean:
	rm -fr $(TARGET) $(OBJS)
dep depend:


