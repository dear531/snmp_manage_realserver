

LDFLAGS = -lcrypt -lxml2 -lssl -lpthread -lcrypto -lnetsnmp
VPATH :=  ../../smartcommon/

TARGET = cli
OBJS = $(shell ls *.o) ../../smartcommon/libcomm.a

$(TARGET): $(OBJS) ../../vcenter/libvm_vcenter.a
	     cc $(LDFLAGS) -o $@ $^

../../smartcommon/libcomm.a:
	make -C ../../smartcommon ACTION=$(ACTION) VERSION=$(VERSION)

clean distclean:
	rm -fr $(TARGET) $(OBJS)
dep depend:


