

CFLAGS ?= -g -Wall -Werror

CFLAGS += -I ../../smartcommon -I /usr/include/libxml2 -I../../smartcommon/ -I../../smartlog 
LDFLAGS = -lxml2 -lcrypto -llog4c 

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
