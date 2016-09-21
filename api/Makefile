include ../Makefile.inc

CFLAGS += -I../include -I$(CUAPI_INCLUDE_PATH)
TARGETS := api_common.o api_parse.o api_pending.o api_server.o create_capsule.o
LDFLAGS_TESTS := $(LDFLAGS) $(shell pkg-config --libs json-c) -lcmocka -lcrypto

ifneq ($(NOTESTS),1)
	TARGETS += tests
endif

.PHONY: strip

all: $(TARGETS)

strip: all
	$(STRIP) $(TARGETS)

tests: tests.o api_common.o api_pending.o create_capsule.o ../common/daemon_utils.o ../common/devices.o ../common/drop_priv.o ../common/error.o ../common/error_hv.o ../common/json.o ../common/policy.o ../common/readall.o ../common/setproctitle.o ../common/signals.o ../common/utils.o ../common/uuid.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS_TESTS) -Wl,--wrap=close -Wl,--wrap=ioctl

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

../common/%.o:
	$(MAKE) -C ../common/ $(notdir $@)

clean:
	rm -f $(TARGETS) *.o

check:
	./tests
