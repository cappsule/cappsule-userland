include ../Makefile.inc

CFLAGS += -I../include -I$(CUAPI_INCLUDE_PATH)
LDFLAGS_DAEMON := $(LDFLAGS) $(shell pkg-config --libs json-c) -lcrypto
LDFLAGS_TESTS := $(LDFLAGS) -lcmocka
TARGETS := daemon

ifneq ($(NOTESTS),1)
	TARGETS += tests
endif

.PHONY: strip check

all: $(TARGETS)

strip: all
	$(STRIP) daemon

tests: tests.o swap.o ../common/error.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS_TESTS) -Wl,--wrap=fgets -Wl,--wrap=swapoff -Wl,--wrap=swapon

daemon: daemon.o ramfs.o swap.o ../api/create_capsule.o ../api/api_common.o ../api/api_parse.o ../api/api_pending.o ../api/api_server.o ../common/devices.o ../common/daemon_utils.o ../common/drop_priv.o ../common/error.o ../common/error_hv.o ../common/exec.o ../common/filesystem.o ../common/json.o ../common/namespace.o ../common/policy.o ../common/readall.o ../common/setproctitle.o ../common/signals.o ../common/utils.o ../common/uuid.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_DAEMON)

../api/%.o:
	$(MAKE) -C ../api/ $(notdir $@)

../common/%.o:
	$(MAKE) -C ../common/ $(notdir $@)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(TARGETS) *.o

check:
	./tests
