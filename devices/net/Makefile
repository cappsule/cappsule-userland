include ../../Makefile.inc

CFLAGS += -I$(CUAPI_INCLUDE_PATH) -I../../include/
LDFLAGS += -lrt -lcrypto
EXEC := netclient netserver

.PHONY: strip

all: $(EXEC)

strip: all
	$(STRIP) $(EXEC)

netclient: netclient.o net_common.o ../common/device_client.o ../common/ring.o ../common/xchan.o ../../common/drop_priv.o ../../common/error.o ../../common/readall.o
	$(CC) -static -o $@ $^ $(LDFLAGS)

netserver: netserver.o net_policy.o net_common.o ../common/child.o ../common/infos.o ../common/ring.o ../common/xchan.o ../../common/error.o ../../common/exec.o ../../common/filesystem.o ../../common/json.o ../../common/log.o ../../common/namespace.o ../../common/policy.o ../../common/readall.o ../../common/utils.o ../../common/uuid.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs json-c)

../common/%.o:
	$(MAKE) -C ../common/ $(notdir $@)

../../common/%.o:
	$(MAKE) -C ../../common/ $(notdir $@)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o $(EXEC)
