include ../../Makefile.inc

CFLAGS += -I$(CUAPI_INCLUDE_PATH) -I../../include/
LDFLAGS += $(shell pkg-config --libs json-c) -lrt -lcrypto -lutil
EXEC := consoleserver

.PHONY: strip

all: $(EXEC)

strip: all
	$(STRIP) $(EXEC)

consoleserver: consoleserver.o ../common/child.o ../common/infos.o ../common/ring.o ../common/xchan.o ../../common/error.o ../../common/filesystem.o ../../common/json.o ../../common/log.o ../../common/policy.o ../../common/readall.o ../../common/sendfd.o ../../common/utils.o ../../common/signals.o ../../common/uuid.o
	$(CC) -o $@ $^ $(LDFLAGS)

../common/%.o:
	$(MAKE) -C ../common/ $(notdir $@)

../../common/%.o:
	$(MAKE) -C ../../common/ $(notdir $@)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o $(EXEC)
