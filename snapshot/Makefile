include ../Makefile.inc

CFLAGS += -I../include -I../include -I$(CUAPI_INCLUDE_PATH)
LDFLAGS += -static
TARGET := snapshot

.PHONY: strip check

all: $(TARGET)

strip: all
	$(STRIP) daemon

snapshot: capsule_init.o snapshot.o ../common/error.o ../common/error_hv.o ../common/readall.o ../common/setproctitle.o ../common/utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

../common/%.o:
	$(MAKE) -C ../common/ $(notdir $@)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(TARGET) *.o
