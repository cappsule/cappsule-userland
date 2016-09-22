include ../../Makefile.inc

CFLAGS += -I$(CUAPI_INCLUDE_PATH) -I../../include/ -D_FILE_OFFSET_BITS=64
LDFLAGS += -lrt -lcrypto
CFLAGS_FUSE := $(CFLAGS) $(shell pkg-config fuse --cflags)
LDFLAGS_FUSE := $(LDFLAGS) $(shell pkg-config fuse --libs)
EXEC := fsclient fsserver mount_override.so

.PHONY: strip

all: $(EXEC)

strip: all
	$(STRIP) $(EXEC)

fsclient: fsclient.o packet.o ../common/ring.o ../common/xchan.o ../../common/drop_priv.o ../../common/error.o ../../common/utils.o
	$(CC) -o $@ $^ $(LDFLAGS_FUSE)

fsclient.o: fsclient.c
	$(CC) -o $@ -c $< $(CFLAGS_FUSE)

fsserver: aufs.o direct.o fsserver.o fsserver_op.o mount_handler.o overlay.o ../common/child.o ../common/infos.o ../common/ring.o ../common/xchan.o ../../common/error.o ../../common/filesystem.o ../../common/json.o ../../common/log.o ../../common/policy.o ../../common/readall.o ../../common/utils.o ../../common/uuid.o
	$(CC) -o $@ $^ -pie $(LDFLAGS) $(shell pkg-config --libs json-c)

mount_override.so: mount_override.o
	$(CC) -o $@ $^ -ldl $(LDFLAGS) -fPIC -shared

mount_override.o: mount_override.c
	$(CC) -o $@ -c $^ $(CFLAGS) -fPIC

../common/%.o:
	$(MAKE) -C ../common/ $(notdir $@)

../../common/%.o:
	$(MAKE) -C ../../common/ $(notdir $@)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o $(EXEC)
