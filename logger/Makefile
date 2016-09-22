include ../Makefile.inc

CFLAGS += -I$(CUAPI_INCLUDE_PATH) -I../include
LDFLAGS += -pie
TARGET := logger

.PHONY: strip

all: $(TARGET)

strip: all
	$(STRIP) $(TARGET)

$(TARGET): $(TARGET).o ../common/error.o ../common/filesystem.o ../common/log.o ../common/utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

../common/%.o:
	$(MAKE) -C ../common/ $(notdir $@)

clean:
	rm -f $(TARGET) *.o
