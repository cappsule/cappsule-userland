include ../../Makefile.inc

CFLAGS += -I../../include -I$(CUAPI_INCLUDE_PATH) -fPIC
LDFLAGS_TESTS := $(LDFLAGS) -lcmocka
TARGET := child.o device_client.o infos.o ring.o xchan.o

ifneq ($(NOTESTS),1)
	TARGET += tests
endif

.PHONY: strip check

all: $(TARGET)

tests: tests.o ring.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS_TESTS)

strip:

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(TARGET) *.o

check:
	./tests
