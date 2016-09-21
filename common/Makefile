include ../Makefile.inc

CFLAGS += -I../include -I$(CUAPI_INCLUDE_PATH) -fPIC
LDFLAGS_TESTS := $(LDFLAGS) $(shell pkg-config --libs json-c) -lrt -lcmocka -lcrypto
TARGET := daemon_utils.o devices.o drop_priv.o error.o error_hv.o exec.o filesystem.o json.o log.o namespace.o policy.o readall.o sendfd.o setproctitle.o signals.o utils.o uuid.o

ifneq ($(NOTESTS),1)
	TARGET += tests
endif

.PHONY: strip check

all: $(TARGET)

tests: tests.o error.o filesystem.o policy.o uuid.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS_TESTS)

strip:

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(TARGET) *.o

check:
	./tests
