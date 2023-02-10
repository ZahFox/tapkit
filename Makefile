CC=gcc
CFLAGS=-g
CUNIT=-L/usr/include/CUnit -I/usr/include/CUnit -lcunit
LDFLAGS=
LDLIBS=-lpthread -lpcap -lnet

BIN = tapkit
SRCS = ds.c utils.c tpool.c $(BIN).c main.c
HDRS = common.h ds.h utils.h tpool.h $(BIN).h

.PHONY: all

all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

$(BIN)-unittest: $(SRCS) $(HDRS) cunittests.c cunittests.h
	$(CC) $(CFLAGS) -DTESTING $(SRCS) $(HDRS) cunittests.c -o $@ $(LDLIBS) $(CUNIT)

.PHONY: clean

clean:
	$(RM) -rf $(BIN) autotest test $(BIN)-unittest TEST_STDOUT TEST_STDERR