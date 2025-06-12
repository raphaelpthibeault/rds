CC = gcc
CFLAGS = -std=c2x -O2 -Wall -Wextra -pedantic -I./ -lcmocka

all: clean rds-test

test: clean rds-test
	@echo "----- Running standard tests... -----"
	@./rds-test

test-large: clean rds-test-large
	@echo "----- Running standard tests + LARGE tests (they're slow, 2**32 and 2**64 size strings)... -----"
	@./rds-test-large

rds-test: rds.c rds.h tests.c
	$(CC) -o $@ $^ $(CFLAGS)

rds-test-large: rds.c rds.h tests.c
	$(CC) -o $@ $^ $(CFLAGS) -DTEST_LARGE

clean:
	rm -f rds-test rds-test-large

.PHONY: all test test-large
