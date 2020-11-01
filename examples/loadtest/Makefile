CC=gcc
CFLAGS=-Wall -I/opt/snf/include
LDFLAGS=-L/opt/snf/lib -lsnf -lpthread
SRCS=main.c
EXE=loadtest

$(EXE): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(EXE)
