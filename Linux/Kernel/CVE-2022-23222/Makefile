EXP := exploit
HDRS := $(sort $(wildcard include/*.h))

CFLAGS += -I include -static -w

all: $(EXP)

%: %.c $(HDRS)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXP)