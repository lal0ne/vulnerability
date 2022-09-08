FLAGS = -static -no-pie -Werror -s -Os -Wno-unused-result

TARGET ?= exploit

.PHONY: all

all: $(TARGET)

exploit: exploit.c
	gcc $< -o $@ $(FLAGS)

poc: poc.c
	gcc $< -o $@ $(FLAGS)