OUT_PATH=bin/unpackfire

CC=g++
CPPFLAGS=-I${SRC_PATH}/lib -std=c++11 -g -Wall

bin/unpackfire: unpackfire.o
	@mkdir -p $(@D)
	${CC} $< -o $@

all: $(OUT_PATH)

.PHONY: clean
clean:
	@rm -rf ${OUT_PATH}
	@rm -rf *.o

