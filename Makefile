CFLAGS=-Wall -Wextra -g
CXXFLAGS=$(CFLAGS)
#LDFLAGS=-static
LIBS=-lunwind-ptrace -lunwind-x86_64 -lunwind -lbfd -liberty -lz -ldl -lrt

crxprof: src/trace.o src/visualize.o src/callgrind_dump.o src/utils.o src/elf_read.o src/maps.o src/main.o  
	$(CXX) -g -o $@ $^ ${LDFLAGS} ${LIBS}

.cpp.o:
	$(CXX) -c -o $@ $(CXXFLAGS) $<

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $<

clean:
	$(RM) crxprof src/*.o
