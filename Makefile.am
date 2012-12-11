AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

bin_PROGRAMS = crxprof
crxprof_SOURCES = src/main.cpp src/callgrind_dump.cpp src/crxprof.hpp src/defs.hpp \
                  src/elf_read.c src/maps.c src/symbols.h \
                  src/trace.cpp src/utils.cpp src/visualize.cpp

crxprof_LDADD = -lunwind-ptrace -lunwind-@ARCH_TAG@ -lunwind -lbfd -lrt
