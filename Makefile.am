AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

bin_PROGRAMS = crxprof
crxprof_SOURCES = src/main.c src/fndescr.c src/callgrind_dump.c src/crxprof.h \
                  src/elf_read.c src/maps.c src/symbols.h \
                  src/trace.c src/utils.c src/visualize.c

crxprof_LDADD = -lunwind-ptrace -lunwind-@ARCH_TAG@ -lunwind -lbfd -lrt
