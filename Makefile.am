AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

man_MANS = crxprof.1
EXTRA_DIST = crxprof.1

bin_PROGRAMS = crxprof
crxprof_SOURCES = src/main.c src/fndescr.c \
                  src/ptime.c src/ptime.h \
                  src/elf_read.c src/maps.c \
                  src/trace.c src/visualize.c src/callgrind_dump.c \
                  src/utils.c \
                  src/liberty_stub.h src/symbols.h src/crxprof.h 

crxprof_LDADD = -lunwind-ptrace -lunwind-@ARCH_TAG@ -lunwind -lbfd -lrt -ldl
