#ifndef CRXPROF_SYMBOLS_H__
#define CRXPROF_SYMBOLS_H__

#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <bfd.h>

#ifdef __cplusplus
extern "C" {
#endif

struct maps_info
{
    void *start_addr;
    void *end_addr;
    int prot;         /* memory protection of mapping (like mmap(2)) */
    int flags;        /* MAP_SHARED or MAP_PRIVATE */
    off_t offset;     /* offset of mmaped file */
    dev_t st_dev;     /* ID of device containing file */
    ino_t st_ino;     /* inode number */
    char pathname[0]; /* backed file if has one */
};

struct maps_ctx
{
    FILE  *procfile;     /* source file in procfs */
    char  *linebuf;      /* allocated by getline */
    size_t linebuf_size;
};

/*
 * return path to executable of given pid
 * NULL in case of error
 * Caller responsible to free() returned string
 */
char *proc_get_exefilename(pid_t pid);

struct maps_ctx *maps_fopen(pid_t pid);
struct maps_info* maps_readnext(struct maps_ctx *ctx);
void maps_close(struct maps_ctx *ctx);

#define maps_free(x) do { if(x) free(x); } while(0)



typedef struct elf_symbol {
    const char *symbol_name;
    symvalue symbol_value;
    size_t symbol_size;
    char symbol_class;
} elf_symbol_t;

typedef struct elf_reader {
    bfd *__abfd;
    asymbol **__symbol_table;
    elf_symbol_t *symbols;
    int nsymbols;
} elf_reader_t;

/* ELF-symbol extraction */
void elfreader_init();

elf_reader_t *elf_read_textf(const char *path);
elf_reader_t *elf_read_dynaf(const char *path);
void elfreader_close(elf_reader_t *reader); /* free elf_reader_t */

#ifdef __cplusplus
}
#endif

#endif /* CRXPROF_SYMBOLS_H__ */
