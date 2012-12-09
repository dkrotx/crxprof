/*
 * elf_read.c
 *
 * Extract functions from ELF file using libbfd (binutils)
 */

#include <stdlib.h>
#include <assert.h>
#include <bfd.h>

#include "symbols.h"

/* internal BFD structure we need to extract size of symbol */
struct elf_internal_sym {
  bfd_vma       st_value;               /* Value of the symbol */
  bfd_vma       st_size;                /* Associated symbol size */
  unsigned long st_name;                /* Symbol name, index in string tbl */
  unsigned char st_info;                /* Type and binding attributes */
  unsigned char st_other;               /* Visibilty, and target specific */
  unsigned char st_target_internal;     /* Internal-only information */
  unsigned int  st_shndx;               /* Associated section index */
};

#define BFD_GET_SYMBOL_SIZE(psymbol) ( ((struct elf_internal_sym *)((char *)psymbol + sizeof(asymbol)))->st_size )
typedef enum { READSYMBOLS_TEXT, READSYMBOLS_DYNA } elfread_src_t;


void
elfreader_init()
{
    bfd_init();
}

static int
elf_read_symbols(elf_reader_t *reader, const char *path, elfread_src_t srcsec)
{
    int i, nsymbols, nfiltered, iflt;
    size_t storage_needed;

    reader->__abfd = bfd_openr(path, NULL);
    if (!reader->__abfd)
        return -1;

    bfd_check_format(reader->__abfd, bfd_object);
    storage_needed = (srcsec == READSYMBOLS_TEXT) ? 
        bfd_get_symtab_upper_bound(reader->__abfd) :
        bfd_get_dynamic_symtab_upper_bound(reader->__abfd);

    if (storage_needed <= 0) {
        return -1;
    }
    
    reader->__symbol_table = (asymbol**)malloc(storage_needed);
    if (!reader->__symbol_table)
        return -1;

    nsymbols = (srcsec == READSYMBOLS_TEXT) ? 
        bfd_canonicalize_symtab(reader->__abfd, reader->__symbol_table) : 
        bfd_canonicalize_dynamic_symtab(reader->__abfd, reader->__symbol_table);

    if (nsymbols < 0)
        return -1;

    nfiltered = 0;
    for (i = 0; i < nsymbols; i++) {
        if (reader->__symbol_table[i]->flags & (BSF_FUNCTION | BSF_GLOBAL))
            nfiltered++;
    }

    reader->symbols = (elf_symbol_t *)malloc(nfiltered * sizeof(elf_symbol_t));
    if (!reader->symbols)
        return -1;

    for (i = 0, iflt = 0; i < nsymbols && iflt < nfiltered; i++) {
        asymbol *is = reader->__symbol_table[i];

        if (is->flags & (BSF_FUNCTION | BSF_GLOBAL)) {
            elf_symbol_t *os = reader->symbols + iflt++;
            os->symbol_name   = (const char *)bfd_asymbol_name(is);
            os->symbol_value  = bfd_asymbol_value(is);
            os->symbol_size   = BFD_GET_SYMBOL_SIZE(is);
            os->symbol_class  = (char)bfd_decode_symclass(is);
        }
    }

    assert(iflt == nfiltered);
    return iflt;
}

static elf_reader_t *
call_elf_read_symbols(const char *path, elfread_src_t srcsec)
{
    elf_reader_t *reader = (elf_reader_t *)calloc(1, sizeof(elf_reader_t));
    int n;
    
    if (!reader)
        return NULL;
    
    n = elf_read_symbols(reader, path, srcsec);
    if (n == -1) {
        elfreader_close(reader);
        return NULL;
    }

    reader->nsymbols = n;
    return reader;
}

#define checked_free(x) do { if (x) free(x); } while(0)

void
elfreader_close(elf_reader_t *reader)
{
    if (reader) {
        checked_free(reader->symbols);
        checked_free(reader->__symbol_table);
        if (reader->__abfd) {
            bfd_close(reader->__abfd);
        }

        free(reader);
    }
}


elf_reader_t *
elf_read_textf(const char *path)
{
    return call_elf_read_symbols(path, READSYMBOLS_TEXT);
}

elf_reader_t *
elf_read_dynaf(const char *path)
{
    return call_elf_read_symbols(path, READSYMBOLS_DYNA);
}
