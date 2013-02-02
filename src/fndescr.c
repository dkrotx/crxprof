/**
 * fndescr.c
 * Initialize function descriptions from process map
 */
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include "crxprof.h"
#include "symbols.h"
#include "liberty_stub.h"

fn_descr *g_fndescr = NULL;
int g_nfndescr = 0;

/* Order by addr ASC selecting shortest name if any aliases */
static int
fdescr_cmp(const fn_descr *a, const fn_descr *b)
{
    return (a->addr == b->addr)
           ? ( a->len == b->len ? strlen(a->name) - strlen(b->name) : (int)a->len - (int)b->len )
           : ( a->addr < b->addr ? -1 : 1 );
}


static void
add_fndescr(const char *name, unsigned long addr, unsigned len) {
    static int fn_descr_size = 0;
    fn_descr *descr;

    if (g_nfndescr == fn_descr_size) {
        fn_descr_size = (fn_descr_size == 0) ? 8096: fn_descr_size * 3 / 2;
        g_fndescr = (fn_descr *)realloc(g_fndescr, 
            fn_descr_size * sizeof(fn_descr) );
    }

    descr = &g_fndescr[g_nfndescr++];
    descr->name = strdup(cplus_demangle(name, AUTO_DEMANGLING) ?: name);
    descr->addr = addr;
    descr->len  = len;
}

static void
finalize_fndescr() {
    fn_descr *p  = g_fndescr,
             *pw = g_fndescr;
    int i;

    qsort(p, g_nfndescr, sizeof(fn_descr), (qsort_compar_t)fdescr_cmp);

    /* uniq by .addr */
    for (i = 1, ++p; i < g_nfndescr; i++, p++) {
        if (p->addr != pw->addr) {
            ++pw;
            if (pw != p) {
                if (pw->name) free(pw->name); 
                *pw = *p; p->name = 0;
            }
        }
    }
    for (i = pw - g_fndescr + 1; i < g_nfndescr; i++) {
        if (g_fndescr[i].name)
            free(g_fndescr[i].name);
    }

    g_nfndescr = pw+1 - g_fndescr;
    g_fndescr = (fn_descr *)realloc(g_fndescr, sizeof(fn_descr) * g_nfndescr);
}

void 
init_fndescr(pid_t pid)
{
    struct maps_ctx *mctx;
    struct maps_info *minf;
    char *exe;
    int i;

    exe = proc_get_exefilename(pid);
    if (!exe)
        err(1, "Failed to get path of %d", pid);

    elfreader_init();
    mctx = maps_fopen(pid);
    if (!mctx)
        err(1, "Failed to open maps file of PID %d", (int)pid);
    
    while ((minf = maps_readnext(mctx)) != NULL) {
        if ((minf->prot & PROT_EXEC) && minf->pathname[0] == '/') {
            elf_reader_t *er;

            if (!strcmp(minf->pathname, exe)) {
                print_message("reading symbols from %s (exe)", minf->pathname);
                /* [1] read text table */
                er = elf_read_textf(minf->pathname);

                if (!er)
                    err(1, "Failed to read text data from %s", minf->pathname);

                for (i = 0; i < er->nsymbols; i++) {
                    const elf_symbol_t *es = &er->symbols[i];
                    if (es->symbol_class == 'T')
                        add_fndescr(es->symbol_name, es->symbol_value, es->symbol_size);
                }
                elfreader_close(er);
            }
            else {
                /* [2] read dynamic table */
                off_t load_offset = minf->offset;
                off_t load_end = minf->offset + ((char *)minf->end_addr - (char *)minf->start_addr);
                er = elf_read_dynaf(minf->pathname);

                print_message("reading symbols from %s (dynlib)", minf->pathname);

                if (!er)
                    err(1, "Failed to read dynamic data from %s", minf->pathname);

                for (i = 0; i < er->nsymbols; i++) {
                    const elf_symbol_t *es = &er->symbols[i];
                    if ((es->symbol_class == 'T' || es->symbol_class == 'W') && 
                        (off_t)es->symbol_value >= load_offset && (off_t)es->symbol_value < load_end) 
                    {
                        add_fndescr(es->symbol_name, 
                            (off_t)es->symbol_value - load_offset + (unsigned long)(char *)minf->start_addr,
                            es->symbol_size);
                    }
                }
                elfreader_close(er);
            }
        }
        maps_free(minf);
    }
    free(exe);
    maps_close(mctx);

    finalize_fndescr();
}


void
free_fndescr()
{
    int i;

    if (g_fndescr) {
        for (i = 0; i < g_nfndescr; i++) {
            free(g_fndescr[i].name);
        }

        free(g_fndescr);
        g_fndescr = NULL;
        g_nfndescr = 0;
    }
}
