/* Use -liberty for demangling.
 * Most distribustions doestn't provide demangle.h
 */
#define DMGL_AUTO        (1 << 8)
#define AUTO_DEMANGLING DMGL_AUTO
extern char *cplus_demangle (const char *mangled, int options);
