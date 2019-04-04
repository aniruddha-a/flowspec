
#if !defined(__DEBUG_H)
#define __DEBUG_H

#define DEBUG 1   /* change this for debugs */

#if DEBUG
  #define DBG_PRINT printf
#else
  #define DBG_PRINT dummy
#endif
int dummy(const char *fmt, ...); 

#endif 
