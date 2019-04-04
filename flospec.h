#if !defined(__FLOSPEC__H)
#define __FLOSPEC__H

/* flow spec sub components */
typedef enum flo_comp_ {
    NLRI_DEST_PREFIX = 1,
    NLRI_SOURCE_PREFIX,
    NLRI_IP_PROTO,
    NLRI_PORT,
    NLRI_DEST_PORT,
    NLRI_SOURCE_PORT,
    NLRI_ICMP_TYPE,
    NLRI_ICMP_CODE,
    NLRI_TCP_FLAGS,
    NLRI_PAK_LEN,
    NLRI_DSCP,
    NLRI_FRAGMENT,
} flo_comp_t;

#define MAX_NLRI_COMPONENTS  13
#define NLRI_COMP_START      1
#define NLRI_PREFIX_TYPE(X)  ( ((X) == NLRI_DEST_PREFIX) || \
                               ((X) == NLRI_SOURCE_PREFIX) )

/* Define the Fragmentation Bitmask types  */
#define FRAG_BM_DF    0x01 
#define FRAG_BM_ISF   0x02
#define FRAG_BM_FF    0x04
#define FRAG_BM_LF    0x08

/* Main data type */
typedef struct flo_data_ {
    bool and;  /* 'and' is a cpp keyword - anything better? */ 
    op_t op;
    unsigned int value;
    uint8_t  len; /* only used with prefix type */
}  flo_data_t ;

typedef struct flo_decode_ {
    flo_comp_t comp;
    int num_elems;
    flo_data_t *d;
} flo_decode_t ; 

typedef struct flo_list_ {
    int n;
    flo_data_t *d;
} flo_list_t;

/* Macros to fill the flo_data_t structure in a clean way */

/* Macros to fill the numerical operator type  */
#define EQ(X)     { .and = false, .op=OP_EQ, .value=X } 
#define NE(X)     { .and = false, .op=OP_NE, .value=X }
#define LT(X)     { .and = false, .op=OP_LT, .value=X }
#define GT(X)     { .and = false, .op=OP_GT, .value=X }
#define LE(X)     { .and = false, .op=OP_LE, .value=X }
#define GE(X)     { .and = false, .op=OP_GE, .value=X }

/* syntactic sugars equivalent to above */
#define OR_EQ(X)  EQ(X)  
#define OR_NE(X)  NE(X)
#define OR_LT(X)  LT(X)
#define OR_GT(X)  GT(X)
#define OR_LE(X)  LE(X)
#define OR_GE(X)  GE(X)

#define AND_EQ(X) { .and = true, .op=OP_EQ, .value=X }
#define AND_NE(X) { .and = true, .op=OP_NE, .value=X }
#define AND_LT(X) { .and = true, .op=OP_LT, .value=X }
#define AND_GT(X) { .and = true, .op=OP_GT, .value=X }
#define AND_LE(X) { .and = true, .op=OP_LE, .value=X }
#define AND_GE(X) { .and = true, .op=OP_GE, .value=X }

/* Macros to fill the bitmask operator type  */
#define MATCH(X)         { .and = false, .op=OP_EQ, .value=X }
#define NOT_MATCH(X)     { .and = false, .op=OP_NE, .value=X }
#define OR_MATCH(X)      MATCH(X)
#define OR_NOT_MATCH(X)  NOT_MATCH(X)
#define AND_MATCH(X)     { .and = true, .op=OP_EQ, .value=X }
#define AND_NOT_MATCH(X) { .and = true, .op=OP_NE, .value=X }

#define RULE_BEGIN (flo_data_t[]){
#define RULE_END   }
/* Macros to fill the prefix components  */
#define PREFIX(X,Y)     { .value=(htonl(inet_addr(X)) >> (32-(Y))), .len = (Y)}

/* Comparison macros */
#define PREFIX_LEN(X)   X.len
#define MIN(A,B)  ((A) < (B) ? (A) : (B))
#define GET_PREFIX(X,Y) ((X.value) >> (32-(Y)) )
/* min inclusive range macro */
#define IN_RANGE(_x, _min, _max)  ( ((_x) >= (_min)) && ((_x) < (_max)) )

int     prefix_cmp (flo_data_t a, flo_data_t b, uint8_t comm);
uint8_t flospec_encode (unsigned char *p, flo_comp_t type, 
                        int num_comp, flo_data_t data[]);
bool    flospec_decode (unsigned char *p, flo_decode_t d[], int *num_comp);
void    flospec_show   (flo_decode_t d[], int len);

#endif 
