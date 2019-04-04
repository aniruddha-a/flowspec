#if !defined(__ENCODE_H)
#define __ENCODE_H

/* include bitset.h before this  */
#define B_EOL 7 
#define B_AND 6
#define B_LT  2
#define B_GT  1
#define B_EQ  0

#define B_NOT 1
#define B_MATCH 0

#define B_GET_LEN(X)  ( 1 << (((X) & 0x30) >> 4))
#define B_SET_LEN(X, N) ( (X) |= (get_log2(N) << 4))

typedef enum op_ {
    OP_LT = 1,
    OP_GT,
    OP_EQ,
    OP_LE,
    OP_GE,
    OP_NE
} op_t;
#define NO_OP 0
void set_num_comp_op(unsigned char *x,op_t op);
op_t get_num_comp_op(unsigned char x);
unsigned int get_log2(unsigned int v);

#endif
