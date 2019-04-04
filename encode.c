#include <stdio.h>
#include <stdint.h>
#include "encode.h"
#include "bitset.h"

/* get numerical comparison operator from x  */
op_t get_num_comp_op (unsigned char x) 
{
    if (B_IS_SET(x, B_LT) && B_IS_SET(x, B_EQ))
        return OP_LE;
    else if (B_IS_SET(x, B_GT) && B_IS_SET(x, B_EQ))
        return OP_GE;
    else if (B_IS_SET(x, B_LT) && B_IS_SET(x, B_GT)) // != is <>
        return OP_NE;
    else if (B_IS_SET(x, B_LT))
        return OP_LT;
    else if (B_IS_SET(x, B_GT))
        return OP_GT;
    else if (B_IS_SET(x, B_EQ))
        return OP_EQ;
    return OP_EQ; // shut off warn
}

/* set numerical comparison operator op in x  */
void set_num_comp_op (unsigned char *x, op_t op) 
{
    switch(op) {
        case OP_LT: 
            B_SET(*x, B_LT);
            break;
        case OP_GT: 
            B_SET(*x, B_GT);
            break;
        case OP_EQ: 
            B_SET(*x, B_EQ);
            break;
        case OP_LE: 
            B_SET(*x, B_EQ);
            B_SET(*x, B_LT);
            break;
        case OP_GE: 
            B_SET(*x, B_GT);
            B_SET(*x, B_EQ);
            break;
        case OP_NE: 
            B_SET(*x, B_GT);
            B_SET(*x, B_LT);
            break;
        default: printf ("\n No such op");
                 break;
    }
}

/* copied from Bit Twiddling Hacks site  */
unsigned int get_log2 (unsigned int v) 
{  /* v - 32-bit value to find the log2 of  */
    const unsigned int b[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
    const unsigned int S[] = {1, 2, 4, 8, 16};
    int i;

    register unsigned int r = 0; /* result of log2(v) will go here */
    for (i = 4; i >= 0; i--) /* unroll for speed... */
    {
        if (v & b[i])
        {
            v >>= S[i];
            r |= S[i];
        } 
    }
    return r;
}

