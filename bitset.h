#if !defined(__BITSET_H)

#define __BITSET_H
#define GETLONG(ptr) getlong_inline(ptr)
#define GETSHORT(ptr) getshort_inline(ptr)

#define PUTSHORT(ptr, val) putshort_inline((ptr), (val))
#define PUTLONG(ptr, val) putlong_inline((ptr), (val))


static inline
unsigned short getshort_inline(register void const *ptr)
{
    return ( ((uint8_t *)ptr)[0] << 8 | ((uint8_t *)ptr)[1] );
}

static inline
unsigned long getlong_inline(register void const *ptr)
{
    return( getshort_inline(ptr) << 16 | getshort_inline((uint16_t *)ptr+1) );
}

static inline
void putshort_inline(register void *ptr, uint16_t value)
{
    ((uint8_t *)ptr)[1] = (uint8_t)value;
    ((uint8_t *)ptr)[0] = (uint8_t)(value >> 8);
}

static inline
void putlong_inline(register void *ptr, register unsigned long value)
{
    putshort_inline(ptr, (uint16_t)(value >> 16));
    putshort_inline((uint16_t *)ptr+1, (uint16_t)value);
}

static inline
void put_3byte(unsigned char *ptr, uint32_t value)
{
    ((uint8_t *)ptr)[2] = (uint32_t)value;
    ((uint8_t *)ptr)[1] = (uint32_t)(value >>  8);
    ((uint8_t *)ptr)[0] = (uint32_t)(value >> 16);
}

static inline
uint32_t get_3byte(unsigned char *ptr)
{
    return  ( ((uint8_t *)ptr)[0] << 16 ) |
            ( ((uint8_t *)ptr)[1] <<  8 ) |
            ( ((uint8_t *)ptr)[2] );
}
/* test if n-th bit in x is set */
#define B_IS_SET(x, n)   (((x) & (1 << (n))) ? 1 : 0)
/* set n-th bit in x */
#define B_SET(x, n)      ((x) |= (1 << (n)))
/* unset n-th bit in x */
#define B_UNSET(x, n)    ((x) &= ~(1 << (n)))

#if 0 
/* debug only - remove  */
void printcharbits (int num)
{
    int  i;

    for (i = 7; i > -1; i--)
    {
        if (num & (1 << i)) printf("1");
        else printf("0");
        if (!(i % 8))
            printf (" ");
    }
}
#endif 
#endif 
