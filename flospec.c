/*
 * BGP Flowspec encoding NLRI
 * NLRI Encoding as per
 * RFC5575 - Dissemination of Flow Specification Rules
 *
 * Fri Feb  5 09:09:31 IST 2010
 *
 * Aniruddha. A (aniruddha.a@gmail.com)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <limits.h>
#include <stdarg.h>
#include "bitset.h"
#include "encode.h"
#include "flospec.h"
#include "iana_ip_proto.h"
#include "dscp_cp.h"
#include "utils.h"
#include "token.h"
#include "debug.h"

/* build numerical operator */
uint8_t mk_num_op (bool eol, uint8_t numbytes, flo_data_t d)
{
    uint8_t res = 0;

    set_num_comp_op(&res, d.op);
    B_SET_LEN(res, numbytes);
    if (eol)
        B_SET(res, B_EOL);
    if (d.and)
        B_SET(res, B_AND);

    return res;
}

/* build bitmask operator */
uint8_t mk_bm_op (bool eol, uint8_t numbytes, flo_data_t d)
{
    uint8_t res = 0;

    B_SET_LEN(res, numbytes);
    if (eol)
        B_SET(res, B_EOL);
    if (d.and)
        B_SET(res, B_AND);
        
    if (d.op == OP_NE)
        B_SET(res, B_NOT);
    /* TODO m bit un-set handling   */
    B_SET(res, B_MATCH); /* set always for now  */
    return res;
}

uint8_t flospec_encode (unsigned char *p, flo_comp_t type, 
                        int num_comp, flo_data_t data[])
{
    int i;
    uint8_t (*mk_op) (bool, uint8_t, flo_data_t)  = NULL;
    uint8_t len = 0;
    uint8_t numbytes;
    bool eol = false;

    if ((type == NLRI_TCP_FLAGS) || (type == NLRI_FRAGMENT))
        mk_op = mk_bm_op;
    else if (NLRI_PREFIX_TYPE(type))
        mk_op = NULL;
    else
        mk_op = mk_num_op;

    *p = type; /* Type */
    p++;
    len ++;
    DBG_PRINT("\n Type = %02X ;", type); 
    for (i = 0; i < num_comp ; i++) {
        if (i == (num_comp - 1)) 
            eol = true; /* set eol for last elem */
        /* Calculate actual data bytes */
        numbytes = sizeof(unsigned int); /* flo_data_t.value  */
        if (data[i].value <= 0xFFFFFF) numbytes --;
        if (data[i].value <= 0xFFFF) numbytes --;
        if (data[i].value <= 0xFF) numbytes --;
        DBG_PRINT(" %s  op/len = %02X ; value = %02X, bytes = %d", 
                eol ? "Eol" : "", 
                mk_op ? mk_op(eol, numbytes, data[i]) : data[i].len,
                data[i].value, numbytes);
        *p = mk_op ? mk_op(eol, numbytes, data[i]) : data[i].len; /* OP/Len */
        p++;
        /* Data */
        switch (numbytes) {
            case 1:
                *p = data[i].value;
                break;
            case 2:
                PUTSHORT(p, data[i].value);
                break;
            case 3:
                put_3byte(p,  data[i].value);
                break;
            case 4:
                PUTLONG(p, data[i].value);
                break;
            default:
                DBG_PRINT ("\n Unknown length!");
                break;
        }
        p += numbytes;
        len += (1 + numbytes); 
    }
    
    DBG_PRINT("\n-----");
    return len;
}

uint8_t decode_bm_op(flo_data_t *d, uint8_t v)
{
    d->and = B_IS_SET(v, B_AND) ? true : false;
    d->op  = B_IS_SET(v, B_NOT) ? OP_NE : OP_EQ; 
    return B_GET_LEN(v);
}

uint8_t decode_num_op(flo_data_t *d, uint8_t v)
{
    d->op  = get_num_comp_op(v);
    d->and = B_IS_SET(v, B_AND) ? true : false;
    return B_GET_LEN(v);
}
/*
 * if returned success the flo_decode_t array is valid (and has num_comp
 * flow components)
 */
bool flospec_decode (unsigned char *p, flo_decode_t d[], int *num_comp)
{
    int i, last_seen = 0;
    unsigned char *cp;
    int  dlen;
    uint32_t comp_type;
    flo_data_t comp_data[10] ; /* max 10 vals per comp ? */
    int ci = 0; /* index to comp_data */
    uint32_t vlen;
    bool eol = true;

    if ((*p & 0xF0) == 0xF0) {
        dlen = get_3byte(p+1); 
        cp = p+2;
    } else {
        dlen = *p;
        cp = p+1;
    }
    DBG_PRINT ("\n Decode: data len =%d", dlen);
    i = 0;
    while (dlen > 0) {
        if (eol) {
            /* read comp type - 1b */
            comp_type =  d[i].comp = *cp;
            if (comp_type < last_seen) {
                printf("\n Error: components not ordered!");
                printf("\n curr-comp = %s [%d], prev was %s [%d] ",
                        show_nlri_comp(comp_type), comp_type, show_nlri_comp(last_seen), last_seen);
                return false;
            }
            DBG_PRINT ("\n Decode: Type = %s", show_nlri_comp(comp_type));
            last_seen = comp_type;
            cp++;
            dlen --;
            ci = 0;
        }
        /* read OP/len - 1b */
        if ((comp_type == NLRI_TCP_FLAGS) || (comp_type == NLRI_FRAGMENT)) {
            /* BM op */
            vlen = decode_bm_op(&comp_data[ci], *cp);
            eol = B_IS_SET(*cp, B_EOL);
        } else if (NLRI_PREFIX_TYPE(comp_type)) {
            comp_data[ci].len = *cp;
            vlen = *cp / 8; /* FIXME ceil() needed? */
            eol = true; /* only 1 val */
        } else {
            /* numerical op */
            vlen = decode_num_op(&comp_data[ci], *cp);
            eol = B_IS_SET(*cp, B_EOL);
        }
        DBG_PRINT ("\n Decode: bytes to read =%d", vlen);
        cp++;
        dlen --;
        /* read vlen bytes of value */
        switch (vlen) {
            case 1:
                comp_data[ci].value = *cp;
                break;
            case 2:
                comp_data[ci].value = GETSHORT(cp);
                break;
            case 3:
                comp_data[ci].value = get_3byte(cp);
                break;
            case 4:
                comp_data[ci].value = GETLONG(cp);
                break;
            default:
                printf ("\n Unknown length!");
                break;
        }
        if (NLRI_PREFIX_TYPE(comp_type)) {
            comp_data[ci].value <<= (32 - (8 * vlen));/* fix IP prefixes to MSB */
        }
        cp += vlen;
        dlen -= vlen;
        DBG_PRINT ("\n Decode: val= %d", comp_data[ci].value);
        ci ++; /* move to next val or [op,val] */
        if (eol) {
            d[i].num_elems = ci;
            /* cp comp arry to decode arr */
            d[i].d = malloc(sizeof(flo_data_t) * ci);
            memcpy(d[i].d, &comp_data,  sizeof(flo_data_t) * ci);
            i++;
        }
    } /* end while */
    DBG_PRINT ("\n Decode: found, %d components", i);
    *num_comp = i;
    return true;
}

int prefix_cmp(flo_data_t a, flo_data_t b, uint8_t comm)
{
    uint32_t x, y;
    x = GET_PREFIX(a, comm); 
    y = GET_PREFIX(b, comm);
    if (x == y)
        return 0;
    else if (x < y)
        return -1;
    else
        return 1;
}
/* compare 2 flows and return the one which takes precedence  */
int flospec_compare (flo_list_t a[], flo_list_t b[])
{
    uint32_t comm;
    int cmp, i;
    
    if(!a || !b) 
        return 0;
    for (i = NLRI_COMP_START ; i < MAX_NLRI_COMPONENTS; i++) {
        if ((a[i].n && a[i].d) && (!(b[i].n && b[i].d))) {
            DBG_PRINT ("\n COMP: first has %s which second doesnt", 
                    show_nlri_comp(i));
            return 1;// a;
        }    
        if ((b[i].n && b[i].d) && (!(a[i].n && a[i].d))) {
            DBG_PRINT ("\n COMP: second has %s which first doesnt", 
                    show_nlri_comp(i));
            return 2;//b;
        }
        if ((!(a[i].n && a[i].d)) && (!(b[i].n && b[i].d)))
         continue;
        if (NLRI_PREFIX_TYPE(i)) {
            comm = MIN(PREFIX_LEN(a[i].d[0]), PREFIX_LEN(b[i].d[0])); // we know there is only 1b in d
            cmp = prefix_cmp(a[i].d[0], b[i].d[0], comm);
            if (cmp == 0) {
                /* IPs same in the comm prefix len, choose the most specific */
                DBG_PRINT ("\n COMP: IP same in comm prefix len %d", comm);
                if (PREFIX_LEN(a[i].d[0]) > PREFIX_LEN (b[i].d[0])) {
                    DBG_PRINT ("\n COMP: first has prefix len(%d) > second(%d)",
                            PREFIX_LEN(a[i].d[0]), PREFIX_LEN (b[i].d[0]));
                    return 1;//a;
                } else {
                    DBG_PRINT ("\n COMP: second has prefix len(%d) > first(%d)",
                            PREFIX_LEN (b[i].d[0]), PREFIX_LEN(a[i].d[0]));
                    return 2;//b;
                }
            } else if (cmp > 0) {
                // a > b ; pick lowest
                DBG_PRINT ("\n COMP: pick lower prefix value - second");
                return 2;//b;
            } else {
                DBG_PRINT ("\n COMP: pick lower prefix value - first");
                return 1;//a;
            }
        } else {
            comm = MIN(a[i].n, b[i].n);
            // compare comm prefix
            cmp = memcmp(a[i].d, b[i].d, comm * sizeof(flo_data_t));
            if (cmp == 0) {
                // equal - pick longer
                DBG_PRINT ("\n COMP: pick longer value (num elements) ");
                return (a[i].n > b[i].n) ? 1 /* a */ : 2;//b;
            } else if (cmp > 0) {
                // a > b ; pick lowest
                DBG_PRINT("\n COMP: pick lower value (binary compare)- second");
                return 2;//b;
            } else {
                DBG_PRINT("\n COMP: pick lower (binary compare) value - first");
                return 1;//a;
            }
        }
    }
    return 0;
}

void flospec_show(flo_decode_t d[], int len)
{
    int i, j;
    for (i = 0; i < len; i++) {
        if (i) printf("\n AND");
        printf ("\n %s", show_nlri_comp(d[i].comp));
        for (j = 0; j < d[i].num_elems; j++) {
            if ((d[i].comp == NLRI_TCP_FLAGS) || (d[i].comp == NLRI_FRAGMENT)) {
                if (j) {
                 printf (" %s %s", d[i].d[j].and ? "AND" : "OR", show_nlri_comp(d[i].comp));
                }/* no bm func now */
                printf (" %s 0x%X ", show_num_op(d[i].d[j].op), d[i].d[j].value); 
             } else if (NLRI_PREFIX_TYPE(d[i].comp)) {
                printf (" = 0x%X/%d ", d[i].d[j].value, d[i].d[j].len);
             } else {
                if (j) {
                 printf (" %s %s", d[i].d[j].and ? "AND" : "OR", show_nlri_comp(d[i].comp));
                }
                printf (" %s 0x%X ", show_num_op(d[i].d[j].op), d[i].d[j].value);
             }
        }
    }
    printf("\n");
}


/* NLRI Encode decode demo - reading from string description */
/*
 * a sample nlri string - Note: do not use char*; tokeniser will modify
 * by placing '\0's 
 */
char sampl[] = "prefix.src = 10.0.1.0/24 and "
               "ip.proto = tcp|udp  and pak.len != 30"
               " and port >= 300 & <= 800";

#define MAX_HISTORY 5

typedef struct hist_ {
    char *flow_desc;
    flo_list_t *list;
} history_t;
history_t hist[MAX_HISTORY] = {{NULL, NULL}};

void do_help ()
{
    printf ("\n Usage: Type NLRI flow description and hit <enter> "
            "\n        The string will be tokenised and encoded, then"
            "\n        decoded; can verify if same.\n"
            "\n help or ?       - this help screen"
            "\n show            - stored history and index of each"
            "\n compare <a> <b> - compare flow description of indexes a and b"
            "\n quit or Ctrl-D  - end.\n");
}
void do_internal_cmd (char *line, bool *internal) 
{
    int i, a, b, ti, prec;

    *internal = false;
    if (!line || strlen(line) <= 1) {
        *internal = true; // hit return
    } else if (strncmp(line,"quit", 4) == 0) {
        exit(0); 
    } else if (strncmp(line, "show", 4) == 0) {
        for (i = 0;i <MAX_HISTORY ; i++)
            if (hist[i].flow_desc)
                printf ("\n [%d] : %s", i , hist[i].flow_desc);
        *internal = true;
    } else if ((strncmp(line, "help", 4)==0) || (strncmp(line, "?", 1)==0)) { 
        do_help();
        *internal = true;
    } else if (strncmp(line, "compare", 7) == 0) {
        if (sscanf(line, "compare %d %d", &a, &b) == 2) {
            if (IN_RANGE(a, 0,MAX_HISTORY) && IN_RANGE(b,0,MAX_HISTORY)) {
                if (hist[a].list && hist[b].list) {
                    prec = flospec_compare(hist[a].list, hist[b].list);
                    ti = prec == 1 ? a : b;
                    printf ("\n Precedence: %s", hist[ti].flow_desc);
                } else printf ("Empty index(es)!\n");
            } else printf ("\n Invalid index(es)!\n");
        } else printf ("\n Invalid compare! \n");
        *internal = true;
    } 
}

int main (int argc, char *argv[])
{
    char line[LINE_MAX];
    int hi = 0;
    flo_list_t *list;
    bool internal;

    printf("\nnlri> ");
    while (fgets(line, LINE_MAX, stdin) != NULL) {
        do_internal_cmd(line, &internal);
        if (!internal) {
            list = calloc (1, sizeof(flo_list_t) * MAX_NLRI_COMPONENTS);
            hi %= MAX_HISTORY;
            if (hist[hi].flow_desc) {
                free (hist[hi].flow_desc);
            }
            hist[hi].flow_desc = malloc (strlen(line) + 1);
            strcpy(hist[hi].flow_desc, line); /* cp b4 tokenisation */
            tok_nlri(line, list);
            if (hist[hi].list) {
                free (hist[hi].list);
            }
            hist[hi].list = list; 
            hi++;
        }
        printf("\nnlri> ");
    }
    return 0;
} 

#if 0 
/* NLRI Encode decode and show demo - Programmatic - with Macros */
int main (int argc, char *argv[])
{
    unsigned char buf[200] = {0}; /* a rough estimate */
    unsigned char *hdr, *cp = buf, *strt = buf;
    uint32_t len, dlen;
    flo_decode_t flo_decode[MAX_NLRI_COMPONENTS+1];
    int dec_len;

    hdr = cp;
    PUTSHORT(cp, 0); /* placeholder for len */
    cp += 2;

    len = flospec_encode (cp, NLRI_SOURCE_PREFIX, 1, 
            RULE_BEGIN
            PREFIX("10.0.1.0", 24),
            RULE_END);
    cp += len;

    len =  flospec_encode (cp, NLRI_IP_PROTO, 2, 
            RULE_BEGIN
            EQ(IP_PROTO_TCP),
            OR_EQ(IP_PROTO_UDP)
            RULE_END);
    cp += len;

    len = flospec_encode (cp, NLRI_TCP_FLAGS, 1,
            RULE_BEGIN
            MATCH(0x8),
            RULE_END);
    cp += len;

    len = flospec_encode (cp, NLRI_FRAGMENT, 2, 
            RULE_BEGIN
            MATCH(FRAG_BM_ISF),
            AND_MATCH(FRAG_BM_FF),
            RULE_END);
    cp += len;

    len = (cp - hdr) ; /* len of the whole buf */
    dlen = len - 2; /* exclude 2 b header */
    if (len > 0xF0) {
        PUTLONG(hdr, dlen | 0xF000);  /* exclude header len */
    } else {
        *(hdr + 1) = dlen; /* data len */
        strt = hdr + 1;
        len -= 1;/* 1 b at start wasted */
    }

    #if DEBUG
    printf ("\n Final buf len = %d, data/hdr len = %d (%X)\n",  len,dlen,dlen);
    for ( i = 0 ; i < len; i++) {
        printf ("%02X ", strt[i]);
    }
    printf ("\n");
    #endif 

    flospec_decode(strt, flo_decode, &dec_len);
    flospec_show(flo_decode, dec_len);
    return 0;
} 
#endif 
