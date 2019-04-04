/*
 *  NLRI description from string using the nlri_type_tok values 
 */
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "encode.h"
#include "flospec.h"
#include "bitset.h"
#include "utils.h"
#include "token.h"
#include "iana_ip_proto.h"
#include "debug.h"

/* Get NLRI component type from the string token  */
flo_comp_t get_comp_type (char *s) 
{
    char *p= s;
    while( *p ==' ' ||*p == '\t') p++;

    if (0 == strncmp(p, "ip", 2)) return NLRI_IP_PROTO;
    else if (0 == strncmp(p, "icmp", 4)) {
        if (0 == strncmp(p+5, "type", 4)) return NLRI_ICMP_TYPE;
        else if (0 == strncmp(p+5, "code", 4)) return NLRI_ICMP_CODE;
        else printf("\n Err: Unknown sub-comp [%s]", p+5);
    } else if (0 == strncmp(p, "port",4)) {
        if (*(p+4) == '.') {
            if (0 == strncmp(p+5, "src", 3)) return NLRI_SOURCE_PORT;
            else if (0 == strncmp(p+5, "dest", 4)) return NLRI_DEST_PORT;
            else printf("\n Err: Unknown sub-comp [%s]", p+5);
        } else return NLRI_PORT;
    } else if (0 == strncmp(p, "pref", 4)) {
        if (0 == strncmp(p+7, "src", 3)) return NLRI_SOURCE_PREFIX;
        else if( 0 == strncmp(p+7, "dest", 4)) return NLRI_DEST_PREFIX;
        else printf("\n Err: Unknown sub-comp [%s]", p+7);
    } else if(0 == strncmp(p, "tcp", 3)) return NLRI_TCP_FLAGS;
    else if (0 == strncmp(p, "pak",3)) return NLRI_PAK_LEN;
    else if (0 == strncmp(p, "dscp",4)) return NLRI_DSCP;
    else if (0 == strncmp(p, "frag",4)) return NLRI_FRAGMENT;
    else printf ("\n Err: Unknown NLRI component code [%s]\n",p);
    return MAX_NLRI_COMPONENTS;
}

/* similarto strtok, just that '\0' is not placed */
char* find_first(char *s, char *f)
{
    int i, n = strlen(f);
    char *p;

    p = s;
    while (*p) {
        for (i = 0; i < n; i++)
            if(*p == f[i])
                return p;
        p++;
    }
    return NULL;
}

/* tokenise the operator and operands  */
op_t tok_op (char *s, char **l, char **r) 
{
    char *a;
    op_t op;
    
    a = find_first(s, "<>!=");
    if (a) {
        switch (*a) {
            case '<':
                op = *(a+1) == '=' ?  OP_LE : OP_LT;
                break;
            case '>':
                op = *(a+1) == '=' ?  OP_GE : OP_GT;
                break;
            case '!':
                op = *(a+1) == '=' ?  OP_NE : OP_NE;// may give err here 
                break;
            case '=':
                op = OP_EQ;
                break;
        }
        *a = 0;
        *l = s;
        *r = a+2; /* skip op */
        return op;
    }
    return NO_OP;
}

/* assign a value for the keywords used in the nlri string */
uint32_t get_val (char *s) 
{
    // TODO - only commonly used protos added here,to add full set,
    // have to store in tree/trie
    if (!s)
        return 0;
    if (0 == strncmp(s,"tcp", 3)) return IP_PROTO_TCP;
    else if (0 == strncmp(s,"udp", 3)) return IP_PROTO_UDP;
    else if (0 == strncmp(s,"icmp", 4)) return IP_PROTO_ICMP;
    else if (0 == strncmp(s,"igmp", 4)) return IP_PROTO_IGMP;
    else if (0 == strncmp(s,"rsvp", 4)) return IP_PROTO_RSVP;
    else return strtol(s, NULL, 0);
}

/* per nlri component tokeniser, adds the encode data in a list in the comp type slot */
void tok_comp (char *s, flo_list_t list[])
{
    char  *a, *b, *c, *d, *p, *q;
    op_t op, prev_op;
    uint32_t len = 0;
    int i = 0;
    flo_data_t  data[10]; 
    flo_comp_t type;
    bool subval_eval = false;

    op = tok_op(s, &a, &b);
    DBG_PRINT ("\n TOK: main-op: [%s] [%s] [%s]", a, show_num_op(op), b);
    DBG_PRINT ("\n TOK: comp type= %d" , get_comp_type(a));
    type = get_comp_type(a);
    if (type == MAX_NLRI_COMPONENTS)
        return;
    if (NLRI_PREFIX_TYPE(type)) {
        p = strtok(b, "/");
        q = strtok(NULL, "/");
        len = get_val(q);
        //data[0] = (flo_data_t) PREFIX(p, get_val(q));
        data[0] = (flo_data_t) PREFIX(p, !len ? 32 : len); // IPv4 only
        list[type].n = 1;
        list[type].d = malloc(sizeof(flo_data_t));
        if (!list[type].d) {
            printf ("\n Memory allocation failure for list\n");
            exit (1);
        }
        memcpy(list[type].d, &data, sizeof(flo_data_t));
        return ;
    }

    data[i].op = op; 
    data[i].and = false;
    prev_op = op;
    q = strtok (b, "&"); 
    while ((p = strtok (NULL, "&"))) {
        subval_eval = true;
        DBG_PRINT ("\n TOK: set AND");
        /* and bit set  */
        op = tok_op(p+1, &c, &d);
        if (op == NO_OP) {
            /* no op here (use prev op) */
            DBG_PRINT ("\n\t TOK: sub-NO-New-OP: [%s] [%s] [%s]", q, 
                    show_num_op(prev_op), p);
            data[i].value = get_val(q);
            i++;
            data[i].op = prev_op;
            data[i].and = true;
            data[i].value = get_val(p);
        } else {
            /* op is in op */
            DBG_PRINT ("\n\t TOK: sub-op: [%s] [%s] [%s]", q, 
                    show_num_op(op), d);
            data[i].value = get_val(q);
            i++;
            data[i].op = op;
            data[i].and = true;
            data[i].value = get_val(d);
            b = d; // put remaining in b for '|' tokeniser to use
        }
    }
    prev_op = op;
    q = strtok (b, "|"); 
    while ((p = strtok (NULL, "|"))) {
        subval_eval = true;
        DBG_PRINT ("\n TOK: set OR");
        /* and bit unset  */
        op = tok_op(p+1, &c, &d);
        if (op == NO_OP) {
            /* no op here (use prev op) */
            DBG_PRINT ("\n\t TOK: sub-NO-New-OP: [%s] [%s] [%s]", q,
                    show_num_op(prev_op), p);
            data[i].value = get_val(q);
            i++;
            data[i].op = prev_op;
            data[i].and = false;
            data[i].value = get_val(p);
        } else {
            /* op is in op */
            DBG_PRINT ("\n\t TOK: sub-op: [%s] [%s] [%s]", q,  
                    show_num_op(op), d);
            data[i].value = get_val(q);
            i++;
            data[i].op = op;
            data[i].and = false;
            data[i].value = get_val(d);
        }
    }
    if (!subval_eval) {
        data[i].value = get_val(b);
    }
    i++;

    list[type].n = i;
    list[type].d = malloc(sizeof(flo_data_t)* i);
    if (!list[type].d) {
        printf ("\n Memory allocation failure for list\n");
        exit (1);
    }
    memcpy(list[type].d, &data, sizeof(flo_data_t) * i);
}

/* top level tokeniser   */
void tok_nlri (char *s, flo_list_t list[])
{
    char *n, *p = s;
    char *tmp;
    unsigned char *bufp;
    unsigned char buf[200] = {0}; /* sufficient ? */
    unsigned char *hdr, *strt;
    uint32_t len, dlen;
    int i;
//    flo_list_t list[MAX_NLRI_COMPONENTS] = { {0, NULL} };
    /* TEST */
    flo_decode_t flo_decode[MAX_NLRI_COMPONENTS+1];
    int dec_len;

    /* as per the RFC,all components encoded are considered ANDed */
    while((n = strstr(p, "and"))) {
        tmp = malloc(n - p + 1);
        strncpy(tmp, p, n-p);
        tmp[n - p] = '\0';
        tok_comp(tmp, list);
        p = n+3;
        free (tmp);
    }
    tok_comp(p, list); /* remaining part in str */

    /*
     * Now the list must be populated with the components tokenised, add them to
     * the buffer sorted
     */

    hdr = bufp = strt = buf;
    PUTSHORT(bufp, 0);
    bufp += 2;
    for (i = NLRI_COMP_START ; i < MAX_NLRI_COMPONENTS; i++) {
        if (list[i].n && list[i].d) {
            DBG_PRINT ("\n Tok: adding %s with %d comps", 
                    show_nlri_comp(i), list[i].n );
            len = flospec_encode (bufp, i, list[i].n, list[i].d);
            bufp += len;
           // free(list[i].d);
        }
    }

    len = (bufp - hdr);
    dlen = len - 2; /* exclude 2 b header */
    if (len > 0xF0) {
        PUTLONG(hdr, (dlen | 0xF000));  /* exclude header len */
    } else {
        *(hdr + 1) = dlen; /* data len */
        strt = hdr + 1;
        len -= 1;/* 1 b at start wasted */
    }
    printf ("\n Final buf len = %d, data/hdr len = %d (%X)\n ",  len,dlen,dlen);
    for (i = 0 ; i < len; i++) {
        printf ("%02X ", strt[i]);
    }
    printf ("\n");
    /* TEST  */
    flospec_decode(strt, flo_decode, &dec_len);
    flospec_show(flo_decode, dec_len);
}

