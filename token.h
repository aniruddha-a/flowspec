#if !defined(__TOKEN_H)
#define __TOKEN_H

#if 0
/* not being used right now, maybe needed later - for nlri string defn */
char * nlri_type_tok [MAX_NLRI_COMPONENTS] = {
    [NLRI_DEST_PREFIX] = "prefix.dest",
    [NLRI_SOURCE_PREFIX] = "prefix.src",
    [NLRI_IP_PROTO] = "ip.proto",
    [NLRI_PORT] = "port",
    [NLRI_DEST_PORT] = "port.dest",
    [NLRI_SOURCE_PORT] = "port.src",
    [NLRI_ICMP_TYPE] = "icmp.type",
    [NLRI_ICMP_CODE] = "icmp.code",
    [NLRI_TCP_FLAGS] = "tcp.flags",
    [NLRI_PAK_LEN] = "pak.len",
    [NLRI_DSCP] = "dscp",
    [NLRI_FRAGMENT] = "fragment",
};
#endif 
void  tok_nlri(char *s, flo_list_t list[]);
void  tok_comp(char *s, flo_list_t list[]);
uint32_t get_val(char *s);
op_t tok_op(char *s,char **l,char **r);
flo_comp_t get_comp_type(char *s);
#endif 
