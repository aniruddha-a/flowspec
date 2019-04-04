#include <stdbool.h>
#include <stdint.h>
#include "encode.h"
#include "flospec.h"

const char* show_num_op (op_t op) {
    switch (op) {
        case OP_LT : return "<";
        case OP_GT : return ">";
        case OP_EQ : return "=";
        case OP_LE : return "<=";
        case OP_GE : return ">=";
        case OP_NE : return "!="; // <>
        default: return "unknown";
    }
}

const char* show_nlri_comp (flo_comp_t c)
{
    switch(c) {
        case NLRI_DEST_PREFIX : return "DEST-PREFIX ";
        case NLRI_SOURCE_PREFIX: return "SOURCE-PREFIX";
        case NLRI_IP_PROTO: return "IP-PROTO";
        case NLRI_PORT: return "PORT";
        case NLRI_DEST_PORT: return "DEST-PORT";
        case NLRI_SOURCE_PORT: return "SOURCE-PORT";
        case NLRI_ICMP_TYPE: return "ICMP-TYPE";
        case NLRI_ICMP_CODE: return "ICMP-CODE";
        case NLRI_TCP_FLAGS: return "TCP-FLAGS";
        case NLRI_PAK_LEN: return "PAK-LEN";
        case NLRI_DSCP: return "DSCP";
        case NLRI_FRAGMENT: return "FRAGMENT";
        default: return "unknown";
    }
}
