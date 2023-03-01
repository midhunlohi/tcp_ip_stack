#ifndef __ISIS_PKT_H__
#define __ISIS_PKT_H__
#include "isis_intf.h"

#define ISIS_TLV_MAC_ADDR   112

typedef uint16_t isis_pkt_type_t;
typedef uint8_t isis_pkt_hdr_flags_t;

typedef struct isis_pkt_hdr_{
    isis_pkt_type_t isis_pkt_type;
    uint32_t seq_no; /* meaningful only for LSPs */
    uint32_t rtr_id;
    isis_pkt_hdr_flags_t flags;
} isis_pkt_hdr_t;

#define ISIS_INTF_COST(intf_ptr) ((isis_intf_info_t *)intf_ptr->intf_nw_props.isis_intf_info)->cost
#define ISIS_INTF_HELLO_INTERVAL(intf_ptr) ((isis_intf_info_t *)intf_ptr->intf_nw_props.isis_intf_info)->hello_interval

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size);
void isis_pkt_receive(void *arg, size_t arg_size);
byte* isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size);
static uint32_t isis_print_hello_pkt(byte *buff, isis_pkt_hdr_t *hello_pkt_hdr, uint32_t pkt_size);

#endif