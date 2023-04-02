#ifndef __ISIS_INTF__
#define __ISIS_INTF__

#include <stdlib.h>
#include "isis_adjacency.h"
typedef struct isis_intf_info_ {
    uint32_t                cost; // Cost associated with this interface
    uint32_t                hello_interval; // Time interval in sec.
    timer_event_handle      *hello_xmit_timer; // hello packet transmit timer.
    isis_adjacency_t        *adjacency; // Adjacency information
    bool                    hello_transmission; // Transmission status
    uint32_t                hello_pkt_rcv_cnt; // Hello packets received count
    uint32_t                hello_pkt_drp_cnt; // Invalid Hello packets received count
    uint32_t                hello_pkt_snt_cnt; // Hello packets sent count
}isis_intf_info_t;

#define ISIS_INTF_INFO(intf_ptr) \
    (isis_intf_info_t *)(intf_ptr->intf_nw_props.isis_intf_info)
#define ISIS_INTF_HELLO_XMIT_TIMER(intf_ptr) \
    (((isis_intf_info_t *)(intf_ptr)->intf_nw_props.isis_intf_info))->hello_xmit_timer

#define ISIS_INCREMENT_INTF_STAT(intf_ptr, field) \
                                ({ \
                                if (intf_ptr->intf_nw_props.isis_intf_info) { \
                                     ((isis_intf_info_t *)(intf_ptr->intf_nw_props.isis_intf_info))->field++; \
                                } \
                                }) \

#define ISIS_GET_INTF_STAT(intf_ptr, field) \
                                ((isis_intf_info_t *)(intf_ptr->intf_nw_props.isis_intf_info))->field \


bool
isis_node_intf_is_enable(interface_t *intf);

int
isis_enable_protocol_on_interface(interface_t *intf);

int
isis_disable_protocol_on_interface(interface_t *intf);

void
isis_start_sending_hellos(interface_t *intf);

void
isis_stop_sending_hellos(interface_t *intf);

bool
isis_interface_quality_to_send_hellos(interface_t *intf);

void 
isis_show_interface_protocol_state(interface_t *intf);

void
isis_print_intf_stats(interface_t *intf);

void
isis_clear_interface_protocol_adjacency(interface_t *intf);
#endif