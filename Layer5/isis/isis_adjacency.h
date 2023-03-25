#ifndef __ISIS_ADJACENCY_H__
#define __ISIS_ADJACENCY_H__

typedef enum isis_adj_state_ {
    ISIS_ADJ_STATE_UNKNOWN,
    ISIS_ADJ_STATE_DOWN,
    ISIS_ADJ_STATE_INIT,
    ISIS_ADJ_STATE_UP
}isis_adj_state_t;

static inline char*
isis_adj_state_str(isis_adj_state_t adj_state) {
    switch(adj_state) {
        case ISIS_ADJ_STATE_DOWN:
            return "Down";
        case ISIS_ADJ_STATE_INIT:
            return "Init";
        case ISIS_ADJ_STATE_UP:
            return "Up";
        case ISIS_ADJ_STATE_UNKNOWN:
            return "Unknown";
        default:
            return NULL;
    }
    return NULL;
}

typedef struct isis_adjacency_{
    /* Back pointer to the interface*/
    interface_t *intf;

    /*Nbr Loopback Address*/
    uint32_t nbr_rtr_id;

    /*Nbr Device Name*/
    unsigned char nbr_name[NODE_NAME_SIZE];

    /*Nbr Intf IP*/
    uint32_t nbr_intf_ip;

    /*Nbr If Index*/
    uint32_t remote_if_index;

    /*Hold time in sec reported by nbr*/
    uint32_t hold_time;

    /*Nbr Link Cost Value*/
    uint32_t cost;

    /*Adj state*/
    isis_adj_state_t adj_state;

    /* Uptime*/
    time_t uptime;

    /*Expiry Timer*/
    timer_event_handle *expiry_timer;

    /*Delete timer*/
    timer_event_handle *delete_timer;

    /*MAC address of neighbor interface*/
    mac_add_t nbr_mac;
}isis_adjacency_t;

void 
isis_update_interface_adjacency_from_hello(interface_t *iif, byte *hello_tlv_buffer, size_t tlv_buff_size);

void
isis_show_adjacency( isis_adjacency_t *adjacency, uint8_t tab_spaces);

void
isis_update_adjacency_state(
    isis_adjacency_t* adj, 
    isis_adj_state_t new_adj_state);

void
isis_adjacency_set_uptime(isis_adjacency_t *adjacency);

void
isis_delete_adjacency(isis_adjacency_t *adjacency);

isis_adj_state_t 
isis_get_next_state(isis_adjacency_t *adj);

#endif