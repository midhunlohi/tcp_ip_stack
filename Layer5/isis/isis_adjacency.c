#include "../../tcp_public.h"
#include "isis_adjacency.h"
#include "isis_intf.h"
#include "isis_trace.h"
#include "isis_const.h"
#include "isis_rtr.h"

static void
isis_adjacency_start_delete_timer(isis_adjacency_t *adj);

void isis_update_interface_adjacency_from_hello(interface_t *iif, 
                                                byte *hello_tlv_buffer, 
                                                size_t tlv_buff_size) {
    bool new_adj = false;
    bool nbr_attr_changed = false;
    uint8_t type;
    uint8_t len; 
    char *val;
    isis_adjacency_t *adj = NULL;

    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(iif);
    if (!isis_intf_info) {
        LOG(LOG_ERROR, ISIS_PKT, iif->att_node, iif, "%s: Invalid isis interface info pointer", 
                                                    __FUNCTION__);
        return;
    }
    if (!isis_intf_info->adjacency) {
        /*No Existing Adjacency*/
        isis_adjacency_t *adj = NULL;
        adj = calloc(1, sizeof(isis_adjacency_t));
        if (!adj) {
            LOG(LOG_ERROR, ISIS_PKT, iif->att_node, iif, "%s: Failed to calloc adj pointer", 
                                                            __FUNCTION__);
            return;
        }
        memset(adj, 0x0, sizeof(adj));
        adj->intf = iif;
        new_adj = true;
        adj->adj_state = ISIS_ADJ_STATE_DOWN;
        isis_intf_info->adjacency = adj;
        isis_adjacency_start_delete_timer(isis_intf_info->adjacency);        
    }

    ITERATE_TLV_BEGIN(hello_tlv_buffer, type, len, val, tlv_buff_size){
        switch(type){
            case ISIS_TLV_HOSTNAME:
                if (memcmp(isis_intf_info->adjacency->nbr_name, val, len)) {
                    nbr_attr_changed = true;
                    memcpy(isis_intf_info->adjacency->nbr_name, val, len);
                }
                break;
            case ISIS_TLV_RTR_ID:
                if (isis_intf_info->adjacency->nbr_rtr_id != *(uint32_t*)val) {
                    nbr_attr_changed = true;
                    isis_intf_info->adjacency->nbr_rtr_id = *(uint32_t*)val;
                }
                break;
            case ISIS_TLV_IF_IP:
                if (isis_intf_info->adjacency->nbr_intf_ip != *(uint32_t*)val) {
                    nbr_attr_changed = true;
                    isis_intf_info->adjacency->nbr_intf_ip = *(uint32_t*)val;
                }
                break;
            case ISIS_TLV_IF_INDEX:
                if (isis_intf_info->adjacency->remote_if_index != *(uint32_t*)val) {
                    nbr_attr_changed = true;
                    isis_intf_info->adjacency->remote_if_index = *(uint32_t*)val;
                }
                break;
            case ISIS_TLV_HOLD_TIME:
                if (isis_intf_info->adjacency->hold_time != *(uint32_t*)val) {
                    nbr_attr_changed = true;
                    isis_intf_info->adjacency->hold_time = *(uint32_t*)val;
                }
                break;
            case ISIS_TLV_METRIC_VAL:
                if (isis_intf_info->adjacency->cost != *(uint32_t*)val) {
                    nbr_attr_changed = true;
                    isis_intf_info->adjacency->cost = *(uint32_t*)val;
                }
                break;
            default:
                break;
        }
    }ITERATE_TLV_END(hello_tlv_buffer, type, len, val, tlv_buff_size)   
    /*A good hello pkt arrived at interface and adjacency already existing*/
    if (!new_adj) {
        isis_adj_state_t next_state = isis_get_next_state(isis_intf_info->adjacency);
        isis_update_adjacency_state(isis_intf_info->adjacency, next_state);
    }
}

void
isis_show_adjacency( isis_adjacency_t *adjacency, uint8_t tab_spaces) {
    if (adjacency) {
        uint32_t* if_ip_addr_int = &adjacency->nbr_rtr_id;
        char* if_ip_addr_str = tcp_ip_covert_ip_n_to_p(*if_ip_addr_int, 0);
        PRINT_TABS(tab_spaces);
        printf("Nbr : %s(%s)\n", adjacency->nbr_name, if_ip_addr_str);
        if_ip_addr_int = &adjacency->nbr_intf_ip;
        if_ip_addr_str = tcp_ip_covert_ip_n_to_p(*if_ip_addr_int, 0);
        PRINT_TABS(tab_spaces);        
        printf("Nbr intf ip: %s ifIndex : %d\n", if_ip_addr_str, adjacency->remote_if_index);
        PRINT_TABS(tab_spaces);        
        printf("State : %s HT: %d sec Cost : %d\n", isis_adj_state_str(adjacency->adj_state),
                                                adjacency->hold_time,
                                                adjacency->cost);
        PRINT_TABS(tab_spaces);
        if (adjacency->expiry_timer) {
            printf("Expiry Timer Remaining : %u msec\n", 
                    wt_get_remaining_time(adjacency->expiry_timer));
        } else {
            printf("Expiry Timer : NIL\n");
        }
        PRINT_TABS(tab_spaces);
        if (adjacency->delete_timer) {
            printf("Delete Timer Remaining : %u msec\n", 
                    wt_get_remaining_time(adjacency->delete_timer));
        } else {
            printf("Delete Timer : NIL\n");
        }
        PRINT_TABS(tab_spaces);
        if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {
            printf("Up Time : %s\n", 
                hrs_min_sec_format((unsigned int)difftime(time(NULL), adjacency->uptime)));
        }
    } else {
        PRINT_TABS(tab_spaces);        
        printf("Nbr : NIL\n");
    }
}

/* Timer APIs */
/*Delete Timer APIs*/
/*
* isis_adjacecncy_delete_timer_expire_cb() invokes at the time of expiration
* of delete timer.
*/
static void
isis_adjacecncy_delete_timer_expire_cb(void *arg, uint32_t arg_size) {
    if (!arg) {
        return;
    }
    isis_adjacency_t* adj = (isis_adjacency_t*)arg;
    interface_t* intf = adj->intf;
    isis_intf_info_t* intf_info = ISIS_INTF_INFO(intf);
    intf_info->adjacency = NULL;
    timer_de_register_app_event(adj->delete_timer);
    adj->delete_timer = NULL;
    assert(!adj->expiry_timer);
    free(adj);
}

static void
isis_adjacency_start_delete_timer(isis_adjacency_t *adj) {
    if (adj->delete_timer) {
        return;
    }
    adj->delete_timer = timer_register_app_event(
        node_get_timer_instance(adj->intf->att_node),
        isis_adjacecncy_delete_timer_expire_cb,
        (void*)adj,
        sizeof(isis_adjacency_t),
        ISIS_ADJ_DEFAULT_DELETE_TIME,
        0
    );
}

static void
isis_adjacency_stop_delete_timer(isis_adjacency_t *adj) {
    if (!adj->delete_timer) {
        return;
    }
    timer_de_register_app_event(adj->delete_timer);
    adj->delete_timer = NULL;
}

/*Expiry Timer APIs*/
/*
* Bringdown the adjacency state from INIT/UP to DOWN state.
*/
static void
isis_adjacecncy_down_timer_expire_cb(void *arg, uint32_t arg_size) {
    if (!arg) {
        return;
    }
    isis_adjacency_t* adj = (isis_adjacency_t*)arg;
    timer_de_register_app_event(adj->expiry_timer);
    adj->expiry_timer = NULL;
    isis_update_adjacency_state(adj, ISIS_ADJ_STATE_DOWN);
}

static void
isis_adjacency_start_expiry_timer(isis_adjacency_t *adj) {
    if (adj->expiry_timer) {
        return;
    }
    adj->expiry_timer = timer_register_app_event(
        node_get_timer_instance(adj->intf->att_node),
        isis_adjacecncy_down_timer_expire_cb,
        (void*)adj, sizeof(isis_adjacency_t),
        adj->hold_time * 1000,
        0);
}

static void
isis_adjacency_stop_expiry_timer(
    isis_adjacency_t *adj) {
        if (!adj->expiry_timer) {
            return;
        }
    timer_de_register_app_event(adj->expiry_timer);
    adj->expiry_timer = NULL;
}

static void 
isis_adjacency_refresh_expiry_timer(
    isis_adjacency_t *adj) {
    assert(adj->expiry_timer);
    timer_reschedule(adj->expiry_timer,
    adj->hold_time * 1000);
}

void
isis_adjacency_set_uptime(isis_adjacency_t *adj) {
    assert(adj->adj_state == ISIS_ADJ_STATE_UP);
    adj->uptime = time(NULL);
}

void
isis_delete_adjacency(isis_adjacency_t *adj) {
    if (!adj) {
        return;
    }
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(adj->intf);
    assert(intf_info);
    ISIS_DECREMENT_NODE_STATS(adj->intf->att_node, adj_up_count);
    intf_info->adjacency = NULL;
    isis_adjacency_stop_delete_timer(adj);
    isis_adjacency_stop_expiry_timer(adj);
    free(adj);
    adj = NULL;    
}

isis_adj_state_t 
isis_get_next_state(isis_adjacency_t *adj) {
    isis_adj_state_t next_state = ISIS_ADJ_STATE_UNKNOWN;
    switch(adj->adj_state) {
        case ISIS_ADJ_STATE_DOWN:
            next_state = ISIS_ADJ_STATE_INIT;
            break;
        case ISIS_ADJ_STATE_INIT:
            next_state = ISIS_ADJ_STATE_UP;
            break;
        case ISIS_ADJ_STATE_UP:
            next_state = ISIS_ADJ_STATE_UP;
            break;
        default:
            break;            
    }
    return next_state;
}

void
isis_update_adjacency_state(
    isis_adjacency_t* adj, 
    isis_adj_state_t new_state) {
    if (!adj) {
        return;
    }
    isis_adj_state_t cur_state = adj->adj_state;
    switch(cur_state) {
        case ISIS_ADJ_STATE_DOWN: 
            {
                switch(new_state) {                    
                    case ISIS_ADJ_STATE_INIT:
                        {
                            adj->adj_state = new_state;
                            isis_adjacency_stop_delete_timer(adj);
                            isis_adjacency_start_expiry_timer(adj);
                        }
                        break;
                    case ISIS_ADJ_STATE_UP:
                        {
                            adj->adj_state = ISIS_ADJ_STATE_UP;
                            isis_adjacency_refresh_expiry_timer(adj);
                            adj->uptime = time(NULL);
                        }
                        break;     
                    default:
                        break;               
                }
            }
            break;
        case ISIS_ADJ_STATE_INIT: 
            {
                switch(new_state) {
                    case ISIS_ADJ_STATE_DOWN:
                        {
                            adj->adj_state = new_state;
                            isis_adjacency_stop_expiry_timer(adj);
                            isis_adjacency_start_delete_timer(adj);
                        }
                        break;
                    case ISIS_ADJ_STATE_UP:
                        {
                            adj->adj_state = new_state;
                            isis_adjacency_refresh_expiry_timer(adj);
                            isis_adjacency_set_uptime(adj);
                            ISIS_INCREMENT_NODE_STATS(adj->intf->att_node, adj_up_count);
                        }
                        break;                    
                    default:
                        break;
                }
            }
            break;
        case ISIS_ADJ_STATE_UP: 
            {
                switch(new_state) {
                    case ISIS_ADJ_STATE_DOWN:
                        {
                            adj->adj_state = new_state;
                            isis_adjacency_stop_expiry_timer(adj);
                            isis_adjacency_start_delete_timer(adj);
                        }
                        break;
                    case ISIS_ADJ_STATE_UP:
                        {
                            isis_adjacency_refresh_expiry_timer(adj);                            
                        }
                        break;
                    default:
                        break;
                }
            }
            break;
        default:
            break;
    }
}