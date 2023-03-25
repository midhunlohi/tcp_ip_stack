#include "../../tcp_public.h"
#include "isis_adjacency.h"
#include "isis_intf.h"
#include "isis_trace.h"
#include "isis_const.h"

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
    isis_intf_info->adjacency->adj_state = ISIS_ADJ_STATE_UP;
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
    } else {
        PRINT_TABS(tab_spaces);        
        printf("Nbr : NILL\n");
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