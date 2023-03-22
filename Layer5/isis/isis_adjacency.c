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
                if (memcmp(adj->nbr_name, val, len)) {
                    nbr_attr_changed = true;
                    memcpy(adj->nbr_name, val, len);
                }
                break;
            case ISIS_TLV_RTR_ID:
                if (adj->nbr_rtr_id != (int)*val) {
                    nbr_attr_changed = true;
                    adj->nbr_rtr_id = (int)*val;
                }
                break;
            case ISIS_TLV_IF_IP:
                if (adj->nbr_intf_ip != (int)*val) {
                    nbr_attr_changed = true;
                    adj->nbr_intf_ip = (int)*val;
                }
                break;
            case ISIS_TLV_IF_INDEX:
                if (adj->remote_if_index != (int)*val) {
                    nbr_attr_changed = true;
                    adj->remote_if_index = (int)*val;
                }
                break;
            case ISIS_TLV_HOLD_TIME:
                if (adj->hold_time != (int)*val) {
                    nbr_attr_changed = true;
                    adj->hold_time = (int)*val;
                }
                break;
            case ISIS_TLV_METRIC_VAL:
                if (adj->cost != (int)*val) {
                    nbr_attr_changed = true;
                    adj->cost = (int)*val;
                }
                break;
            default:
                break;
        }
    }ITERATE_TLV_END(hello_tlv_buffer, type, len, val, tlv_buff_size)
}