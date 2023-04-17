#include "isis_l2map.h"

/*
* isis_is_l2_mapping_enabled()
* Check whether l2mapping is enabled on node.
*/
bool
isis_is_l2_mapping_enabled(node_t* node) {
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if (!isis_node_info) {
        return false;
    }
    if(!isis_node_info->l2_mapping) {
        return false;
    }
    return true;
}

/*
* isis_config_l2_map()
* Config l2 mapping
* This Function getting called when ISIS protocol enabled on node.
* Re-add all L2 mapping on the node.
* Or when adjacency on interface goes UP.
*/
int
isis_config_l2_map(node_t* node) {
    /*Iterate via all the interface on the node and iterate via all the adjacencies on the interface.
    * and if the state of the adjacencies are UP, then add them to the ARP table.
    */
    interface_t *intf = NULL;
    if (!isis_is_protocol_enable_on_node(node)) {
        return -1;
    }

    ITERATE_NODE_INTERFACES_BEGIN(node, intf){  
        if (isis_node_intf_is_enable(intf)) {      
            isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);
            if (intf_info_ptr && intf_info_ptr->adjacency) {
                if (intf_info_ptr->adjacency->adj_state == ISIS_ADJ_STATE_UP) {
                    isis_update_l2_mapping_on_adj_up(node, intf_info_ptr->adjacency);
                }
            }
        }
    }ITERATE_NODE_INTERFACES_END(node, intf);
    return 0;
}

/*
* Unconfig L2 mapping.
* This Function getting called when ISIS protocol disabled on node.
* Deletes all L2 mapping on the node.
* or when adjacency on interface goes DOWN or deleted.
*/
int
isis_un_config_l2_map(node_t* node) {
    /*Iterate via all the interface on the node and iterate via all the adjacencies on the interface.
    * and if the state of the adjacencies are DOWN, then del them from the ARP table.
    */
    /*Iterate via all the interface on the node and iterate via all the adjacencies on the interface.
    * and if the state of the adjacencies are UP, then add them to the ARP table.
    */
    interface_t *intf = NULL;
    if (!isis_is_protocol_enable_on_node(node) || !node) {
        return -1;
    }

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
        if (isis_node_intf_is_enable(intf)) {
            isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);
            if (intf_info_ptr) {
                isis_update_l2_mapping_on_adj_down(node, intf_info_ptr->adjacency);
            }
        }
    }ITERATE_NODE_INTERFACES_END(node, intf);
    return 0;
}

/*
* Update ARP table when adjacnecy is up
* 1. Add when adjacency learned on local interface
* 2. Update when Nbr interface IP gets updated
*/
bool
isis_update_l2_mapping_on_adj_up(node_t* node, isis_adjacency_t* adj) {
    if (!adj || !node) {
        return true;
    }
    if (isis_is_l2_mapping_enabled(node)) {
        uint32_t* if_ip_addr_int = &adj->nbr_intf_ip;
        char* if_ip_addr_str = tcp_ip_covert_ip_n_to_p(*if_ip_addr_int, 0);
        arp_entry_add(node, if_ip_addr_str, adj->nbr_mac, adj->intf, PROTO_ISIS);
    }
}

/*
* Update ARP table when adjacnecy is down
* 1. Local interface shuts DOWN.
* 2. Remote peer interface is down ( Adj timeout )
*/
bool
isis_update_l2_mapping_on_adj_down(node_t *node, isis_adjacency_t* adj) {
    if (!adj || !node) {
        return true;
    }
    if (isis_is_l2_mapping_enabled(node)) {
        uint32_t* if_ip_addr_int = &adj->nbr_intf_ip;
        char* if_ip_addr_str = tcp_ip_covert_ip_n_to_p(*if_ip_addr_int, 0);
        arp_entry_delete(node, if_ip_addr_str, PROTO_ISIS);
    }
    return true;
}