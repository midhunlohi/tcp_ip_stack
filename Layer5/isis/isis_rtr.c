#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_trace.h"

/*
* isis_check_delete_node_info()
* free the resources allocated for isis_node_info_t data structure
*/
void 
isis_check_delete_node_info(node_t *node){
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    /*Checks to be added here before free*/
    free(node->node_nw_prop.isis_node_info);
    node->node_nw_prop.isis_node_info = NULL;
}

bool
isis_is_protocol_enable_on_node(node_t *node) {
    if (NULL == ISIS_NODE_INFO(node)) {
        // printf("%s , ISIS protocol is disabled \n", __FUNCTION__);
        return (false);
    } else {
        // printf("%s , ISIS protocol is enabled \n", __FUNCTION__);
        return (true);
    }
}

/*
* isis_show_node_protocol_single_interface_stats()
* show interface stats
*/
void
isis_show_node_protocol_single_interface_stats(node_t *node, char *name) {
    interface_t *intf = NULL;    
    if (isis_is_protocol_enable_on_node(node) == true) {
        printf("%s: ÏSIS Protocol : %s\n\n", node->node_name, "Enabled");
        ITERATE_NODE_INTERFACES_BEGIN(node, intf){
            if (!strcmp(name, intf->if_name)) {
                printf("%s : %s\n", intf->if_name, isis_node_intf_is_enable(intf) == 1 ? "Enabled" : "Disabled");
                isis_show_interface_protocol_state(intf);
                return;
            }
        }ITERATE_NODE_INTERFACES_END(node, intf);
        printf("%s is invalid\n", name);
    } else {
        printf("%s:ÏSIS Protocol : %s\n\n", node->node_name, "Disabled");
    }
    return;
}

void
isis_show_node_protocol_interface_stats(node_t *node) {
    interface_t *intf = NULL;
    ITERATE_NODE_INTERFACES_BEGIN(node, intf){
        if (isis_node_intf_is_enable(intf)) {
            printf("%s : %s\n", intf->if_name, "Enabled");
            isis_print_intf_stats(intf);
        } else {
            printf("%s : %s\n", intf->if_name, "Disabled");
        }
    }ITERATE_NODE_INTERFACES_END(node, intf);
}

void
isis_show_node_protocol_state(node_t *node) {
    interface_t *intf = NULL;
    if (!isis_is_protocol_enable_on_node(node)) {
        printf("%s : ISIS Protocol : %s\n\n", node->node_name, "Disabled");
        return;
    }
    printf("%s : ISIS Protocol : %s\n\n", node->node_name, "Enabled");
    printf("Adjacency Up Count : %d\n\n", ISIS_GET_NODE_STATS(node, adj_up_count));
    ITERATE_NODE_INTERFACES_BEGIN(node, intf){        
        printf("%s : %s\n", intf->if_name, isis_node_intf_is_enable(intf) == 1 ? "Enabled" : "Disabled");
        isis_show_interface_protocol_state(intf);
    }ITERATE_NODE_INTERFACES_END(node, intf);
}

/*
* isis_clear_node_protocol_adjacency()
* Invoked when cmd 'clear node <node-name> protocol isis adjacencies' issued
* The function deletes all adjacencies on all interfaces of a node, no matter in which state Adjacency is.
* Note : Obviously Adjacencies shall reform again due to continuous reception of hello pkts.
*/
void
isis_clear_node_protocol_adjacency(node_t *node) {
    interface_t *intf = NULL;
    if (!isis_is_protocol_enable_on_node(node)) {
        printf("ÏSIS Protocol : Disabled\n\n");
        return;
    }
    printf("ÏSIS Protocol : Enabled\n\n");
    printf("Pre-clear adjacency up count : %d\n\n", ISIS_GET_NODE_STATS(node, adj_up_count));
    ITERATE_NODE_INTERFACES_BEGIN(node, intf){
        if (!isis_node_intf_is_enable(intf)) {
            printf("%s : %s\n", intf->if_name, "Disabled");
            continue;
        }
        printf("%s : %s\n", intf->if_name, "Enabled");
        isis_clear_interface_protocol_adjacency(intf);
    }ITERATE_NODE_INTERFACES_END(node, intf);
    printf("Post-clear adjacency up count : %d\n\n", ISIS_GET_NODE_STATS(node, adj_up_count));
}

/*
* Register the ISIS packet with TCP/IP stack.
* When TCP/IP stack gets a ISIS packet, it invokes
* the API pointed by func pointer isis_print_pkt
*/
void
isis_one_time_registation(void) {
    /*Regiter for interface updates*/
    nfc_intf_register_for_events(isis_interface_updates);
    nfc_register_for_pkt_tracing(ISIS_ETH_PKT_TYPE, isis_print_pkt);
}