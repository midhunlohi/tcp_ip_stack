#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_const.h"

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

void
isis_show_node_protocol_state(node_t *node) {
    interface_t *intf = NULL;
    printf("ÏSIS Protocol : %s\n", (isis_is_protocol_enable_on_node(node) == true)? "Ënabled" : "Disabled");
    ITERATE_NODE_INTERFACES_BEGIN(node, intf){                       
        printf("%s : %s\n", intf->if_name, isis_node_intf_is_enable(intf) == 1 ? "Enabled" : "Disabled");            
    }ITERATE_NODE_INTERFACES_END(node, intf);
}

/*
* Register the ISIS packet with TCP/IP stack.
* When TCP/IP stack gets a ISIS packet, it invokes
* the API pointed by func pointer isis_print_pkt
*/
void
isis_one_time_registation(void) {
    nfc_register_for_pkt_tracing(ISIS_ETH_PKT_TYPE, isis_print_pkt);
}