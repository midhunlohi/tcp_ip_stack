#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"

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
