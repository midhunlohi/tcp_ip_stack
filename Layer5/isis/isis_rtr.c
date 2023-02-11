#include "../../tcp_public.h"
#include "isis_rtr.h"

bool
isis_is_protocol_enable_on_node(node_t *node) {
    if (NULL == ISIS_NODE_INFO(node)) {
        printf("%s , ISIS protocol is disabled \n", __FUNCTION__);
        return (false);
    } else {
        printf("%s , ISIS protocol is enabled \n", __FUNCTION__);
        return (true);
    }
}

void
isis_show_node_protocol_state(node_t *node) {
    printf("ÏSIS Protocol : %s\n", (isis_is_protocol_enable_on_node(node) == true)? "Ënable" : "Disable");
}
