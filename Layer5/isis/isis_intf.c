#include "../../tcp_public.h"
#include "isis_intf.h"

bool
isis_node_intf_is_enable(interface_t *intf) {
    if (NULL == ISIS_INTF_INFO(intf)) {
        printf("%s , ISIS protocol is disabled on interface\n", __FUNCTION__);
        return (false);
    } else {
        printf("%s , ISIS protocol is enabled on interface\n", __FUNCTION__);
        return (true);
    }
}