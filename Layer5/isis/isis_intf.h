#ifndef __ISIS_INTF__
#define __ISIS_INTF__

#include <stdlib.h>

typedef struct isis_intf_info_ {


}isis_intf_info_t;

#define ISIS_INTF_INFO(intf_ptr) (isis_intf_info_t *)(intf_ptr->intf_nw_props.isis_intf_info)

bool
isis_node_intf_is_enable(interface_t *intf);

#endif