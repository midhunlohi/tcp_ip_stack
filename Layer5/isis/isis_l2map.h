#ifndef __ISIS_L2MAP__
#define __ISIS_L2MAP__
#include "../../tcp_public.h"
#include "isis_adjacency.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_trace.h"

bool
isis_is_l2_mapping_enabled(node_t*);

int
isis_config_l2_map(node_t*);

int
isis_un_config_l2_map(node_t*);

bool
isis_update_l2_mapping_on_adj_up(node_t*, isis_adjacency_t*);

bool
isis_update_l2_mapping_on_adj_down(node_t*, isis_adjacency_t*);

#endif