#ifndef __ISIS_RTR__
#define __ISIS_RTR__

#include <stdlib.h>

typedef struct isis_node_info_ {
    uint32_t adj_up_count;
}isis_node_info_t;

typedef struct isis_timer_data_ {
    node_t      *node;
    interface_t *intf;
    void        *data;
    size_t      data_size;
} isis_timer_data_t;

#define ISIS_NODE_INFO(node_ptr) (isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info)
#define ISIS_INCREMENT_NODE_STATS(node_ptr, field) \
                                ((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))->field++
#define ISIS_DECREMENT_NODE_STATS(node_ptr, field) \
                                ((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))->field--
#define ISIS_GET_NODE_STATS(node_ptr, field)                                                \
        ({                                                                                  \
            uint32_t val = 0;                                                               \
            if (node_ptr->node_nw_prop.isis_node_info) {                                    \
                val = ((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))->field; \
            }                                                                               \
            val;                                                                            \
        })
                               
bool
isis_is_protocol_enable_on_node(node_t *node);

void
isis_show_node_protocol_state(node_t *node);

void
isis_show_node_protocol_interface_stats(node_t *node);

void
isis_clear_node_protocol_adjacency(node_t *node);
#endif