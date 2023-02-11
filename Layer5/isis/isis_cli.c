/**standard header files*/

#include <assert.h>

/*Project specific header files*/

#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"

static void
isis_init(node_t *node) {
    printf("%s Invoked \n", __FUNCTION__);
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if (isis_node_info) {
        printf("%s, ISIS Protocol is already ENABLED on this node\n", __FUNCTION__);
        return;
    }
    isis_node_info = (isis_node_info_t *)malloc(sizeof(isis_node_info_t));
    node->node_nw_prop.isis_node_info = isis_node_info;
    printf("%s, ISIS protocol ENABLED on this node\n", __FUNCTION__);
    return;
}

static void
isis_de_init(node_t *node) {
    printf("%s Invoked \n", __FUNCTION__);
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if (NULL == isis_node_info) {
        printf("%s, ISIS protocol is already DISABLED on this node.\n", __FUNCTION__);
        return;
    }

    free(isis_node_info);
    node->node_nw_prop.isis_node_info = NULL;
    printf("%s, ISIS protocol is DISABLED this node.\n", __FUNCTION__);
    return;
}

/*
* conf node <node-name> protocol isis
* isis_config_handler() - The function to handle the confiuguration of ISIS protocol.
* param - parameters passed when we register with libcli.
* tlv_buff - TLV buffer associated with the input config command.
* op_mode - Whether the command is for disabling or enabling the configuration.
*/

static int 
isis_config_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable)
{
    int cmdcode         = -1;
    tlv_struct_t *tlv   = NULL;
    char *node_name     = NULL;
    node_t *node        = NULL;
    
    cmdcode = EXTRACT_CMD_CODE(tlv_buf);
    
    TLV_LOOP_BEGIN(tlv_buf, tlv) {
        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
            node_name = tlv->value;
        } else {
            assert(0);
        }
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {
        case ISIS_CONFIG_NODE_ENABLE:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    isis_init(node);
                    break;
                case CONFIG_DISABLE:
                    isis_de_init(node);
                    break;
                default:
                    break;
            }
    }

    return 0;
}

/*
* isis_config_cli_tree() - Function to register the config command with libcli
* param - param to register with libcli
* return - always return 0
*/
int
isis_config_cli_tree(param_t *param) 
{
    static param_t isis_proto;
    init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
    libcli_register_param(param, &isis_proto);
    set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
    return 0;
}

/* show node <node-name> protocol*/
static int 
isis_show_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable) {
    int cmdcode         = -1;
    tlv_struct_t *tlv   = NULL;
    char *node_name     = NULL;
    node_t *node        = NULL;
    
    cmdcode = EXTRACT_CMD_CODE(tlv_buf);
    
    TLV_LOOP_BEGIN(tlv_buf, tlv) {
        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
            node_name = tlv->value;
        } else {
            assert(0);
        }
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL:
            isis_show_node_protocol_state(node);
            break;
        default:
            break;
    }

    return 0;
}
/**show node <node-name> protocol*/
int
isis_show_cli_tree(param_t *param) {
    static param_t isis_proto;
    init_param(&isis_proto, CMD, "isis", isis_show_handler, 0, INVALID, 0, "isis protocol");
    libcli_register_param(param, &isis_proto);
    set_param_cmd_code(&isis_proto, CMDCODE_SHOW_NODE_ISIS_PROTOCOL);
    return 0;
}