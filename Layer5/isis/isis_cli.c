/**standard header files*/

#include <assert.h>

/*Project specific header files*/

#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"

typedef enum status_t{ 
    SUCCESS, 
    FAILURE
}status;

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
    tcp_stack_register_l2_pkt_trap_rule(node, isis_pkt_trap_rule, isis_pkt_receive);
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
    tcp_stack_de_register_l2_pkt_trap_rule(node, isis_pkt_trap_rule, isis_pkt_receive);
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
* isis_interface_config_handler()
* conf node <node-name> protocol isis interface all
* isis_config_handler() - The function to handle the confiuguration of ISIS protocol.
* param - parameters passed when we register with libcli.
* tlv_buff - TLV buffer associated with the input config command.
* op_mode - Whether the command is for disabling or enabling the configuration.
*/

static int 
isis_interface_config_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable)
{
    int cmdcode         = -1;
    tlv_struct_t *tlv   = NULL;
    char *node_name     = NULL;
    char *if_name       = NULL;
    node_t *node        = NULL;
    interface_t *intf   = NULL;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);
    
    TLV_LOOP_BEGIN(tlv_buf, tlv) {
        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
            node_name = tlv->value;
        } else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0) {
            if_name = tlv->value;
        } else {
            assert(0);
        }
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (if_name && node_name && node) {
        intf = node_get_intf_by_name(node, if_name);
        if (NULL == intf) {
            printf("%s, no interface %s exists for the node %s\n", 
                    __FUNCTION__, if_name, node_name);
            return -1;
        }
    }

    switch(cmdcode) {
        case CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_ALL:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    printf("Midhun debug 1\n");
                    ITERATE_NODE_INTERFACES_BEGIN(node, intf){
                        isis_enable_protocol_on_interface(intf);
                    }ITERATE_NODE_INTERFACES_END(node, intf);
                    printf("config enabled for all interaces\n");
                    break;
                case CONFIG_DISABLE:
                    ITERATE_NODE_INTERFACES_BEGIN(node, intf){                       
                        isis_disable_protocol_on_interface(intf);   
                    }ITERATE_NODE_INTERFACES_END(node, intf);
                    printf("config disabled for all interfaces\n");
                    break;
                default:
                    break;
            }
            break;
        case CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    if (SUCCESS == isis_enable_protocol_on_interface(intf)) {
                        printf("config enabled for interace %s\n", if_name);
                    } else {
                        printf("Error to config for interace %s\n", if_name);
                    }
                    break;
                case CONFIG_DISABLE:
                    if (SUCCESS == isis_disable_protocol_on_interface(intf)) {
                        printf("config disabled for interface %s\n", if_name);
                    } else {
                        printf("Error to disable for interface %s\n", if_name);
                    }
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

    /*config node R1 protocol isis interface*/
    {
        static param_t isis_interface;
        init_param(&isis_interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
        libcli_register_param(&isis_proto, &isis_interface);
        /*config node R1 protocol isis interface all*/
        {
            static param_t all;
            init_param(&all, CMD, "all", isis_interface_config_handler, 0, INVALID, 0, "all interfaces");
            libcli_register_param(&isis_interface, &all);
            set_param_cmd_code(&all, CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_ALL);
        }
        /*config node R1 protocol isis interface <if-name>*/
        {
            static param_t intf_name;
            init_param(&intf_name, LEAF, 0, isis_interface_config_handler, 0, STRING, "if-name", "interface name");
            libcli_register_param(&isis_interface, &intf_name);
            set_param_cmd_code(&intf_name, CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF);
        }
    }

    /*config node R1 protocol isis interface <interface-name>*/
    return 0;
}

/*
* isis_show_handler()
* Function to display the show command - show node <node-name> protocol
*/
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

/* isis_show_cli_tree()
* Function to register the show commands for the ISIS protocol.
*/
int
isis_show_cli_tree(param_t *param) {
    static param_t isis_proto;
    init_param(&isis_proto, CMD, "isis", isis_show_handler, 0, INVALID, 0, "isis protocol");
    libcli_register_param(param, &isis_proto);
    set_param_cmd_code(&isis_proto, CMDCODE_SHOW_NODE_ISIS_PROTOCOL);
    return 0;
}