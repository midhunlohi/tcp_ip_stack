/**standard header files*/

#include <assert.h>

/*Project specific header files*/

#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_trace.h"
#include "isis_const.h"

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
    memset(isis_node_info, 0x0, sizeof(isis_node_info_t));
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

int
hello_interval_validate(char *interval) {
    uint32_t hello_interval = atoi(interval);
    if (hello_interval <= 3 || hello_interval >= 100) {
        printf("Error : Invalid Value, expected between 3 and 100\n");
        return VALIDATION_FAILED;
    }
    return VALIDATION_SUCCESS;
}

/*
* authentication_string_validate()
* Function to validate the authentication password string
*/
int
authentication_string_validate(char *string) {
    if (strlen(string) >= 32) {
        printf("Error : Invalid Value, expected a string with < 32 bytes size\n");
        return VALIDATION_FAILED;
    }
    return VALIDATION_SUCCESS;
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
    int         cmdcode         = -1;
    tlv_struct_t *tlv           = NULL;
    char        *node_name      = NULL;
    char        *if_name        = NULL;
    node_t      *node           = NULL;
    interface_t *intf           = NULL;
    uint32_t    hello_interval  = ISIS_DEFAULT_HELLO_INTERVAL;
    bool        hello_cmd       = false;
    bool        auth_cmd        = false;
    char        password[AUTH_PASSWD_LEN];
    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv) {
        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
            node_name = tlv->value;
        } else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0) {
            if_name = tlv->value;            
        } else if (strncmp(tlv->leaf_id, "hello-interval", strlen("hello-interval")) == 0) {
            hello_interval = atoi(tlv->value);
            hello_cmd = true;
        } else if(strncmp(tlv->leaf_id, "authentication", strlen("authentication")) == 0) {
            strncpy(password, tlv->value, AUTH_PASSWD_LEN);
            auth_cmd = true;
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
                        LOG(LOG_DEBUG, ISIS_CONF, intf->att_node, intf, "%s: ISIS protocol enabled", __FUNCTION__);
                    } else {
                        LOG(LOG_ERROR, ISIS_CONF, intf->att_node, intf, "%s: Failed to configure ISIS protocol", __FUNCTION__);
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
        case CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_HELLO_INTERVAL_PARAM:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    if (hello_cmd) {
                        isis_update_interface_protocol_hello_interval(intf, hello_interval);
                        isis_interface_refresh_hellos(intf);
                    }
                    break;
                case CONFIG_DISABLE:
                    if (hello_cmd) {
                        isis_update_interface_protocol_hello_interval(intf, ISIS_DEFAULT_HELLO_INTERVAL);
                        isis_interface_refresh_hellos(intf);
                    }
                    break;
                default:
                    break;      
            }
        case CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_AUTH_PARAM:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    if (auth_cmd) {
                        isis_update_interface_protocol_authentication(intf, password);
                        isis_interface_refresh_hellos(intf);
                    }
                    break;
                case CONFIG_DISABLE:
                    if (auth_cmd) {
                        isis_update_interface_protocol_authentication(intf, NULL);
                        isis_interface_refresh_hellos(intf);
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
            {
                /*Register for cmd - conf node <node-name> protocol isis interface <if-name> hello-interval*/
                static param_t hello_intrvl_cmd;
                init_param(&hello_intrvl_cmd, CMD, "hello-interval", isis_interface_config_handler, 0, 
                            INVALID, 0, "hello interval value");
                libcli_register_param(&intf_name, &hello_intrvl_cmd);
                set_param_cmd_code(&hello_intrvl_cmd, CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_HELLO_INTERVAL);
                {
                    /*Register for param - conf node <node-name> protocol isis interface <if-name> hello-interval <hello-interval-value>*/
                    static param_t hello_intrvl_param;
                    init_param(&hello_intrvl_param, LEAF, 0, isis_interface_config_handler, hello_interval_validate,
                                INT, "hello-interval", "hello interval value");
                    libcli_register_param(&hello_intrvl_cmd, &hello_intrvl_param);
                    set_param_cmd_code(&hello_intrvl_param, CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_HELLO_INTERVAL_PARAM);
                }
            }
            {
                /*Register for cmd - conf node <node-name> protocol isis interface <if-name> authentication*/
                static param_t auth_cmd;
                init_param(&auth_cmd, CMD, "authentication", isis_interface_config_handler, 0, 
                            INVALID, 0, "password");
                libcli_register_param(&intf_name, &auth_cmd);
                set_param_cmd_code(&auth_cmd, CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_AUTH_CMD);
                {
                    /*Register for param - conf node <node-name> protocol isis interface <if-name> authentication <password>*/
                    static param_t auth_param;
                    init_param(&auth_param, LEAF, 0, isis_interface_config_handler, authentication_string_validate,
                                STRING, "authentication", "password");
                    libcli_register_param(&auth_cmd, &auth_param);
                    set_param_cmd_code(&auth_param, CMDCODE_CONF_NODE_ISIS_PROTOCOL_INTF_AUTH_PARAM);
                }
            }
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
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_INTF_STATS:
            isis_show_node_protocol_interface_stats(node);
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
    {
        static param_t isis_proto;
        init_param(&isis_proto, CMD, "isis", isis_show_handler, 0, INVALID, 0, "isis protocol");
        libcli_register_param(param, &isis_proto);
        set_param_cmd_code(&isis_proto, CMDCODE_SHOW_NODE_ISIS_PROTOCOL);
        {
            static param_t interface_stats;
            init_param(&interface_stats, CMD, "interface", isis_show_handler, 0, INVALID, 0, "interface statistics");
            libcli_register_param(&isis_proto, &interface_stats);
            set_param_cmd_code(&interface_stats, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_INTF_STATS);
        }
    }
    return 0;
}

/*
* isis_clear_handler()
* Function to display the clear command - clear node <node-name> protocol isis <>
*/
static int 
isis_clear_handler(param_t *param, 
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
        case CMDCODE_CLEAR_NODE_ISIS_PROTOCOL:
            /*clear node <node-name> protocol isis*/
            /*NO-OP*/
            break;
        case CMDCODE_CLEAR_NODE_ISIS_PROTOCOL_ADJACENCIES:
            /*clear node <node-name> protocol isis adjacencies*/
            isis_clear_node_protocol_adjacency(node);
            break;
        default:
            break;
    }

    return 0;
}

/*
* isis_clear_cli_tree()
* Function to register the clear commands for the ISIS protocol
*/
int
isis_clear_cli_tree(param_t *param) {
    {
        /*Register for the command : clear node <node-name> protocol isis*/
        static param_t isis_proto;
        init_param(&isis_proto, CMD, "isis", isis_clear_handler, 0, INVALID, 0, "isis protocol");
        libcli_register_param(param, &isis_proto);
        set_param_cmd_code(&isis_proto, CMDCODE_CLEAR_NODE_ISIS_PROTOCOL);
        {
            /*Register for the command : clear node <node-name> protocol isis adjacencies*/
            static param_t clear_adj;
            init_param(&clear_adj, CMD, "adjacencies", isis_clear_handler, 0, INVALID, 0, "clear all adjacencies");
            libcli_register_param(&isis_proto, &clear_adj);
            set_param_cmd_code(&clear_adj, CMDCODE_CLEAR_NODE_ISIS_PROTOCOL_ADJACENCIES);
        }
    }
}