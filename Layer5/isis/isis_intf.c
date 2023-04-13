#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_trace.h"

static void
isis_init_isis_intf_info(interface_t *intf_ptr) {
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf_ptr);
    memset(intf_info_ptr, 0x0, sizeof(isis_intf_info_t));
    intf_info_ptr->cost = ISIS_DEFAULT_INTF_COST;
    intf_info_ptr->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    intf_info_ptr->hello_transmission = false;
}

bool
isis_node_intf_is_enable(interface_t *intf) {
    if (NULL == ISIS_INTF_INFO(intf)) {
        // printf("%s , ISIS protocol is disabled on interface\n", __FUNCTION__);
        return (false);
    } else {
        // printf("%s , ISIS protocol is enabled on interface\n", __FUNCTION__);
        return (true);
    }
}

int
isis_enable_protocol_on_interface(interface_t *intf) {
    isis_intf_info_t *intf_info_ptr = NULL;
    if (NULL == ISIS_NODE_INFO(intf->att_node)) {
        printf("Error: protocol disabled at node\n");
        return -1;
    }
    
    intf_info_ptr = ISIS_INTF_INFO(intf);
    if (intf_info_ptr) {
        printf("protocol is already enabled on this interface.\n");
        return -1;
    }

    intf_info_ptr = (isis_intf_info_t *)malloc(sizeof(isis_intf_info_t));
    if (!intf_info_ptr) {
        printf("Error: malloc() failed\n");
    }
    intf->intf_nw_props.isis_intf_info = intf_info_ptr;
    isis_init_isis_intf_info(intf);

    if (intf_info_ptr->hello_xmit_timer == NULL) {
        if (isis_interface_quality_to_send_hellos(intf)) {
            isis_start_sending_hellos(intf);
        }
    }

    return 0;
}

int
isis_disable_protocol_on_interface(interface_t *intf) {
    isis_intf_info_t *intf_info_ptr = NULL;

    intf_info_ptr = ISIS_INTF_INFO(intf);
    if (!intf_info_ptr) {
        printf("protocol is already disabled on this interface.\n");
        return -1;
    }

    isis_stop_sending_hellos(intf);
    /*Delete the adjacencies*/
    isis_delete_adjacency(intf_info_ptr->adjacency);
    free(intf_info_ptr);
    intf->intf_nw_props.isis_intf_info = NULL;

    return 0;
}

static void
isis_transmit_hello_cb(void *arg, uint32_t arg_size) {
    if (!arg) {
        return;
    }

    isis_timer_data_t *timer_data = (isis_timer_data_t *)arg;
    node_t *node = timer_data->node;
    interface_t *intf = timer_data->intf;
    byte *hello_pkt = (byte*)timer_data->data;
    size_t hello_pkt_size = timer_data->data_size;
    LOG(LOG_DEBUG, ISIS_PKT, intf->att_node, intf, ">>>> Hello out", hello_pkt);
    send_pkt_out(hello_pkt, hello_pkt_size, intf);
    ISIS_INCREMENT_INTF_STAT(intf, hello_pkt_snt_cnt);
    return;
}

void
isis_start_sending_hellos(interface_t *intf) {
    if (!intf) {
        return;
    }
    
    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);
    if (!isis_intf_info) {
        return;
    }        
    size_t hello_pkt_size = 0;

    assert(ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL);
    assert(isis_node_intf_is_enable(intf));

    wheel_timer_t *wt = node_get_timer_instance(intf->att_node);
    byte *hello_pkt = isis_prepare_hello_pkt(intf, &hello_pkt_size);

    isis_timer_data_t *timer_data = (isis_timer_data_t *)malloc(sizeof(isis_timer_data_t));
    if (!timer_data) {
        printf("Err:Failed to allocted memory for timer data\n");
        return;
    }

    timer_data->node = intf->att_node;
    timer_data->intf = intf;
    timer_data->data = (void*)hello_pkt;
    timer_data->data_size = hello_pkt_size;

    isis_transmit_hello_cb((void *)timer_data, 0);
    ISIS_INTF_HELLO_XMIT_TIMER(intf) = timer_register_app_event(wt, isis_transmit_hello_cb, (void *)timer_data, 
                            sizeof(isis_timer_data_t), ISIS_INTF_HELLO_INTERVAL(intf) * 1000, 1);
    ISIS_INTF_HELLO_TX_STATUS(intf) = true;
    return;
}

void
isis_stop_sending_hellos(interface_t *intf) {
    if (!intf) {
        return;
    }

    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);
    if (!isis_intf_info) {
        return;
    }    

    timer_event_handle *hello_xmit_timer = NULL;
    hello_xmit_timer = ISIS_INTF_HELLO_XMIT_TIMER(intf);

    if (!hello_xmit_timer) {
        return;
    }

    /** Claiming back the memory **/
    isis_timer_data_t *isis_timer_data = (isis_timer_data_t*)wt_elem_get_and_set_app_data(hello_xmit_timer, 0);
    tcp_ip_free_pkt_buffer(isis_timer_data->data, isis_timer_data->data_size);
    free(isis_timer_data);

    /** De Register **/
    timer_de_register_app_event(hello_xmit_timer);
    ISIS_INTF_HELLO_XMIT_TIMER(intf) = NULL;
    ISIS_INTF_HELLO_TX_STATUS(intf) = false;
    return;
}

bool
isis_interface_quality_to_send_hellos(interface_t *intf) {
    if (isis_node_intf_is_enable(intf) &&
            IF_IS_UP(intf) &&
                IS_INTF_L3_MODE(intf)) {
        return (true);
    }
    return (false);
}

void
isis_print_drop_stats(interface_t *intf) {
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);    
    PRINT_TABS(5);
    printf("ISIS_PROTO_NOT_ENABLED : %d\n", intf_info_ptr->drop_stats[ISIS_PROTO_NOT_ENABLED]);
    PRINT_TABS(5);
    printf("INTF_NOT_QUALIFIED : %d\n", intf_info_ptr->drop_stats[INTF_NOT_QUALIFIED]);
    PRINT_TABS(5);
    printf("DEST_MAC_IS_NOT_BCAST : %d\n", intf_info_ptr->drop_stats[DEST_MAC_IS_NOT_BCAST]);
    PRINT_TABS(5);
    printf("IP_TLV_MISSING : %d\n", intf_info_ptr->drop_stats[IP_TLV_MISSING]);
    PRINT_TABS(5);
    printf("IP_SUBNET_MISMATCH : %d\n", intf_info_ptr->drop_stats[IP_SUBNET_MISMATCH]);
    PRINT_TABS(5);
    printf("AUTH_DISABLED : %d\n", intf_info_ptr->drop_stats[AUTH_DISABLED]);
    PRINT_TABS(5);
    printf("AUTH_MISMATCH : %d\n", intf_info_ptr->drop_stats[AUTH_MISMATCH]);
}

void
isis_print_intf_stats(interface_t *intf) {    
    PRINT_TABS(5);
    printf("Hello pkts rcvd : %d\n", ISIS_GET_INTF_STAT(intf, hello_pkt_rcv_cnt));
    PRINT_TABS(5);
    printf("Hello pkts sent : %d\n", ISIS_GET_INTF_STAT(intf, hello_pkt_snt_cnt));
    PRINT_TABS(5);
    printf("Hello pkts dropped : %d\n", ISIS_GET_INTF_STAT(intf, hello_pkt_drp_cnt));
}

void 
isis_show_interface_protocol_state(interface_t *intf) {
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);
    if (intf_info_ptr) {
        printf("hello interval : %d sec, Intf Cost : %d, ", ISIS_INTF_HELLO_INTERVAL(intf), ISIS_INTF_COST(intf));
        printf("authentication : %s\n", 
                intf_info_ptr->authentication.auth_enable ? intf_info_ptr->authentication.password : "OFF");
        printf("hello transmission : %s\n", ISIS_INTF_HELLO_TX_STATUS(intf) ? "On" : "Off");
        printf("Stats:\n");
        isis_print_intf_stats(intf);
        printf("Drop Stats:\n");
        isis_print_drop_stats(intf);
        printf("Adjacencies:\n");
        isis_show_adjacency(intf_info_ptr->adjacency, 5);
        printf("\n\n");
    }
    return;
}

/*
* isis_clear_interface_protocol_adjacency()
* The function free the resources allocated for adjacency for an interface
*/
void
isis_clear_interface_protocol_adjacency(interface_t *intf) {
    if (!intf) {
        return;
    }
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);

    if (!intf_info_ptr) {
        return;
    }
    isis_delete_adjacency(intf_info_ptr->adjacency);
    return;
}

/*
*isis_update_interface_protocol_hello_interval()
* The function is to update the hello interval time period for sending hello packet
*/
void
isis_update_interface_protocol_hello_interval(interface_t *intf, uint32_t hello_interval) {
    if (!intf) {
        return;
    }
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);
    if (!intf_info_ptr) {
        return;
    }
    intf_info_ptr->hello_interval = hello_interval;
    return;         
}

/*
* isis_interface_refresh_hellos()
* The function to restart the send hello packet
*/
void
isis_interface_refresh_hellos(interface_t* intf) {
    if (!intf) {
        return;
    }
    isis_stop_sending_hellos(intf);
    isis_start_sending_hellos(intf);
}

/*
*isis_update_interface_protocol_hello_interval()
* The function is to update the hello interval time period for sending hello packet
*/
void
isis_update_interface_protocol_authentication(interface_t *intf, char* password) {
    if (!intf) {
        return;
    }
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);
    if (!intf_info_ptr) {
        return;
    }
    if (!password) {
        intf_info_ptr->authentication.auth_enable = false;
        return;
    }
    intf_info_ptr->authentication.auth_enable = true;
    strncpy(intf_info_ptr->authentication.password, password, AUTH_PASSWD_LEN);
    return;         
}