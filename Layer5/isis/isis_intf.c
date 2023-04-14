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

/*
* isis_check_and_delete_intf_info()
* Assert if the interface pointer holds valid objects
*/
static void 
isis_check_and_delete_intf_info(interface_t *intf) {
    isis_intf_info_t *intf_info_ptr = NULL;
    intf_info_ptr = ISIS_INTF_INFO(intf);
    assert(!intf_info_ptr->adjacency);
    assert(!intf_info_ptr->hello_xmit_timer);
    free(intf->intf_nw_props.isis_intf_info);
    intf->intf_nw_props.isis_intf_info = NULL;
    return;
}

/*
* isis_disable_protocol_on_interface()
* Free the resources associated with the interface data structure.
*/
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
    isis_check_and_delete_intf_info(intf);
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

/*
* isis_handle_intf_up_down()
* Handle interface up/down notification
*/
void
isis_handle_intf_up_down(interface_t *intf, bool old_status) {
    /*Interface is coming up*/
    if (old_status == false) {
        LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
            "Comes up");
        if (!isis_interface_quality_to_send_hellos(intf)) {
            LOG(LOG_WARN, ISIS_IF_UPD, intf->att_node, intf, 
                "Interface is not qualified to send hellos");
            return;
        }
        isis_start_sending_hellos(intf);
    } else {
        /*Interface is going down*/
        LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
            "Goes down");
        isis_stop_sending_hellos(intf);
        isis_clear_interface_protocol_adjacency(intf);
    }
    return;
}

/*isis_handle_intf_addr_change()
* Handle interface address change notification
*/
void
isis_handle_intf_addr_change(interface_t *intf, 
                            uint32_t old_ip, uint8_t mask) {
    /*New address added*/
    if (IF_IP_EXIST(intf) && !old_ip && !mask) {
        LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
            "New IP address added");
        if (isis_interface_quality_to_send_hellos(intf)) {
            isis_start_sending_hellos(intf);
        }
    } else if (!IF_IP_EXIST(intf) && old_ip && mask) {
        LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
            "Removed existing IP address");
        /*Removed existing address*/
        isis_stop_sending_hellos(intf);
        isis_clear_interface_protocol_adjacency(intf);
    } else if (tcp_ip_covert_ip_p_to_n(IF_IP(intf)) != old_ip) {
        /*Updates the address*/
        LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
            "Updates existing IP address");
        if (isis_interface_quality_to_send_hellos(intf)) {
            isis_interface_refresh_hellos(intf);
        } else {
            isis_stop_sending_hellos(intf);
        }
    }
    return;
}

/*
*isis_interface_updates()
* Receive the interface updates and reflect on it.
*/
void
isis_interface_updates(void *arg, size_t arg_size) {
    intf_notif_data_t* intf_notif_data          = NULL;
    uint32_t            flags                   = 0x0;
    interface_t         *intf                   = NULL;
    intf_prop_changed_t *old_intf_prop_changed  = NULL;
    if (!arg) {
        return;
    }
    intf_notif_data = (intf_notif_data_t*)arg;
    flags = intf_notif_data->change_flags;
    intf  = intf_notif_data->interface;
    old_intf_prop_changed = intf_notif_data->old_intf_prop_changed;

    if (!isis_node_intf_is_enable(intf)) {
        LOG(LOG_WARN, ISIS_IF_UPD, intf->att_node, intf, 
            "ISIS proto not enabled on interface");
        return;
    }
    switch(flags) {
        case IF_UP_DOWN_CHANGE_F:
            {
                LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
                "up/down notification receives");
                isis_handle_intf_up_down(intf,
                            old_intf_prop_changed->up_status);
            }
            break;
        case IF_IP_ADDR_CHANGE_F:
            {
                LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
                "IP address change notif receives");
                isis_handle_intf_addr_change(
                            intf, 
                            old_intf_prop_changed->ip_addr.ip_addr,
                            old_intf_prop_changed->ip_addr.mask);
            }
            break;
        case IF_OPER_MODE_CHANGE_F:
            {
                LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
                "Oper mode change notif receives");                
            }
            break;
        case IF_VLAN_MEMBERSHIP_CHANGE_F:
            {
                LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
                "VLAN membership change notif receives");
            }
            break;
        case IF_METRIC_CHANGE_F:
            {
                LOG(LOG_DEBUG, ISIS_IF_UPD, intf->att_node, intf, 
                "Metric change notif receives");
            }
            break;
    }
    return;
}