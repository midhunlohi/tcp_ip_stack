#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_pkt.h"

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
    
    send_pkt_out(hello_pkt, hello_pkt_size, intf);

    return;
}

void
isis_start_sending_hellos(interface_t *intf) {
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

    ISIS_INTF_HELLO_XMIT_TIMER(intf) = timer_register_app_event(wt, isis_transmit_hello_cb, (void *)timer_data, 
                            sizeof(isis_timer_data_t), ISIS_INTF_HELLO_INTERVAL(intf) * 1000, 1);
    ISIS_INTF_HELLO_TX_STATUS(intf) = true;
    return;
}

void
isis_stop_sending_hellos(interface_t *intf) {
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
isis_show_interface_protocol_state(interface_t *intf) {
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);
    printf("hello interval : %d sec, Intf Cost : %d\n", ISIS_INTF_HELLO_INTERVAL(intf), ISIS_INTF_COST(intf));
    printf("hello transmission : %s\n", ISIS_INTF_HELLO_TX_STATUS(intf) ? "On" : "Off");
    return;
}