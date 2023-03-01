#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include <arpa/inet.h>

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size) {
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t*)pkt;
    return (eth_hdr->type == ISIS_ETH_PKT_TYPE);
}

void isis_pkt_receive(void *arg, size_t arg_size) {
    printf("%s invoked \n", __FUNCTION__);
}

byte* isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size) {
    isis_pkt_hdr_t *hello_pkt_hdr = NULL;
    byte *temp = NULL;
    uint32_t eth_hdr_payload_size = sizeof(isis_pkt_hdr_t) + 
                                    (TLV_OVERHEAD_SIZE * 6) +
                                    NODE_NAME_SIZE +
                                    4+
                                    4+
                                    4+
                                    4+
                                    4;

    *hello_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + eth_hdr_payload_size;
    
    /* Prepare ethernet header*/
    ethernet_hdr_t *hello_eth_hdr  = (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(*hello_pkt_size);
    layer2_fill_with_broadcast_mac(hello_eth_hdr->dst_mac.mac);
    memset(hello_eth_hdr->src_mac.mac, 0x0, sizeof(mac_add_t));
    hello_eth_hdr->type = ISIS_ETH_PKT_TYPE;

    /*Prepare hello packet header*/
    hello_pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    hello_pkt_hdr->isis_pkt_type = ISIS_PTP_HELLO_PKT_TYPE;
    hello_pkt_hdr->seq_no = 0; // Not Required
    hello_pkt_hdr->rtr_id = tcp_ip_covert_ip_p_to_n(NODE_LO_ADDR(intf->att_node));
    hello_pkt_hdr->flags = 0;

    temp = (byte*)(hello_pkt_hdr + 1);

    /** Fill TLVs **/
    /*1. Insert Host Name TLV*/
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOSTNAME, NODE_NAME_SIZE, intf->att_node->node_name);
    
    /*2. Insert router id TLV*/
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_RTR_ID, 4, (byte *)&hello_pkt_hdr->rtr_id);
    
    /*3. Insert Interface IP address TLV*/
    uint32_t ip_addr_int = tcp_ip_covert_ip_p_to_n(IF_IP(intf));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_IP, 4, (byte *)&ip_addr_int);
    
    /*4. Insert interface index TLV*/
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_INDEX, 4, (byte *)&IF_INDEX(intf));
    
    /*5. Insert Hold Time TLV*/
    uint32_t hold_time = ISIS_INTF_HELLO_INTERVAL(intf) * ISIS_HOLD_TIME_FACTOR;
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOLD_TIME, 4, (byte *)&hold_time);
    
    /*6. Insert interface cost*/
    uint32_t cost = ISIS_INTF_COST(intf);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_METRIC_VAL, 4, (byte *)&cost);
    SET_COMMON_ETH_FCS(hello_eth_hdr, eth_hdr_payload_size, 0);
    
    char buffer[200];
    int len = isis_print_hello_pkt(buffer, hello_pkt_hdr, *hello_pkt_size);
    printf("ISIS_PTP_HELLO_PKT_TYPE : %s\n", buffer);
    return (byte*)hello_eth_hdr;
}

typedef enum tlv_type_t{
    TLV_HOSTNAME,
    TLV_RTR_ID,
    TLV_IF_IP,
    TLV_IF_INDEX,
    TLV_HOLD_TIME,
    TLV_METRIC_VAL,
    TLV_MAX
}tlv_type;

static uint32_t 
isis_print_hello_pkt(byte *buff, isis_pkt_hdr_t *hello_pkt_hdr, uint32_t pkt_size) {
    char *tlv_buffer = (char*)hello_pkt_hdr + sizeof(isis_pkt_hdr_t);
    uint8_t type;
    uint8_t len; 
    char *val;
    char array[TLV_MAX][20];
    char str[INET_ADDRSTRLEN];

    ITERATE_TLV_BEGIN(tlv_buffer, type, len, val, pkt_size){
        switch(type){
            case ISIS_TLV_HOSTNAME:
                sprintf(array[TLV_HOSTNAME], "%d %d %s", type, len, val);
                break;
            case ISIS_TLV_RTR_ID:
                memset(str, '\0', INET_ADDRSTRLEN);
                inet_ntop(AF_INET, val, str, INET_ADDRSTRLEN);
                sprintf(array[TLV_RTR_ID], "%d %d %s", type, len, str);
                break;
            case ISIS_TLV_IF_IP:
                memset(str, '\0', INET_ADDRSTRLEN);
                inet_ntop(AF_INET, val, str, INET_ADDRSTRLEN);
                sprintf(array[TLV_IF_IP], "%d %d %s", type, len, str);
                break;
            case ISIS_TLV_IF_INDEX:
                sprintf(array[TLV_IF_INDEX], "%d %d %d", type, len, (int)*val);
                break;
            case ISIS_TLV_HOLD_TIME:
                sprintf(array[TLV_HOLD_TIME], "%d %d %d", type, len, (int)*val);
                break;
            case ISIS_TLV_METRIC_VAL:
                sprintf(array[TLV_METRIC_VAL], "%d %d %d", type, len, (int)*val);
                break;
            default:
                break;
        }
    }ITERATE_TLV_END(tlv_buffer, type, len, val, pkt_size)

    sprintf(buff, "%s :: %s :: %s :: %s :: %s :: %s",
                                            array[TLV_HOSTNAME],
                                            array[TLV_RTR_ID],
                                            array[TLV_IF_IP],
                                            array[TLV_IF_INDEX],
                                            array[TLV_HOLD_TIME],
                                            array[TLV_METRIC_VAL]);
    int total_len = strlen(array[TLV_HOSTNAME]) + strlen(array[TLV_RTR_ID]) + 
                    strlen(array[TLV_IF_IP]) + strlen(array[TLV_IF_INDEX]) + 
                    strlen(array[TLV_HOLD_TIME]) + strlen(array[TLV_METRIC_VAL]) + 25;
    return total_len;
}