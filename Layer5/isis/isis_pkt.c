#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_rtr.h"
#include <arpa/inet.h>
#include "isis_trace.h"
#include "isis_adjacency.h"
#include "isis_intf.h"

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size) {
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t*)pkt;
    return (eth_hdr->type == ISIS_ETH_PKT_TYPE);
}

void 
isis_process_hello_pkt(node_t *node, interface_t *iif, ethernet_hdr_t *hello_eth_hdr, size_t pkt_size){
    uint8_t intf_ip_len = 0;
    uint8_t password_len = 0;
    
    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(iif);

    if (!isis_node_intf_is_enable(iif)) {
        /* ISIS protocol is not enabled on the interface on the node*/
        LOG(LOG_WARN, ISIS_PKT, node, iif, "%s: ISIS protocol is not enabled on the interface %s", __FUNCTION__, iif->if_name);
        if (isis_intf_info) {
            isis_intf_info->drop_stats[ISIS_PROTO_NOT_ENABLED]++;
        }
        goto bad_hello;
    }
    if (!isis_interface_quality_to_send_hellos(iif)) {
        /* Interface is not qualified to send hello packets*/
        LOG(LOG_WARN, ISIS_PKT, node, iif, "%s: Interface is not qualified to send hello packets %s", __FUNCTION__, iif->if_name);
        if (isis_intf_info) {
            isis_intf_info->drop_stats[INTF_NOT_QUALIFIED]++;
        }
        goto bad_hello;
    }
    if (!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac)) {
        /* Dest MAC is not Broadcast address */
        LOG(LOG_WARN, ISIS_PKT, node, iif, "%s: Dest MAC is not Broadcast address", __FUNCTION__);
        if (isis_intf_info) {
            isis_intf_info->drop_stats[DEST_MAC_IS_NOT_BCAST]++;
        }
        goto bad_hello;
    }
    
    isis_pkt_hdr_t *hello_pkt_hdr = (isis_pkt_hdr_t*)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    byte *hello_tlv_buffer = (byte*)(hello_pkt_hdr + 1);
    size_t tlv_buff_size = pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD - sizeof(isis_pkt_hdr_t);
    uint32_t *if_ip_addr_int = (uint32_t *)tlv_buffer_get_particular_tlv(hello_tlv_buffer, tlv_buff_size, ISIS_TLV_IF_IP, &intf_ip_len);

    if (!if_ip_addr_int) {
        /*IP TLV is missing in the packet*/
        LOG(LOG_WARN, ISIS_PKT, node, iif, "%s: IP TLV is missing in the packet", __FUNCTION__);
        if (isis_intf_info) {
            isis_intf_info->drop_stats[IP_TLV_MISSING]++;
        }
        goto bad_hello;
    }

    char* if_ip_addr_str = tcp_ip_covert_ip_n_to_p(*if_ip_addr_int, 0);
    if (!is_same_subnet(IF_IP(iif), IF_MASK(iif), if_ip_addr_str)) {
        /*Packet IP subnet is not matching with interface subnet.*/
        LOG(LOG_WARN, ISIS_PKT, node, iif, "%s: Packet IP subnet is not matching with interface subnet.", __FUNCTION__);
        if (isis_intf_info) {
            isis_intf_info->drop_stats[IP_SUBNET_MISMATCH]++;
        }
        goto bad_hello;
    }

    char *password = tlv_buffer_get_particular_tlv(hello_tlv_buffer, tlv_buff_size, ISIS_TLV_AUTH, &password_len);
    if (!password && !password_len) {
        LOG(LOG_DEBUG, ISIS_ADJ, iif->att_node, iif, "password is EMPTY");
    } else {
        LOG(LOG_DEBUG, ISIS_ADJ, iif->att_node, iif, "password is %s", password);
        if (!isis_intf_info->authentication.auth_enable) {
            LOG(LOG_DEBUG, ISIS_ADJ, iif->att_node, iif, "Auth is not enabled");
            isis_update_adjacency_state(isis_intf_info->adjacency, ISIS_ADJ_STATE_DOWN);
            if (isis_intf_info) {
                isis_intf_info->drop_stats[AUTH_DISABLED]++;
            }
            goto bad_hello;
        } else {
            if (memcmp(isis_intf_info->authentication.password, password, AUTH_PASSWD_LEN)) {
                LOG(LOG_DEBUG, ISIS_ADJ, iif->att_node, iif, "Auth is not MATCHING");
                isis_update_adjacency_state(isis_intf_info->adjacency, ISIS_ADJ_STATE_DOWN);
                if (isis_intf_info) {
                    isis_intf_info->drop_stats[AUTH_MISMATCH]++;
                }
                goto bad_hello;
            } else {
                LOG(LOG_DEBUG, ISIS_ADJ, iif->att_node, iif, "Auth is MATCHING :-)");
            }    
        }        
    }
    isis_update_interface_adjacency_from_hello(iif, hello_tlv_buffer, tlv_buff_size);
    ISIS_INCREMENT_INTF_STAT(iif, hello_pkt_rcv_cnt);
    return;

    bad_hello:
        LOG(LOG_ERROR, ISIS_PKT, node, iif, "%s: Hello packet rejected, node=%s, iif=%s", __FUNCTION__, node->node_name, iif->if_name);
        ISIS_INCREMENT_INTF_STAT(iif, hello_pkt_drp_cnt);
}

void 
isis_process_lsp_pkt(node_t *node, interface_t *iif, ethernet_hdr_t *lsp_eth_hdr, size_t pkt_size){

}

/*
* Receive Hello Pkt or Receive LSP Pkt
*/
void isis_pkt_receive(void *arg, size_t arg_size) {
#if 0
    printf("%s invoked \n", __FUNCTION__);
#endif
    pkt_notif_data_t*  pkt_notif_data = (pkt_notif_data_t*)arg;
    node_t                      *node = pkt_notif_data->recv_node;
    interface_t                  *iif = pkt_notif_data->recv_interface;
    ethernet_hdr_t     *hello_eth_hdr = (ethernet_hdr_t*)pkt_notif_data->pkt;
    uint32_t                 pkt_size = pkt_notif_data->pkt_size;

    if (!isis_is_protocol_enable_on_node(node)) {
        LOG(LOG_WARN, ISIS_PKT, node, iif, "%s: ISIS is not enabled on the node", 
            __FUNCTION__);
        return;
    }

    isis_pkt_hdr_t *pkt_hdr = (isis_pkt_hdr_t*)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    switch(pkt_hdr->isis_pkt_type) {
        case ISIS_PTP_HELLO_PKT_TYPE:
            isis_process_hello_pkt(node, iif, hello_eth_hdr, pkt_size);
            break;
        case ISIS_LSP_PKT_TYPE:
            isis_process_lsp_pkt(node, iif, hello_eth_hdr, pkt_size);
            break;
    }
}

byte* isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size) {
    isis_pkt_hdr_t *hello_pkt_hdr = NULL;
    byte *temp = NULL;
    uint32_t eth_hdr_payload_size = sizeof(isis_pkt_hdr_t) + 
                                    (TLV_OVERHEAD_SIZE * 6) +
                                    NODE_NAME_SIZE +
                                    4+ // ISIS_TLV_RTR_ID size in bytes
                                    4+ // ISIS_TLV_IF_IP size in bytes
                                    4+ // ISIS_TLV_IF_INDEX size in bytes
                                    4+ // ISIS_TLV_HOLD_TIME size in bytes
                                    4+ // ISIS_TLV_METRIC_VAL size in bytes
                                    6; // ISIS_TLV_MAC_ADDR size in bytes
    isis_intf_info_t *intf_info_ptr = ISIS_INTF_INFO(intf);
    if (!intf_info_ptr) {
        printf("Error: intf_info_ptr is NULL\n");
        return NULL;
    }
    if (intf_info_ptr->authentication.auth_enable) {
        eth_hdr_payload_size += AUTH_PASSWD_LEN;
    }
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

    /*7. Insert interface mac*/
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_MAC_ADDR, 6, (byte*)&IF_MAC(intf));

    /*8. Inser auth password*/
    if (intf_info_ptr->authentication.auth_enable) {
        temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_AUTH, 32, intf_info_ptr->authentication.password);
    }

    SET_COMMON_ETH_FCS(hello_eth_hdr, eth_hdr_payload_size, 0);
    
    char buffer[200];
    int len = isis_print_hello_pkt(buffer, hello_pkt_hdr, *hello_pkt_size);
    LOG(LOG_DEBUG, ISIS_PKT, intf->att_node, intf, buffer);
    return (byte*)hello_eth_hdr;
}

typedef enum tlv_type_t{
    TLV_HOSTNAME,
    TLV_RTR_ID,
    TLV_IF_IP,
    TLV_IF_INDEX,
    TLV_HOLD_TIME,
    TLV_METRIC_VAL,
    TLV_IF_MAC,
    TLV_IF_AUTH,
    TLV_MAX
}tlv_type;

static uint32_t 
isis_print_hello_pkt(byte *buff, isis_pkt_hdr_t *hello_pkt_hdr, uint32_t pkt_size) {
    char *tlv_buffer = (char*)hello_pkt_hdr + sizeof(isis_pkt_hdr_t);
    uint8_t type;
    uint8_t len; 
    char *val;
    char array[TLV_MAX][65];
    char str[INET_ADDRSTRLEN];
    char *isis_proto_type = "ISIS_PTP_HELLO_PKT_TYPE";
    ITERATE_TLV_BEGIN(tlv_buffer, type, len, val, pkt_size){
        switch(type){
            case ISIS_TLV_HOSTNAME:
                sprintf(array[TLV_HOSTNAME], ":: %d %d %s", type, len, val);
                break;
            case ISIS_TLV_RTR_ID:
                memset(str, '\0', INET_ADDRSTRLEN);
                sprintf(str, "%d.%d.%d.%d", val[3], val[2], val[1], val[0]);
                sprintf(array[TLV_RTR_ID], ":: %d %d %s", type, len, str);
                break;
            case ISIS_TLV_IF_IP:
                memset(str, '\0', INET_ADDRSTRLEN);
                sprintf(str, "%d.%d.%d.%d", val[3], val[2], val[1], val[0]);
                sprintf(array[TLV_IF_IP], ":: %d %d %s", type, len, str);
                break;
            case ISIS_TLV_IF_INDEX:
                sprintf(array[TLV_IF_INDEX], ":: %d %d %d", type, len, *(uint32_t*)val);
                break;
            case ISIS_TLV_HOLD_TIME:
                sprintf(array[TLV_HOLD_TIME], ":: %d %d %d", type, len, *(uint32_t*)val);
                break;
            case ISIS_TLV_METRIC_VAL:
                sprintf(array[TLV_METRIC_VAL], ":: %d %d %d", type, len, *(uint32_t*)val);
                break;
            case ISIS_TLV_MAC_ADDR:
                sprintf(array[TLV_IF_MAC], ":: %d %d %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", type, len, 
                        (unsigned char)val[0], (unsigned char)val[1], (unsigned char)val[2], 
                        (unsigned char)val[3], (unsigned char)val[4], (unsigned char)val[5]);

                break;
            case ISIS_TLV_AUTH:
                sprintf(array[TLV_IF_AUTH], ":: %d %d %s", type, len, val);
                break;
            default:
                break;
        }
    }ITERATE_TLV_END(tlv_buffer, type, len, val, pkt_size)

    sprintf(buff, "%s%s%s%s%s%s%s%s%s",
                isis_proto_type,
                array[TLV_HOSTNAME],
                array[TLV_RTR_ID],
                array[TLV_IF_IP],
                array[TLV_IF_INDEX],
                array[TLV_HOLD_TIME],
                array[TLV_METRIC_VAL],
                array[TLV_IF_MAC],
                array[TLV_IF_AUTH]);
    int total_len = strlen(isis_proto_type) + 
                    strlen(array[TLV_HOSTNAME]) + strlen(array[TLV_RTR_ID]) + 
                    strlen(array[TLV_IF_IP]) + strlen(array[TLV_IF_INDEX]) + 
                    strlen(array[TLV_HOLD_TIME]) + strlen(array[TLV_METRIC_VAL]) + 
                    strlen(array[TLV_IF_MAC]) + strlen(array[TLV_IF_AUTH]);
    return total_len;
}

/*
* Function invokes by TCP/IP stack
*/
void 
isis_print_pkt(void *arg, size_t arg_size){
    pkt_info_t *pkt_info = (pkt_info_t*)arg;
    if (!pkt_info) {
        printf("Error : pkt_info is NULL\n");
        return;
    }

    byte *buff = pkt_info->pkt_print_buffer;
    size_t packet_size = pkt_info->pkt_size;

    // printf("packet size = %ld = 0x%lx\n", packet_size, packet_size);

    isis_pkt_hdr_t *isis_pkt_hdr = (isis_pkt_hdr_t*)(pkt_info->pkt);
    pkt_info->bytes_written = 0;

    isis_pkt_type_t pkt_type = isis_pkt_hdr->isis_pkt_type;

    switch(pkt_type) {
        case ISIS_PTP_HELLO_PKT_TYPE:
            pkt_info->bytes_written += isis_print_hello_pkt(buff, isis_pkt_hdr, packet_size);
            // printf("pkt_info->bytes_written = %d = 0x%x\n", pkt_info->bytes_written, pkt_info->bytes_written);
            break;
        case ISIS_LSP_PKT_TYPE:
            //pkt_info->bytes_written += isis_print_lsp_pkt(buff, isis_pkt_hdr, packet_size);
            break;
        default:
            break;
    }
    return;
}