#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "tcp_public.h"
#include "CommandParser/libcli.h"
#include "CommandParser/cmdtlv.h"

#define TCP_PRINT_BUFFER_SIZE   2048
static char tcp_print_buffer[TCP_PRINT_BUFFER_SIZE];
static char string_buffer[32];

static void init_tcp_print_buffer(){
    memset(tcp_print_buffer, 0, sizeof(tcp_print_buffer));
}

static void init_string_buffer(){
    memset(string_buffer, 0, sizeof(string_buffer));
}

static char *
string_ethernet_hdr_type(unsigned short type){

    init_string_buffer();
    switch(type){

        case ETH_IP:
            strncpy(string_buffer, "ETH_IP", strlen("ETH_IP"));
            break;
        case ARP_MSG:
            strncpy(string_buffer, "ARP_MSG", strlen("ARP_MSG"));
            break;
        case DDCP_MSG_TYPE_FLOOD_QUERY:
            strncpy(string_buffer, "DDCP_MSG_TYPE_FLOOD_QUERY", 
                strlen("DDCP_MSG_TYPE_FLOOD_QUERY"));
            break;
        default:
            return NULL;
    }
    return string_buffer;
}

static char *
string_arp_hdr_type(int type){

    init_string_buffer();
    switch(type){
        case ARP_BROAD_REQ:
            strncpy(string_buffer, "ARP_BROAD_REQ", strlen("ARP_BROAD_REQ"));
            break;
        case ARP_REPLY:
            strncpy(string_buffer, "ARP_REPLY", strlen("ARP_REPLY"));
            break;
        default:
            ;
    }
    return string_buffer;
}

static char *
string_ip_hdr_protocol_val(uint8_t type){

    init_string_buffer();
    switch(type){

        case ICMP_PRO:
            strncpy(string_buffer, "ICMP_PRO", strlen("ICMP_PRO"));
            break;
        case DDCP_MSG_TYPE_UCAST_REPLY:
            strncpy(string_buffer, "DDCP_MSG_TYPE_UCAST_REPLY" , 
                strlen("DDCP_MSG_TYPE_UCAST_REPLY"));
            break;
        default:
            return NULL;
    }
    return string_buffer;
}

static int
tcp_dump_appln_hdr(char *buff, char *appln_data, uint32_t pkt_size, int tab_count){

    return 0;
}

static int
tcp_dump_ip_hdr(char *buff, ip_hdr_t *ip_hdr, uint32_t pkt_size, int tab_count){

     int rc = 0;
     char ip1[16];
     char ip2[16];

     tcp_ip_covert_ip_n_to_p(ip_hdr->src_ip, ip1);
     tcp_ip_covert_ip_n_to_p(ip_hdr->dst_ip, ip2);

     rc +=  sprintf(buff + rc, "\n-IP Hdr --------\n");
     rc +=  sprintf(buff + rc, "\tversion    : %u\n"
                      "\tihl     : %u\n"
                      "\ttos     : %d\n"
                      "\ttotal_length : %d\n"
                      "\tttl      : %d\n"
                      "\tprotocol : %s\n"
                      "\tsrc_ip   : %s\n"
                      "\tdst_ip   : %s",
                      ip_hdr->version,
                      ip_hdr->ihl,
                      ip_hdr->tos,
                      IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr),
                      ip_hdr->ttl,
                      string_ip_hdr_protocol_val(ip_hdr->protocol),
                      ip1, ip2);

    switch(ip_hdr->protocol){

        case ICMP_PRO:
            rc += tcp_dump_appln_hdr(buff + rc, INCREMENT_IPHDR(ip_hdr), 
                    IP_HDR_PAYLOAD_SIZE(ip_hdr), tab_count + 1);
            break;
        default:
            ;
    }
    return rc;
}

static int
tcp_dump_arp_hdr(char *buff, arp_hdr_t *arp_hdr, 
                  uint32_t pkt_size, int tab_count){

    int rc = 0;
    rc += sprintf(buff, "\n-ARP Hdr --------\n");
    rc += sprintf(buff + rc, "\thw_type : %d\n", arp_hdr->hw_type);
    rc += sprintf(buff + rc, "\tproto_type : %0x\n", arp_hdr->proto_type);
    rc += sprintf(buff + rc, "\thw_addr_len : %d\n", arp_hdr->proto_addr_len);
    rc += sprintf(buff + rc, "\top_code : %s\n", string_arp_hdr_type(arp_hdr->op_code));
    rc += sprintf(buff + rc, "\tsrc mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_hdr->src_mac.mac[0],
            arp_hdr->src_mac.mac[1],
            arp_hdr->src_mac.mac[2],
            arp_hdr->src_mac.mac[3],
            arp_hdr->src_mac.mac[4],
            arp_hdr->src_mac.mac[5]);
    rc += sprintf(buff + rc, "\tsrc ip : %s\n", 
            tcp_ip_covert_ip_n_to_p(arp_hdr->src_ip, 0));
    rc += sprintf(buff + rc, "\tdst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_hdr->dst_mac.mac[0],
            arp_hdr->dst_mac.mac[1],
            arp_hdr->dst_mac.mac[2],
            arp_hdr->dst_mac.mac[3],
            arp_hdr->dst_mac.mac[4],
            arp_hdr->dst_mac.mac[5]);
    rc += sprintf(buff + rc, "\tdst ip : %s",
            tcp_ip_covert_ip_n_to_p(arp_hdr->dst_ip, 0));
    return rc;
}

static int
tcp_dump_ethernet_hdr(char *buff, ethernet_hdr_t *eth_hdr, 
                        uint32_t pkt_size, int tab_count){

    int rc = 0;
    uint32_t payload_size = pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(eth_hdr) \
                            - ETH_FCS_SIZE;

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);

    rc +=  sprintf(buff + rc, "\n-Ethernet Hdr --------\n");
    rc += sprintf(buff + rc, "\tDst Mac : %02x:%02x:%02x:%02x:%02x:%02x\n"
            "\tSrc Mac : %02x:%02x:%02x:%02x:%02x:%02x \n"
            "\tType : %-4s\n\tVlan : %-4d\n\tFCS : %-6d\n\tPayload Size = %u",
            eth_hdr->dst_mac.mac[0],
            eth_hdr->dst_mac.mac[1],
            eth_hdr->dst_mac.mac[2],
            eth_hdr->dst_mac.mac[3],
            eth_hdr->dst_mac.mac[4],
            eth_hdr->dst_mac.mac[5],

            eth_hdr->src_mac.mac[0],
            eth_hdr->src_mac.mac[1],
            eth_hdr->src_mac.mac[2],
            eth_hdr->src_mac.mac[3],
            eth_hdr->src_mac.mac[4],
            eth_hdr->src_mac.mac[5],

            string_ethernet_hdr_type(eth_hdr->type),

            vlan_8021q_hdr ? GET_802_1Q_VLAN_ID(vlan_8021q_hdr) : 0,

            vlan_8021q_hdr ? VLAN_ETH_FCS(eth_hdr, payload_size) : \
                ETH_FCS(eth_hdr, payload_size) , 
            
            payload_size);

    switch(eth_hdr->type){

        case ETH_IP:
            rc += tcp_dump_ip_hdr(buff + rc, 
                    (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                     payload_size, tab_count + 1);
            break;
        case ARP_MSG:
            rc += tcp_dump_arp_hdr(buff + rc,
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                    payload_size, tab_count + 1);
            break;
        default:
            ;
    }
    return rc;
}

static void 
tcp_write_data(int sock_fd, 
               FILE *log_file1, FILE *log_file2, 
               char *out_buff, uint32_t buff_size){

    int rc; 
    char error_msg[64];

    assert(out_buff);

    if(buff_size > TCP_PRINT_BUFFER_SIZE){
        rc  = sprintf(error_msg , "Error : Insufficient size TCP Print Buffer\n");
        assert(rc < sizeof(error_msg));
        fwrite(error_msg, sizeof(char), rc, log_file1);
        fwrite(error_msg, sizeof(char), rc, log_file2);
        write(sock_fd, error_msg, rc);
        return;
    }

    if(log_file1){
        rc = fwrite(out_buff, sizeof(char), buff_size, log_file1);
        /* The below fflush may impact performance as it will flush the
         * data from internal buffer memory onto the disk immediately*/
        fflush(log_file1);
    }

    if(log_file2){
        rc = fwrite(out_buff, sizeof(char), buff_size, log_file2);
        /* The below fflush may impact performance as it will flush the
         * data from internal buffer memory onto the disk immediately*/
        fflush(log_file2);
    }
    
    if(sock_fd == -1)
        return; 

    write(sock_fd, out_buff, buff_size);
}

static void
tcp_dump(int sock_fd, 
         FILE *log_file1,
         FILE *log_file2,
         char *pkt, 
         uint32_t pkt_size, 
         hdr_type_t hdr_type,
         char *out_buff, 
         uint32_t out_buff_size){

    int rc = 0, new_rc = 0;
    
    rc += sprintf(out_buff + rc, 
            "\n===========Pkt Contents Begin================\n");

    switch(hdr_type){

        case ETH_HDR:
            new_rc = tcp_dump_ethernet_hdr(out_buff + rc, 
                (ethernet_hdr_t *)pkt, pkt_size, 0);
            break;
        case IP_HDR:
            new_rc = tcp_dump_ip_hdr(out_buff + rc, 
                (ip_hdr_t *)pkt, pkt_size, 0);
            break;
        default:
            ;
    }

    if(!new_rc){
        return;
    }

    rc += new_rc;
    rc += sprintf(out_buff + rc, 
            "\n===========Pkt Contents Ends================\n");
    
    tcp_write_data(sock_fd, log_file1, log_file2, out_buff, rc);
}

void
tcp_dump_recv(node_t *node, interface_t *intf,
              char *pkt, uint32_t pkt_size,
              hdr_type_t hdr_type){

    if(node->log_info.all || 
        node->log_info.recv ||
        intf->log_info.recv){

        int sock_fd = (node->log_info.is_stdout || 
                        intf->log_info.is_stdout) ? STDOUT_FILENO : -1;
        
        FILE *log_file1 = (node->log_info.all || node->log_info.recv) ?
                node->log_info.log_file : NULL;
        FILE *log_file2 = (intf->log_info.recv || intf->log_info.all) ?
                intf->log_info.log_file : NULL;

        init_tcp_print_buffer();

        tcp_dump(sock_fd,                  /*Write the log to the FD*/
                 log_file1,                /*Write the log to the node's log file*/
                 log_file2,                /*Write the log to the interface log file*/
                 pkt, pkt_size,            /*Pkt and Pkt size to be written in log file*/
                 hdr_type,                 /*Starting hdr type of the pkt*/
                 tcp_print_buffer,         /*Buffer into which the formatted output is to be written*/
                 TCP_PRINT_BUFFER_SIZE);   /*Buffer Max Size*/
    }
}

void
tcp_dump_send(node_t *node, interface_t *intf,
              char *pkt, uint32_t pkt_size,
              hdr_type_t hdr_type){

    if(node->log_info.all || 
         node->log_info.send ||
         intf->log_info.send){

        int sock_fd = (node->log_info.is_stdout || 
                        intf->log_info.is_stdout) ? STDOUT_FILENO : -1;

        FILE *log_file1 = (node->log_info.all || node->log_info.send) ?
                node->log_info.log_file : NULL;
        FILE *log_file2 = (intf->log_info.send || intf->log_info.all) ? 
                intf->log_info.log_file : NULL;
        
        init_tcp_print_buffer();

        tcp_dump(sock_fd,                  /*Write the log to the FD*/
                 log_file1,                /*Write the log to the node's log file*/
                 log_file2,                /*Write the log to the interface log file*/
                 pkt, pkt_size,            /*Pkt and Pkt size to be written in log file*/
                 hdr_type,                 /*Starting hdr type of the pkt*/
                 tcp_print_buffer,         /*Buffer into which the formatted output is to be written*/
                 TCP_PRINT_BUFFER_SIZE);   /*Buffer Max Size*/
    }
}

static FILE *
initialize_node_log_file(node_t *node){

    char file_name[32];

    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s.txt", node->node_name);

    FILE *fptr = fopen(file_name, "w");

    if(!fptr){
        printf("Error : Could not open log file %s\n", file_name);
        return 0;
    }

    return fptr;
}

static FILE *
initialize_interface_log_file(interface_t *intf){

    char file_name[64];

    memset(file_name, 0, sizeof(file_name));

    node_t *node = intf->att_node;

    sprintf(file_name, "logs/%s-%s.txt", node->node_name, intf->if_name);

    FILE *fptr = fopen(file_name, "w");

    if(!fptr){
        printf("Error : Could not open log file %s\n", file_name);
        return 0;
    }

    return fptr;
}

void
tcp_ip_init_node_log_info(node_t *node){

    log_t *log_info = &node->log_info;
    log_info->all = FALSE;
    log_info->recv = FALSE;
    log_info->send = FALSE;
    log_info->is_stdout = FALSE;
    log_info->log_file = initialize_node_log_file(node); 
}

void
tcp_ip_init_intf_log_info(interface_t *intf){
    
    log_t *log_info = &intf->log_info;
    log_info->all = FALSE;
    log_info->recv = FALSE;
    log_info->send = FALSE;
    log_info->is_stdout = FALSE;
    log_info->log_file = initialize_interface_log_file(intf);
}

static void display_expected_flag(param_t *param, ser_buff_t *tlv_buf){

    printf(" : all | no-all\n");
    printf(" : recv | no-recv\n");
    printf(" : send | no-send\n");
    printf(" : stdout | no-stdout\n");
}

int
validate_flag_values(char *value){

    if((strncmp(value, "all", strlen("all")) ==        0     && strlen("all") == strlen(value))             || 
        (strncmp(value, "no-all", strlen("no-all")) == 0     && strlen("no-all") == strlen(value))          ||
        (strncmp(value, "recv", strlen("recv")) ==     0     && strlen("recv") == strlen(value))            ||
        (strncmp(value, "no-recv", strlen("no-recv")) == 0   && strlen("no-recv") == strlen(value))         ||
        (strncmp(value, "send", strlen("send")) ==       0   && strlen("send") == strlen(value))            ||
        (strncmp(value, "no-send", strlen("no-send")) == 0   && strlen("no-send") == strlen(value))         ||
        (strncmp(value, "stdout", strlen("stdout")) ==   0   && strlen("stdout") == strlen(value))          ||
        (strncmp(value, "no-stdout", strlen("no-stdout")) == 0 && strlen("no-stdout") == strlen(value))){
        return VALIDATION_SUCCESS;
    }
    return VALIDATION_FAILED;
}

static int traceoptions_handler(param_t *param, 
                                ser_buff_t *tlv_buf, 
                                op_mode enable_or_disable){

    return 0;
}

static node_t *
tcp_ip_build_node_traceoptions_cli(param_t *node_name_param){

    {
        static param_t traceoptions;
        init_param(&traceoptions, CMD, "traceoptions", 0, 0, INVALID, 0, "traceoptions");
        libcli_register_param(node_name_param, &traceoptions);
        {
            static param_t flag;
            init_param(&flag, CMD, "flag", 0, 0, INVALID, 0, "flag");
            libcli_register_param(&traceoptions, &flag);
            libcli_register_display_callback(&flag, display_expected_flag);
            {
                static param_t flag_val;
                init_param(&flag_val, LEAF, 0, traceoptions_handler, validate_flag_values, STRING, "flag-val", 
                    "<all | no-all | recv | no-recv | send | no-send | stdout | no-stdout>");
                libcli_register_param(&flag, &flag_val);
                set_param_cmd_code(&flag_val, CMDCODE_DEBUG_LOGGING_PER_NODE);
            }
        }
    }

}

static void
tcp_ip_build_intf_traceoptions_cli(node_t *node, param_t *intf_name_param){

}


/*CLI handlers*/
extern void tcp_ip_traceoptions_cli(param_t *node_name_param,
                                 param_t *intf_name_param){

    node_t *node = NULL;

    assert(!node_name_param || !intf_name_param);
    if(node_name_param){
        node = tcp_ip_build_node_traceoptions_cli(node_name_param);
    }
    if(intf_name_param){
        tcp_ip_build_intf_traceoptions_cli(node, intf_name_param);
    }
}
