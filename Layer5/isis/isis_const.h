#ifndef __ISIS_CONST_H__
#define __ISIS_CONST_H__

#define ISIS_ETH_PKT_TYPE           131 // ( Randomly CHosen, No logic)
// X Values
#define ISIS_PTP_HELLO_PKT_TYPE     17 // As per standard
#define ISIS_LSP_PKT_TYPE           18 // As per standard

#define ISIS_DEFAULT_HELLO_INTERVAL 3 // Default hello time interval
#define ISIS_DEFAULT_INTF_COST      10 // Default interface cost

#define ISIS_HOLD_TIME_FACTOR       2 // hold_time interval is a 
                                    //value obtained by multiplying 
                                    //hello interval configured on an interface 
                                    //by some constant factor, 
                                    //in this case we have taken it as 2.

/*ISIS TLVs*/
#define ISIS_TLV_HOSTNAME   137 // As per standard
#define ISIS_TLV_RTR_ID     134 // As per standard
#define ISIS_TLV_IF_IP      132 // As per standard
#define ISIS_TLV_HOLD_TIME  5
#define ISIS_TLV_METRIC_VAL 6
#define ISIS_TLV_IF_INDEX   4 // As per standard
#define ISIS_TLV_MAC_ADDR   112

#endif