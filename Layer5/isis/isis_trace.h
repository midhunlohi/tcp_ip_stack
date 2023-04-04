#ifndef __ISIS_TRACE_H__
#define __ISIS_TRACE_H__

#include "../../tcp_public.h"
#include <stdarg.h>

typedef enum log_level_t {
    LOG_DEBUG,
    LOG_WARN,
    LOG_ERROR
}log_level;

typedef enum log_type_t {
    ISIS_CONF,
    ISIS_PKT    
}log_type;

void LOG(log_level level, log_type type, node_t *node, interface_t *intf, ...);

#endif