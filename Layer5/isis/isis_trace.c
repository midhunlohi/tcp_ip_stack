#include "isis_trace.h"

#define MAX_FMT_SIZE 200

char 
*get_log_type(log_type type) {
    switch(type) {
        case ISIS_CONF:
            return "ISIS(CONF)";
        default:
            break;
    }
}

char*
get_log_level(log_level level) {
    switch(level) {
        case LOG_DEBUG:
            return "DEBUG";
        case LOG_WARN:
            return "WARN";
        case LOG_ERROR:
            return "ERROR";
        default:
            break;
    }
}

void 
LOG(log_level level, log_type type, node_t *node, interface_t *intf, ...) {
    char buffer[MAX_FMT_SIZE];
    va_list arg;
    va_start(arg, intf);
    char const* fmt = va_arg(arg, char const*);    
    vsprintf(buffer, fmt, arg);    
    va_end(arg);
    sprintf(tlb, "%s %s %s\n", get_log_level(level), get_log_type(type), buffer);
    tcp_trace(node, intf, tlb);
}