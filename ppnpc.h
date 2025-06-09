#ifndef __PPNPC_H__
#define __PPNPC_H__

#define MAX_TRACKED_PROCESSES 1024

struct process_net_stat {
    pid_t pid;
    unsigned long packets_sent;
    unsigned long packets_received;
};

#endif // __PPNPC_H__
