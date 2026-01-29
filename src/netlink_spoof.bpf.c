// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define RTM_NEWLINK 16
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFNAMSIZ 16

const unsigned char fake_mac[6] = {0xa4, 0x5e, 0x60, 0x12, 0x34, 0x56};

struct nlmsghdr_simple {
    __u32 nlmsg_len;
    __u16 nlmsg_type;
    __u16 nlmsg_flags;
    __u32 nlmsg_seq;
    __u32 nlmsg_pid;
};

struct rtattr_simple {
    unsigned short rta_len;
    unsigned short rta_type;
};

// Store buffer pointers between entry and exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, unsigned long);
} buffers SEC(".maps");

// Simple helper to modify buffer
static __always_inline int modify_mac_in_buffer(unsigned long buf_ptr)
{
    struct nlmsghdr_simple nlh = {};
    if (bpf_probe_read_user(&nlh, sizeof(nlh), (void *)buf_ptr) < 0) {
        return 0;
    }
    
    if (nlh.nlmsg_type != RTM_NEWLINK) {
        return 0;
    }
    
    bpf_printk("RTM_NEWLINK! len=%u", nlh.nlmsg_len);
    
    // Skip headers: nlmsghdr(16) + ifinfomsg(16)
    unsigned long pos = buf_ptr + 32;
    unsigned long end = buf_ptr + nlh.nlmsg_len;
    
    bool is_eth0 = false;
    
    #pragma unroll
    for (int i = 0; i < 40; i++) {
        if (pos + 4 > end) break;
        
        struct rtattr_simple rta = {};
        if (bpf_probe_read_user(&rta, sizeof(rta), (void *)pos) < 0) break;
        
        if (rta.rta_len < 4 || rta.rta_len > 1024) break;
        
        if (rta.rta_type == IFLA_IFNAME) {
            char name[8] = {};
            bpf_probe_read_user(name, 8, (void *)(pos + 4));
            if (name[0]=='e' && name[1]=='t' && name[2]=='h' && name[3]=='0') {
                is_eth0 = true;
                bpf_printk("Found eth0");
            }
        }
        else if (rta.rta_type == IFLA_ADDRESS && is_eth0) {
            unsigned char orig[6];
            bpf_probe_read_user(orig, 6, (void *)(pos + 4));
            bpf_printk("MAC: %02x:%02x:%02x...", orig[0], orig[1], orig[2]);
            
            if (bpf_probe_write_user((void *)(pos + 4), fake_mac, 6) == 0) {
                bpf_printk("SPOOFED!");
                return 1;
            }
        }
        
        pos += (rta.rta_len + 3) & ~3;
    }
    
    return 0;
}

// Hook recvmsg - ENTRY stores msghdr pointer
SEC("kprobe/__x64_sys_recvmsg")
int BPF_KPROBE(recvmsg_entry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // For __x64_sys_* wrappers, args are in pt_regs struct passed as first param
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long msghdr_ptr;
    bpf_probe_read_kernel(&msghdr_ptr, sizeof(msghdr_ptr), &PT_REGS_PARM2(regs));
    
    bpf_map_update_elem(&buffers, &pid_tgid, &msghdr_ptr, BPF_ANY);
    return 0;
}

// Hook recvmsg - EXIT modifies buffer
SEC("kretprobe/__x64_sys_recvmsg")
int BPF_KRETPROBE(recvmsg_exit, long ret)
{
    if (ret <= 0) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    unsigned long *msghdr_ptr_p = bpf_map_lookup_elem(&buffers, &pid_tgid);
    if (!msghdr_ptr_p) return 0;
    
    unsigned long msghdr_ptr = *msghdr_ptr_p;
    bpf_map_delete_elem(&buffers, &pid_tgid);
    
    // Read msghdr -> iovec -> buffer
    struct {
        void *iov_base;
        unsigned long iov_len;
    } iov;
    
    struct {
        void *msg_name;
        int msg_namelen;
        void *msg_iov;
        unsigned long msg_iovlen;
    } mh;
    
    if (bpf_probe_read_user(&mh, sizeof(mh), (void *)msghdr_ptr) < 0) return 0;
    if (!mh.msg_iov) return 0;
    
    if (bpf_probe_read_user(&iov, sizeof(iov), mh.msg_iov) < 0) return 0;
    if (!iov.iov_base) return 0;
    
    modify_mac_in_buffer((unsigned long)iov.iov_base);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";