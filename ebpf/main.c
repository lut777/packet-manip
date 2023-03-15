#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "redirec.h"
#include "latency.h"

// #ifndef __section
// # define __section(NAME)                  \
//   __attribute__((section(NAME), used))
// #endif

// __section("ingress")
// SEC("ingress")
// int tc_ingress(struct __sk_buff *skb)
// {
//    bpf_printk("ingress forward sk\n");
//    return bpf_redirect(58, 0);
// }

#define THRESH 1000000

SEC("XDP")
int ingr_redirect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return XDP_PASS;
	}

	struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
		return XDP_PASS;
	}
    __be32 key = iph->daddr;
    __be32 *res = bpf_map_lookup_elem(&redirect_map, &key);
    if (res) {
        bpf_printk("tcp_v4_connect dest IP: %b with if index %d", key, *res);
//        return bpf_redirect_peer(*res, 0);
        return bpf_redirect(*res, 0);
}
    bpf_printk("tcp_v4_connect dest IP: %b", *res);
    return XDP_PASS;
};

SEC("kprobe/ip_rcv")
int ip_rcv_latency(struct pt_regs * ctx){
{
    struct sk_buff *skb = (struct *sk_buff)PT_REGS_PARM1(ctx);
    struct rxlatency_t  lat = {0};
    lat->rcv = bpf_ktime_get_ns();
    bpf_map_update_elem(&kernelrx_entry, &skb, &lat, BPF_ANY);
    return 0;
};

SEC("kprobe/ip_rcv_finish_core")
int ip_rcv_finish_latency(struct pt_regs *ctx){
{
    struct sk_buff *skb = (struct *sk_buff)PT_REGS_PARM3(ctx);
    struct rxlatency_t *lat = bpf_map_lookup_elem(&kernelrx_entry,&skb);
	if (lat) {
		lat->rcvfinish = bpf_ktime_get_ns();
		bpf_map_delete_elem(&kernelrx_entry, &skb);
		record_rx(ctx, skb, lat)
		bpf_printk("ip rcv %llu, ip rcv finish %llu\n",lat->rcv,lat->rcvfinish);
	}
    return 0;
};

static inline int record_rx(struct pt_regs *ctx , struct skb *sk_buff, struct rxlatency_t *lat){
    if (lat->rcvfinish > lat->rcv) {
        u64 latency;
        latency = lat->rcvfinish - lat->rcv;
        if ( latency > THRESH ) {

        }
    }
    return 0
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;