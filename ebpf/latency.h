struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct *sk_buff);
	__type(value, struct rxlatency_t);
	__uint(max_entries, 10000);
} kernelrx_entry SEC(".maps");

struct rxlatency_t {
	u64 rcv;
	u64 rcvfinish;
	u64 local;
	u64 localfinish;
};

struct {
    __unit(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __unit(key_size, sizeof());
    __unit(value_size, sizeof());
} abna_evnt SEC(".maps");

struct {
    u32 pid;
    u32 cpu;
    u64 latency;
    struct skb_meta skb_meta;
};

struct skb_meta {
    u32 netns;
    u32 ifindex;

};