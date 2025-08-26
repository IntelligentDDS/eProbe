#include "./include/vmlinux.h"
#include "./include/bpf_tracing.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define BUFF_DATA_LEN 20
#define EXPORT_DURATION 300000000000 // 5* 60s * 1 000 000 000 ns = 5min

#define DDSKETCH_M 640
// #define DDSKETCH_ALPHA 1 // 表示0.01
#define DDSKETCH_GAMMA 102
#define READY_CONNECTION_THRESHOLD 1500
#define RESPONSE_RATE_THRESHOLD 2 // 实际阈值为 threshold / 10
#define ERROR_THRESHOLD_PERCENT 9 // 实际比例为 threshold / 10

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

char ____license[] SEC("license") = "GPL";
int _version SEC("version") = 1;

// alpha = 0.01, m = 512, 一定能够装下10s以内的延时的值（10000ms * 100）
struct ddskectch_bucket {
    __u32 bucket[DDSKETCH_M];
    __u32 total_cnt;
    __u32 p70_index;
    __u32 p90_index;
} __attribute__((packed));


static char HTTP_HEADER[6] = {'H', 'T', 'T', 'P'};
static __u64 metric_last_update_timestamp = 0;
static struct ddskectch_bucket empty_bucket = {.bucket = {0}, .total_cnt = 0, .p70_index = 0, .p90_index = 0};

// ringbuffer
struct ringbuff_event{
    __u32 ip4;           // not ready ip
    __u16 reason_type;   // reason type: 1 - response time, 2 - response ratio, 3 - connection, 4 - error rate
} __attribute__((packed));

// 记录地址(ip:port)
struct ip_port{
    __u32 ip4;
    __u16 port;
} __attribute__((packed));

struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct socket_tuple {
    __u32 sip4;
    __u32 dip4;
    __u16 sport;
    __u16 dport;
} __attribute__((packed));

struct packets_len_count {
    __u32 total_count;
    __u32 large_count; // 数据包大于66 74的有内容的数据包，认为可能是HTTP包
} __attribute__((packed));

// 解析格式 大数格式解析
struct my_tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__u16	doff:4,
		res1:4,	// tcp包长度
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};



// 记录当前连接数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, __u32);  // connections数目
    __uint(max_entries, 1000);
} ip_connections_map SEC(".maps");

// 记录当前HTTP错误率
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, __u32);  // 发送的HTTP包正常的总数
    __uint(max_entries, 1000);
} http_correct_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, __u32);  // 发送的HTTP包错误的数目
    __uint(max_entries, 1000);
} http_error_map SEC(".maps");

// 记录服务响应比例
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, __u32);  // 调用发送函数次数
    __uint(max_entries, 1000);
} ip_recv_cnt_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, __u32);  // 调用接收函数次数
    __uint(max_entries, 1000);
} ip_send_cnt_map SEC(".maps");

// 记录HTTP Probe的使用ip
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, __u16);  // yes: 1
    __uint(max_entries, 1000);
} http_probes_ips SEC(".maps");

// 记录TCP Probe的使用ip
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, __u16);  // yes: 1
    __uint(max_entries, 1000);
} tcp_probes_ips SEC(".maps");

// 记录kubelet与target ip的流经流量是否有超过66 74的，如果有那就是HTTP probe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, struct packets_len_count);  // yes: 1
    __uint(max_entries, 1000);
} ip_packets_len_map SEC(".maps");


// 哈希表，记录套接字四元组对应的状态
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct socket_tuple);
    __type(value, __u64);   //recv_timestamp
    __uint(max_entries, 65535);
} socket_recv_timestamp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);     // ip
    __type(value, struct ddskectch_bucket);
    __uint(max_entries, 1000);
} socket_latency_bucket_curr_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);     // ip
    __type(value, struct ddskectch_bucket);
    __uint(max_entries, 1000);
} socket_latency_bucket_prev_map SEC(".maps");


/****************************** eBPF Maps **************************/
// 哈希表，记录需要被关注的kubelet IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, int);
    __uint(max_entries, 100);
} monitoring_ip_map SEC(".maps");

// ringbuf: 获取套接字的请求延时，处理延时信息
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // 6 KB 
    __uint(max_entries, 1024 * 6);
} not_ready_ringbuf SEC(".maps");




/****************************** kprobe/tcp_set_state *****************************/
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock* sk, int state)
{
    // 获取tcp连接状态
    struct sock_common skp = BPF_CORE_READ(sk, __sk_common);
    int oldstate = skp.skc_state;

    // 获取套接字的四元组信息
    __u32 remote_addr = bpf_ntohl(skp.skc_daddr);
    __u32 local_addr = bpf_ntohl(skp.skc_rcv_saddr);
    __u16 remote_port = bpf_ntohs(skp.skc_dport);
    __u16 local_port = skp.skc_num;


    if(state == TCP_ESTABLISHED){    // 连接成功 可以发送数据
        // 增加连接数
        __u32 * connection_cnt_ptr = bpf_map_lookup_elem(&ip_connections_map, &local_addr);
        if(connection_cnt_ptr){
            *connection_cnt_ptr  += 1;
            bpf_map_update_elem(&ip_connections_map, &local_addr, connection_cnt_ptr, BPF_EXIST);
        }else{
            __u32 temp_connection_cnt = 1;
            bpf_map_update_elem(&ip_connections_map, &local_addr, &temp_connection_cnt, BPF_NOEXIST);
        }
    }

    if(state == TCP_CLOSE){    // 连接关闭
        // 减少连接数
        __u32 * connection_cnt_ptr = bpf_map_lookup_elem(&ip_connections_map, &local_addr);
        if(connection_cnt_ptr){
            if(*connection_cnt_ptr > 1){
                *connection_cnt_ptr  -= 1;
                bpf_map_update_elem(&ip_connections_map, &local_addr, connection_cnt_ptr, BPF_EXIST);
            }else{
                bpf_map_delete_elem(&ip_connections_map, &local_addr);
            }
            
        }
    }

    return 0;
}



// 对应服务器发送响应包的情况
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    bpf_skb_pull_data(ctx, 0);
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
    struct tcphdr *l4;
    __u8 *l7;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;
    
    __u8 protocol = l3->protocol;
    if(protocol != 6) // TCP协议
        return TC_ACT_OK;
    
    l4 = (struct tcphdr *)(l3 + 1);
	if ((void *)(l4 + 1) > data_end)
		return TC_ACT_OK;

    __u32 src_ip = bpf_ntohl(l3->saddr);
    __u32 dst_ip = bpf_ntohl(l3->daddr);
    __u16 src_port = bpf_ntohs(l4->source);
    __u16 dst_port = bpf_ntohs(l4->dest);


    // 筛选非kubelet的数据包
    int *kubelet_probe = bpf_map_lookup_elem(&monitoring_ip_map, &dst_ip);
    if(kubelet_probe)
        return TC_ACT_OK;

    l7 = (void *) l4;
    l7 = l7 + (l4->doff * 4); // res1是tcp头部的占byte数目,为1则占4byte,以此类推。这里的长度包括tcpoptions的长度
    if ((void *)(l7 + 15) > data_end)
        return TC_ACT_OK;

    // 只要有数据就认为是响应包
    // bpf_printk("TC Ingress, skb_len = %d, ttl = %d, remain data len = %d", ctx->len, data_end - data, data_end - (void*)l7);
    
    // 记录发送接收次数
    __u32 *send_cnt_ptr = bpf_map_lookup_elem(&ip_send_cnt_map, &src_ip);
    if(send_cnt_ptr){
        *send_cnt_ptr += 1;
        bpf_map_update_elem(&ip_send_cnt_map, &src_ip, send_cnt_ptr, BPF_EXIST);
        
    }else{
        __u32 send_cnt = 1;
        bpf_map_update_elem(&ip_send_cnt_map, &src_ip, &send_cnt, BPF_NOEXIST);
    }

    // 更新error rate和响应比例, 延时bucket的相关map
    __u64 send_timestamp = bpf_ktime_get_boot_ns();
    __u64 last_timestamp = metric_last_update_timestamp;
    if(send_timestamp - metric_last_update_timestamp > EXPORT_DURATION){
        metric_last_update_timestamp = send_timestamp;
        bpf_printk("Exporting data!! metric_last_update_timestamp = %lld, send_timestamp = %lld", last_timestamp, send_timestamp);
        // 更新响应比例
        bpf_map_delete_elem(&ip_send_cnt_map, &src_ip);
        bpf_map_delete_elem(&ip_recv_cnt_map, &src_ip);
        
        // 更新错误率
        bpf_map_delete_elem(&http_correct_map, &src_ip);
        bpf_map_delete_elem(&http_error_map, &src_ip);

        // 更新延时bucket
        struct ddskectch_bucket * data_bucket = bpf_map_lookup_elem(&socket_latency_bucket_curr_map, &src_ip); 
        if(data_bucket){
            bpf_map_update_elem(&socket_latency_bucket_prev_map, &src_ip, data_bucket, BPF_ANY);
            bpf_map_delete_elem(&socket_latency_bucket_curr_map, &src_ip);
        }else{
            bpf_map_delete_elem(&socket_latency_bucket_prev_map, &src_ip);
        }
        
    }

    // 计算服务器响应请求时间
    struct socket_tuple tuple = {
        .sip4 = src_ip,
        .dip4 = dst_ip,
        .sport = src_port,
        .dport = dst_port,
    };
    __u64 *recv_timestamp = bpf_map_lookup_elem(&socket_recv_timestamp_map, &tuple);
    if(recv_timestamp){
        __u64 response_duration = send_timestamp - (*recv_timestamp); // ns
        __u64 ms_duration = response_duration / 10000; // * ms * 100，记录格式为1.01 -> 101
        __u32 server_ip = src_ip;
        
        struct ddskectch_bucket * data_bucket = bpf_map_lookup_elem(&socket_latency_bucket_curr_map, &server_ip); 
        if(data_bucket){
            // 插入元素
            __u64 bucket_left = 1; 
            __u64 bucket_right = DDSKETCH_GAMMA;
            // 元素一定能放入桶中
            for(int i = 0; i < DDSKETCH_M; i ++){
                // 找到桶
                if(ms_duration < bucket_right){
                    data_bucket->bucket[i] = data_bucket->bucket[i] + 1; 
                    data_bucket->total_cnt = data_bucket->total_cnt + 1;

                    //test 
                    __u32 temp_cnt_sum = 0;
                    __u32 p50_index = 0; 
                    __u32 p90_index = 0;
                    __u32 p50_count = data_bucket->total_cnt * 5 / 10 ;
                    __u32 p90_count = data_bucket->total_cnt * 9 / 10 ;
                    for(int i = 0; i < DDSKETCH_M; i ++){
                        temp_cnt_sum += data_bucket->bucket[i];
                        if(temp_cnt_sum >= p50_count){
                            p50_index = i;
                            break;
                        }
                    }
                    temp_cnt_sum = 0;
                    for(int i = 0; i < DDSKETCH_M; i ++){
                        temp_cnt_sum += data_bucket->bucket[i];
                        if(temp_cnt_sum >= p90_count){
                            p90_index = i;
                            break;
                        }
                    }
                    data_bucket->p70_index = p50_index;
                    data_bucket->p90_index = p90_index;

                    break;
                }
                // 找不到桶，更新桶的左右界
                bucket_left = bucket_right;
                bucket_right = bucket_right * DDSKETCH_GAMMA / 100;
            }
            bpf_map_update_elem(&socket_latency_bucket_curr_map, &server_ip, data_bucket, BPF_EXIST);
        }else{
            bpf_map_update_elem(&socket_latency_bucket_curr_map, &server_ip, &empty_bucket, BPF_NOEXIST);
            struct ddskectch_bucket * data_bucket = bpf_map_lookup_elem(&socket_latency_bucket_curr_map, &server_ip); 
            if(data_bucket){
                // 插入元素
                __u64 bucket_left = 1; 
                __u64 bucket_right = DDSKETCH_GAMMA;
                // 元素一定能放入桶中
                for(int i = 0; i < DDSKETCH_M; i ++){
                    // 找到桶
                    if(ms_duration < bucket_right){
                        data_bucket->bucket[i] = data_bucket->bucket[i] + 1;
                        data_bucket->total_cnt = data_bucket->total_cnt + 1; 

                        //test 
                        __u32 temp_cnt_sum = 0;
                        __u32 p50_index = 0; 
                        __u32 p90_index = 0;
                        __u32 p50_count = data_bucket->total_cnt * 5 / 10 ;
                        __u32 p90_count = data_bucket->total_cnt * 9 / 10 ;
                        for(int i = 0; i < DDSKETCH_M; i ++){
                            temp_cnt_sum += data_bucket->bucket[i];
                            if(temp_cnt_sum >= p50_count){
                                p50_index = i;
                                break;
                            }
                        }
                        temp_cnt_sum = 0;
                        for(int i = 0; i < DDSKETCH_M; i ++){
                            temp_cnt_sum += data_bucket->bucket[i];
                            if(temp_cnt_sum >= p90_count){
                                p90_index = i;
                                break;
                            }
                        }
                        data_bucket->p70_index = p50_index;
                        data_bucket->p90_index = p90_index;

                        break;
                    }
                    // 找不到桶，更新桶的左右界
                    bucket_left = bucket_right;
                    bucket_right = bucket_right * DDSKETCH_GAMMA / 100;
                }
                bpf_map_update_elem(&socket_latency_bucket_curr_map, &server_ip, data_bucket, BPF_EXIST);
            }
        }
        bpf_map_delete_elem(&socket_recv_timestamp_map, &tuple);
    }

	return TC_ACT_OK;
}

// 对应服务器接收请求包的过程
SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
    bpf_skb_pull_data(ctx, 0);
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
    struct tcphdr *l4;
    __u8 *l7;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

    __u8 protocol = l3->protocol;
    if(protocol != 6) // TCP协议
        return TC_ACT_OK;
    
    l4 = (struct tcphdr *)(l3 + 1);
	if ((void *)(l4 + 1) > data_end)
		return TC_ACT_OK;

    __u32 src_ip = bpf_ntohl(l3->saddr);
    __u32 dst_ip = bpf_ntohl(l3->daddr);
    __u16 src_port = bpf_ntohs(l4->source);
    __u16 dst_port = bpf_ntohs(l4->dest);


    // 筛选非kubelet的数据包
    int *kubelet_probe = bpf_map_lookup_elem(&monitoring_ip_map, &src_ip);
    if(kubelet_probe)
        return TC_ACT_OK;

    // 只要有数据就认为是请求
    if (ctx->len == data_end - data)
        return TC_ACT_OK;

    // 记录调用接收次数
    __u32 *recv_cnt_ptr = bpf_map_lookup_elem(&ip_recv_cnt_map, &dst_ip);
    if(recv_cnt_ptr){
        *recv_cnt_ptr += 1;
        bpf_map_update_elem(&ip_recv_cnt_map, &dst_ip, recv_cnt_ptr, BPF_EXIST);
    }else{
        __u32 recv_cnt = 1;
        bpf_map_update_elem(&ip_recv_cnt_map, &dst_ip, &recv_cnt, BPF_NOEXIST);
    }

    // 记录服务器接收请求时间
    __u64 recv_timestamp = bpf_ktime_get_boot_ns();
    struct socket_tuple tuple = {
        .sip4 = dst_ip,
        .dip4 = src_ip,
        .sport = dst_port,
        .dport = src_port,
    }; // 源目的四元组互换， 方便ingress找到该recv的timestamp
    bpf_map_update_elem(&socket_recv_timestamp_map, &tuple, &recv_timestamp, BPF_ANY);

    return TC_ACT_OK;
}


// 如果就绪 那就返回True；如果不是返回False
static inline 
bool judgeReady(__u32 ip){
    // 判断当前IP是否ready
    char fmt_debug_0[] = "Judging Ready: ip = %x";
    bpf_trace_printk(fmt_debug_0, sizeof(fmt_debug_0), ip);	

    // 1. error_rate > 50%（固定阈值）
    __u32 *correct_cnt_ptr = bpf_map_lookup_elem(&http_correct_map, &ip);
    __u32 *error_cnt_ptr = bpf_map_lookup_elem(&http_error_map, &ip); 
    __u32 correct_cnt = 0;
    __u32 error_cnt = 0;
    if(correct_cnt_ptr){
        correct_cnt = *correct_cnt_ptr;   
    }
    if(error_cnt_ptr){
        error_cnt = *error_cnt_ptr;   
    }
    __u32 total_cnt = error_cnt + correct_cnt;
    if(total_cnt > 50){
        __u32 error_threshold = total_cnt / 10 * ERROR_THRESHOLD_PERCENT;
        if (error_cnt >= error_threshold){
            char fmt_ready_2[] = "Judging: IP(%x), the error cnt = %d, the correct cnt = %d";	
            bpf_trace_printk(fmt_ready_2, sizeof(fmt_ready_2), ip, error_cnt, correct_cnt);
            char fmt_ready_3[] = "WARNING: IP(%x) is not Ready, for the error rate > 0.5";	
            bpf_trace_printk(fmt_ready_3, sizeof(fmt_ready_3), ip);

            struct ringbuff_event event_data = {
                .ip4 = ip,
                .reason_type = 4,
            };
            bpf_ringbuf_output(&not_ready_ringbuf, &event_data, sizeof(struct ringbuff_event), 0);
            return false;
        }
    }

    // 2. 连接数 > 固定阈值
    __u32 *connection_cnt_ptr = bpf_map_lookup_elem(&ip_connections_map, &ip);
    if(connection_cnt_ptr){
        char fmt_ready_test[] = "Status: IP(%x) connection = %d";	 
        // bpf_trace_printk(fmt_ready_test, sizeof(fmt_ready_test), ip, *connection_cnt_ptr);
    }
    if(connection_cnt_ptr && *connection_cnt_ptr > READY_CONNECTION_THRESHOLD){
        char fmt_ready_4[] = "WARNING: IP(%x) is not Ready, for the connection count = %d > READY_CONNECTION_THRESHOLD";	
        bpf_trace_printk(fmt_ready_4, sizeof(fmt_ready_4), ip, *connection_cnt_ptr);
        struct ringbuff_event event_data = {
            .ip4 = ip,
            .reason_type = 3,
        };
        bpf_ringbuf_output(&not_ready_ringbuf, &event_data, sizeof(struct ringbuff_event), 0);
        return false;
    }

    // 3. 响应比例 < 20%（固定阈值）
    __u32 * recv_cnt_ptr = bpf_map_lookup_elem(&ip_recv_cnt_map, &ip);
    __u32 * send_cnt_ptr = bpf_map_lookup_elem(&ip_send_cnt_map, &ip);
    if(recv_cnt_ptr){
        __u32 recv_cnt = *recv_cnt_ptr;
        char fmt_ready_test[] = "IP: %x, recv_cnt = %u";	
        bpf_trace_printk(fmt_ready_test, sizeof(fmt_ready_test), ip, recv_cnt);
        if(recv_cnt > 50){
            if(send_cnt_ptr){
                __u32 send_cnt = *send_cnt_ptr;
                __u32 response_rate = send_cnt * 10 / recv_cnt;
                char fmt_ready_test_2[] = "IP: %x, send_cnt = %u, response rate = %d";	
                bpf_trace_printk(fmt_ready_test_2, sizeof(fmt_ready_test_2), ip, send_cnt, response_rate);
                if (response_rate <= RESPONSE_RATE_THRESHOLD){
                    char fmt_ready_5[] = "WARNING: IP(%x) is not Ready, for the response rate < 0.2";	
                    bpf_trace_printk(fmt_ready_5, sizeof(fmt_ready_5), ip);
                    struct ringbuff_event event_data = {
                        .ip4 = ip,
                        .reason_type = 2,
                    };
                    bpf_ringbuf_output(&not_ready_ringbuf, &event_data, sizeof(struct ringbuff_event), 0);
                    return false;
                }
            }else{
                char fmt_ready_5[] = "WARNING: IP(%x) is not Ready, for the response rate = 0";	
                bpf_trace_printk(fmt_ready_5, sizeof(fmt_ready_5), ip);
                struct ringbuff_event event_data = {
                    .ip4 = ip,
                    .reason_type = 2,
                };
                bpf_ringbuf_output(&not_ready_ringbuf, &event_data, sizeof(struct ringbuff_event), 0);
                return false;
            }
        }
    } 
    // 4. 响应延时（30%的请求超过前一段时间的P90）即当前的P70 > 上一个时间段的P90
    struct ddskectch_bucket* data_curr_bucket = bpf_map_lookup_elem(&socket_latency_bucket_curr_map, &ip);
    struct ddskectch_bucket* data_prev_bucket = bpf_map_lookup_elem(&socket_latency_bucket_prev_map, &ip);
    if(data_curr_bucket && data_prev_bucket){
        if(data_curr_bucket->total_cnt > 50 && data_prev_bucket->total_cnt > 50){
            // 数目大于50才进行判断
            __u32 prev_p90_index = data_prev_bucket->p90_index;
            __u32 curr_p70_index = data_curr_bucket->p70_index;

            char fmt_ready_8[] = "(IP = %x) Sketch: curr_p70_index = %d, prev_p90_index = %d";	
            bpf_trace_printk(fmt_ready_8, sizeof(fmt_ready_8), ip, curr_p70_index, prev_p90_index);

            if (curr_p70_index >= prev_p90_index){
                char fmt_ready_6[] = "WARNING: IP(%x) is not Ready, for the P70 >= P90";	
                bpf_trace_printk(fmt_ready_6, sizeof(fmt_ready_6), ip);
                struct ringbuff_event event_data = {
                    .ip4 = ip,
                    .reason_type = 1,
                };
                bpf_ringbuf_output(&not_ready_ringbuf, &event_data, sizeof(struct ringbuff_event), 0);

                return false;

            }

        }
    }
    
    return true;
}


SEC("xdp")
int xdp_cni0_prog(struct xdp_md* ctx){
	// bpf_printk("Hello");
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int packet_size = data_end - data;
	struct ethhdr *l2;
	struct iphdr *l3;
    struct my_tcphdr *l4;
    __u8 *l7;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return XDP_PASS;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return XDP_PASS;

    __u8 protocol = l3->protocol;
    if(protocol != 6) // TCP协议
        return XDP_PASS;
    
    l4 = (struct my_tcphdr *)(l3 + 1);
	if ((void *)(l4 + 1) > data_end)
		return XDP_PASS;

    l7 = (void *) l4;
    l7 = l7 + (l4->res1 * 4); // res1是tcp头部的占byte数目,为1则占4byte,以此类推。这里的长度包括tcpoptions的长度
            

    __u32 src_ip = bpf_ntohl(l3->saddr);
    __u32 dst_ip = bpf_ntohl(l3->daddr);
    __u16 src_port = bpf_ntohs(l4->source);
    __u16 dst_port = bpf_ntohs(l4->dest);


    int *kubelet_probe_return = bpf_map_lookup_elem(&monitoring_ip_map, &dst_ip);
    if(!kubelet_probe_return){
        // 非探针包，需要统计不同服务的错误率
        
        if ((void *)(l7 + BUFF_DATA_LEN) > data_end)
            return XDP_PASS;

        __u8 temp_data[BUFF_DATA_LEN];
        __builtin_memcpy(temp_data, l7, BUFF_DATA_LEN);

        // 判断如果是HTTP包
        if(temp_data[0] == 'H' && temp_data[1] == 'T' && temp_data[2] == 'T' && temp_data[3] == 'P'){
            // 是HTTP协议，读取响应码
            unsigned int first_index_space = 0;
            unsigned int i = 0;
            for(i = 0; i < BUFF_DATA_LEN; i ++){
                if (temp_data[i] == ' '){
                    first_index_space = i;
                    break;
                }
            }
            if(first_index_space > 0 && first_index_space + 1 < BUFF_DATA_LEN){
                // 正常的次数
                if (temp_data[first_index_space + 1] == '2'){
                    __u32 *correct_cnt_ptr = bpf_map_lookup_elem(&http_correct_map, &src_ip);
                    if(correct_cnt_ptr){
                        __u32 correct_cnt = *correct_cnt_ptr;
                        correct_cnt =  correct_cnt + 1;
                        int ret = bpf_map_update_elem(&http_correct_map, &src_ip, &correct_cnt, BPF_ANY);
                    }else{
                        __u32 correct_cnt = 1;
                        int ret = bpf_map_update_elem(&http_correct_map, &src_ip, &correct_cnt, BPF_ANY);
                    }
                    
                }
                // 错误的次数
                if (temp_data[first_index_space + 1] == '5'){
                    __u32 *error_cnt_ptr = bpf_map_lookup_elem(&http_error_map, &src_ip);
                    if(error_cnt_ptr){
                        *error_cnt_ptr += 1;
                        bpf_map_update_elem(&http_error_map, &src_ip, error_cnt_ptr, BPF_EXIST);
                    }else{
                        __u32 error_cnt = 1;
                        bpf_map_update_elem(&http_error_map, &src_ip, &error_cnt, BPF_NOEXIST);
                    }
                }
            }
        }
        // 如果是mysql包
        if(temp_data[1] == 0 && temp_data[2] == 0 && temp_data[3] == 1 ){
            // 错误的次数
            if (temp_data[4] == 0xff){  // 错误码
                __u32 *error_cnt_ptr = bpf_map_lookup_elem(&http_error_map, &src_ip);
                if(error_cnt_ptr){
                    *error_cnt_ptr += 1;
                    bpf_map_update_elem(&http_error_map, &src_ip, error_cnt_ptr, BPF_EXIST);
                }else{
                    __u32 error_cnt = 1;
                    bpf_map_update_elem(&http_error_map, &src_ip, &error_cnt, BPF_NOEXIST);
                }
            }
            else{
                __u32 *correct_cnt_ptr = bpf_map_lookup_elem(&http_correct_map, &src_ip);
                if(correct_cnt_ptr){
                    __u32 correct_cnt = *correct_cnt_ptr;
                    correct_cnt =  correct_cnt + 1;
                    int ret = bpf_map_update_elem(&http_correct_map, &src_ip, &correct_cnt, BPF_ANY);
                }else{
                    __u32 correct_cnt = 1;
                    int ret = bpf_map_update_elem(&http_correct_map, &src_ip, &correct_cnt, BPF_ANY);
                }
                
            }
            
        }

        return XDP_PASS;
    }

    // 探针包处理
    bool is_ready = judgeReady(src_ip);
    
    // 判断是HTTP probe模式还是 tcp probe 模式
    __u16 *is_tcp_probe = bpf_map_lookup_elem(&tcp_probes_ips, &src_ip);
    if(is_tcp_probe){

        // 判断是否就绪
        if(is_ready){
            return XDP_PASS;
        }else{
            char fmt1[] = "TCP probe : (ip)from %x -> %x, not ready";	
	        bpf_trace_printk(fmt1, sizeof(fmt1), src_ip, dst_ip);
            return XDP_DROP;
        }
    }

    __u16 *is_http_probe = bpf_map_lookup_elem(&http_probes_ips, &src_ip);
    if(is_http_probe){
        // 判断是否就绪
        if(is_ready){
            return XDP_PASS;
        }else{
            char fmt1[] = "HTTP probe : (ip)from %x -> %x, not ready";	
	        // bpf_trace_printk(fmt1, sizeof(fmt1), src_ip, dst_ip);
            if ((void *)(l7 + 100) > data_end)
                return XDP_PASS;

            // 尝试修改http返回码
            if(*(l7+0) == 'H' && *(l7+1) == 'T' && *(l7+2) == 'T' && *(l7+3) == 'P'){
                // 是HTTP数据包
                __u8 modify_index = 0;
                char fmt5[] = "Return code = %x, %x, %x";	

                for(int i = 4; i < 20; i ++){
                    // 如果是200返回码 修改为500
                    if((void *) (l7 + i + 2) < data_end  && *(l7+i) == '2' && *(l7+i+1) == '0' && *(l7+i+2) == '0') {
                        modify_index = i;
                        bpf_trace_printk(fmt5, sizeof(fmt5), *(l7+i), *(l7+i+1), *(l7+i+2));
                        break;
                    }
                }

                l7 = l7 + modify_index;
                if ((void *)(l7 + 2) > data_end)
                    return XDP_PASS;

                __u8 modify_return_code[1] = {'5'};
                __builtin_memcpy(l7, modify_return_code, 1);
            }
            return XDP_PASS;
        }
    }

    // 统计探针包不同长度的数据包数目，如果有超过100长度的数据包，那么认为是http probe
    struct packets_len_count *ip_packet_cnt_ptr = bpf_map_lookup_elem(&ip_packets_len_map, &src_ip);
    if(ip_packet_cnt_ptr){
        __u32 total_count = ip_packet_cnt_ptr->total_count;
        __u32 large_count = ip_packet_cnt_ptr->large_count;
        // 判断是HTTP probe 还是 TCP probe
        if(total_count > 20){
            __u16 temp_value = 1;
            if(large_count > 0){
                // HTTP Probe
                bpf_map_update_elem(&http_probes_ips, &src_ip, &temp_value, BPF_NOEXIST);
            }else{
                // TCP Probe
                bpf_map_update_elem(&tcp_probes_ips, &src_ip, &temp_value, BPF_NOEXIST);
            }
        }else{
            // 数目不足以判断 仅计数
            if(packet_size >= 150){
                ip_packet_cnt_ptr->large_count = large_count + 1;
            }
            ip_packet_cnt_ptr->total_count = total_count + 1;
            bpf_map_update_elem(&ip_packets_len_map, &src_ip, ip_packet_cnt_ptr, BPF_EXIST);
        }
    }else{
        struct packets_len_count ip_packet_cnt;
        if(packet_size >= 150){
            ip_packet_cnt.large_count = 1;
        }else{
            ip_packet_cnt.large_count = 0;
        }
        ip_packet_cnt.total_count = 1;
        bpf_map_update_elem(&ip_packets_len_map, &src_ip, &ip_packet_cnt, BPF_NOEXIST);
    }
	
	return XDP_PASS;
}

