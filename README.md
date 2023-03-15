## root net namespace 数据包控制框架

#### 依赖:

cilium/ebpf [0.10.0](https://github.com/cilium/ebpf) 2023/2/5

atadog/ebpf/manager [v1.0.3](https://github.com/DataDog/ebpf-manager)

[go-bindata](https://github.com/shuLhan/go-bindata/cmd/go-bindata) 用于生成ebpf字节码文件的go包

```bash
go get -d github.com/shuLhan/go-bindata/cmd/go-bindata
```



#### 使用:

编译:

```bash
$ make build-ebpf
$ make build
```

运行:

```bash
root@211:~/# ./bin/main
INFO[0000] successfully started, head over to /sys/kernel/debug/tracing/trace_pipe
INFO[0000] Hash(redirect_map)#7 contains 3882 at key 192.168.81.212
INFO[0000] Hash(redirect_map)#7 contains 3880 at key 192.168.81.170
^C
root@211:~/#
```

验证:

```bash
root@test-1:~# ping 192.168.81.212 -c10
PING 192.168.81.212 (192.168.81.212) 56(84) bytes of data.
64 bytes from 192.168.81.212: icmp_seq=1 ttl=64 time=1.52 ms
64 bytes from 192.168.81.212: icmp_seq=2 ttl=64 time=0.425 ms
64 bytes from 192.168.81.212: icmp_seq=3 ttl=64 time=0.328 ms
64 bytes from 192.168.81.212: icmp_seq=4 ttl=64 time=0.351 ms
64 bytes from 192.168.81.212: icmp_seq=5 ttl=64 time=0.380 ms
64 bytes from 192.168.81.212: icmp_seq=6 ttl=64 time=0.392 ms
64 bytes from 192.168.81.212: icmp_seq=7 ttl=64 time=0.414 ms
64 bytes from 192.168.81.212: icmp_seq=8 ttl=64 time=0.446 ms
64 bytes from 192.168.81.212: icmp_seq=9 ttl=64 time=0.371 ms
64 bytes from 192.168.81.212: icmp_seq=10 ttl=64 time=0.388 ms

--- 192.168.81.212 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9195ms
rtt min/avg/max/mdev = 0.328/0.501/1.524/0.342 ms
root@test-1:~# client_loop: send disconnect: Broken pipe
```

```bash
root@211:~/ebpfmanager/examples/programs/xdp# tail /sys/kernel/debug/tracing/trace
   vhost-1296496-1296512 [032]  3609473.993477: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [032]  3609474.995277: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [032]  3609476.020765: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [032]  3609477.044018: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [032]  3609478.068006: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [040]  3609479.092022: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [040]  3609480.116132: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [040]  3609481.140042: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [040]  3609482.164033: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
   vhost-1296496-1296512 [040]  3609483.187993: bpf_trace_printk: tcp_v4_connect dest IP: d451a8c0 with if index 3882
```

增加新功能:

1. 增加新的 ebpf kernel func 之后, 需要在 manager probe 注册. 之后才会进入自动加载过程. map 也是一样. 一个manager 可以同时启动多个 probe.
2. 可以针对 UUID-funcName 的组合来关闭特定的 probe.

TODO:

1. 增加 tc/ingress 使用 bpf_redirect_peer 的部分内容.

2. 性能比较结果



#### 说明:

ebpfmanager 的基本思路是将 obj 文件通过 go-bindata 转换为 golang 源码. 然后通过 golang 接口将转换后的 ebpf 程序通过 netlink/unix 库完成 attach 过程. 和 cilium/ebpf 通过 syscal 的方式略有不同. 

ebpfmanager 基本思想和使用方法相较 ebpf/cilium 更为简单直接. 所以选用了这个库.

manager probe 包含了 tc/xdp 类型的 ebpf 程序的 load/attach/remove 流程. manager map 也是一样. 但是初始化 probe 时需要注意以下问题:

1. probe section 需要小写.
2. 当需要相同的 ebpf 程序注入到不同的位置时, 需要定义 UID 来进行区分. 有必要的情况下还需要记录这个值.
3. 依然可以使用 cilium/ebpf 提供的方法来操作, 例如对 map 的 CRUD.