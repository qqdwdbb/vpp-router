/* Dedicated mlx5 RX queue, exact hardware flow and bounded sequence tracking. */
#define _GNU_SOURCE
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_flow.h>
#include <rte_mbuf.h>
#include "vrouter_sequence_tracker.h"

static volatile sig_atomic_t stopped;
static uint64_t received;
static void handle(int sig) { (void)sig; stopped=1; }
static double monotonic(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return t.tv_sec+t.tv_nsec/1e9;
}
static int report(uint16_t port, const char *path) {
    struct rte_eth_stats stats;
    if (rte_eth_stats_get(port,&stats)) return -1;
    char tmp[1024];
    if (snprintf(tmp,sizeof(tmp),"%s.new",path)>=(int)sizeof(tmp)) return -1;
    FILE *f=fopen(tmp,"w"); if (!f) return -1;
    fprintf(f,"{\"method\":\"DPDK_MLX5\",\"capture_received\":%llu,\"invalid\":%llu,"
        "\"dpdk_stats\":{\"ipackets\":%llu,\"imissed\":%llu,\"ierrors\":%llu,\"rx_nombuf\":%llu},\"batches\":[",
        (unsigned long long)received,(unsigned long long)invalid,
        (unsigned long long)stats.ipackets,(unsigned long long)stats.imissed,
        (unsigned long long)stats.ierrors,(unsigned long long)stats.rx_nombuf);
    write_batches(f);
    int failed=fputs("]}\n",f)<0;
    if (fclose(f)) failed=1;
    if (failed) return -1;
    return rename(tmp,path);
}
int main(int argc, char **argv) {
    int consumed=rte_eal_init(argc,argv);
    if (consumed<0) return 1;
    argc-=consumed; argv+=consumed;
    /* Application args after EAL's --: output_json seconds destination_IP [all|vlan-id] */
    if (argc<4 || argc>5) rte_exit(2,"Expected: -- output_json seconds destination_IP [all|vlan-id]\n");
    int receive_all = argc == 5 && !strcmp(argv[4], "all");
    int vlan_id = -1;
    if (argc == 5 && !receive_all) {
        char *vlan_end;
        vlan_id = strtol(argv[4], &vlan_end, 10);
        if (*vlan_end || vlan_id < 0 || vlan_id > 4095)
            rte_exit(2, "Invalid VLAN selector\n");
    }
    char *end; long seconds=strtol(argv[2],&end,10);
    struct in_addr address;
    if (*end || seconds<1 || seconds>1800 || inet_pton(AF_INET,argv[3],&address)!=1)
        rte_exit(2,"Invalid bounded run or destination\n");
    if (rte_eth_dev_count_avail()!=1) rte_exit(2,"Allow exactly one receiver PCI device\n");
    uint16_t port; RTE_ETH_FOREACH_DEV(port) { break; }
    int status=1, started=0, configured=0;
    struct rte_flow_error error={0}; struct rte_flow *flow=NULL;
    struct rte_mempool *pool=NULL;
    if (receive_all)
        rte_eth_promiscuous_enable(port);
    else if (rte_flow_isolate(port,1,&error)) {
        fprintf(stderr,"flow isolate: %s\n",error.message?error.message:"unsupported"); goto done;
    }
    struct rte_eth_conf config={0};
    /* mlx5 also needs a configured TX queue; this program never transmits. */
    if (rte_eth_dev_configure(port,1,1,&config)) { fputs("RX configure failed\n",stderr); goto done; }
    configured=1;
    int socket=rte_eth_dev_socket_id(port); if (socket<0) socket=rte_socket_id();
    pool=rte_pktmbuf_pool_create("vrouter_rx_pool",16383,256,0,RTE_MBUF_DEFAULT_BUF_SIZE,socket);
    if (!pool) { fprintf(stderr,"mempool: %s\n",rte_strerror(rte_errno)); goto done; }
    if (rte_eth_rx_queue_setup(port,0,8192,socket,NULL,pool)) { fputs("RX queue setup failed\n",stderr); goto done; }
    if (rte_eth_tx_queue_setup(port,0,128,socket,NULL)) { fputs("TX queue setup failed\n",stderr); goto done; }
    if (rte_eth_dev_start(port)) { fputs("RX start failed\n",stderr); goto done; }
    started=1;
    if (!receive_all) {
        struct rte_flow_item_eth eth={0}, ethmask={0};
        struct rte_flow_item_vlan vlan={0}, vlanmask={0};
        struct rte_flow_item_ipv4 ip={0}, ipmask={0};
        ip.hdr.src_addr=htonl(0xcb00710a); ip.hdr.dst_addr=address.s_addr;
        ipmask.hdr.src_addr=UINT32_MAX; ipmask.hdr.dst_addr=UINT32_MAX;
        struct rte_flow_item_udp udp={0}, udpmask={0};
        /* Multi-flow tests vary the source port; keep the destination flow exact. */
        udp.hdr.src_port=0; udp.hdr.dst_port=htons(45996);
        udpmask.hdr.src_port=0; udpmask.hdr.dst_port=UINT16_MAX;
        struct rte_flow_item items[5];
        unsigned item_count = 0;
        items[item_count++] = (struct rte_flow_item){
            .type=RTE_FLOW_ITEM_TYPE_ETH,.spec=&eth,.mask=&ethmask};
        if (vlan_id >= 0) {
            vlan.hdr.vlan_tci = htons((uint16_t)vlan_id);
            vlanmask.hdr.vlan_tci = htons(0x0fff);
            items[item_count++] = (struct rte_flow_item){
                .type=RTE_FLOW_ITEM_TYPE_VLAN,.spec=&vlan,.mask=&vlanmask};
        }
        items[item_count++] = (struct rte_flow_item){
            .type=RTE_FLOW_ITEM_TYPE_IPV4,.spec=&ip,.mask=&ipmask};
        items[item_count++] = (struct rte_flow_item){
            .type=RTE_FLOW_ITEM_TYPE_UDP,.spec=&udp,.mask=&udpmask};
        items[item_count] = (struct rte_flow_item){.type=RTE_FLOW_ITEM_TYPE_END};
        struct rte_flow_action_queue queue={.index=0};
        struct rte_flow_action actions[]={
            {.type=RTE_FLOW_ACTION_TYPE_QUEUE,.conf=&queue}, {.type=RTE_FLOW_ACTION_TYPE_END}};
        struct rte_flow_attr attr={.ingress=1};
        if (rte_flow_validate(port,&attr,items,actions,&error)) {
            fprintf(stderr,"flow validate: %s\n",error.message?error.message:"failed"); goto done;
        }
        flow=rte_flow_create(port,&attr,items,actions,&error);
        if (!flow) { fprintf(stderr,"flow create: %s\n",error.message?error.message:"failed"); goto done; }
    }
    signal(SIGINT,handle); signal(SIGTERM,handle);
    char stop_path[1024];
    if (snprintf(stop_path,sizeof(stop_path),"%s.stop",argv[1])>=(int)sizeof(stop_path)) goto done;
    double deadline=monotonic()+seconds, last=0;
    uint64_t tick=rte_get_timer_hz()/1000, next=0;
    struct rte_mbuf *mbufs[64];
    if (report(port,argv[1])) goto done;
    puts(receive_all ? "READY DPDK_MLX5 promiscuous RX queue" :
         "READY DPDK_MLX5 isolated RX queue"); fflush(stdout);
    while (!stopped) {
        uint16_t count=rte_eth_rx_burst(port,0,mbufs,64);
        if (count) {
            double timestamp=monotonic();
            received+=count;
            for (uint16_t i=0;i<count;i++) {
                unsigned char scratch[60];
                const unsigned char *data=rte_pktmbuf_read(mbufs[i],0,60,scratch);
                if (data) packet(data,60,timestamp); else invalid++;
            }
            rte_pktmbuf_free_bulk(mbufs,count);
        }
        uint64_t now=rte_get_timer_cycles();
        if (now>=next) {
            next=now+tick;
            double t=monotonic();
            if (t>=deadline || access(stop_path,F_OK)==0) break;
            if (t-last>=1) {
                if (report(port,argv[1])) goto done;
                last=t;
            }
        }
    }
    status=report(port,argv[1])?1:0;
done:
    if (flow) rte_flow_destroy(port,flow,&error);
    if (started) rte_eth_dev_stop(port);
    if (configured) rte_eth_dev_close(port);
    if (pool) rte_mempool_free(pool);
    for (unsigned i=0;i<used;i++) free(batches[i].seen);
    rte_eal_cleanup();
    return status;
}
