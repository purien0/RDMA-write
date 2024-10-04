#include<cstdio>
#include <infiniband/verbs.h>
#include <sys/socket.h>
#include <netdb.h>
#include<cstdlib>
#include<unistd.h>
#include <arpa/inet.h> 
#include <inttypes.h>
#include <sys/time.h> // For timing
/* structure of test parameters */
struct config_t
{
    const char *dev_name; /* IB device name */
    char *server_name;    /* server host name */
    uint32_t tcp_port;    /* server TCP port */
    int ib_port;          /* local IB port to work with */
    int gid_idx;          /* gid index to use */
};
struct config_t config =
{
    NULL,  /* dev_name */
    "192.168.247.130",  /* server_name */
    19875, /* tcp_port */
    1,     /* ib_port */
    1     /* gid_idx */
};

struct exchange_data{
    uint8_t  gid[16] ;
    uint32_t qpn;/* QP number */
    uint64_t va;//virtual address
    uint32_t r_key;
    uint16_t lid;         /* LID of the IB port */
};
struct resource{//RDMA resources used;easier for transmission
    ibv_qp *qp;
    ibv_cq *cq;
    ibv_mr *mr;
    ibv_pd *pd;
    ibv_gid * gid;
    struct exchange_data *remote_data;
    struct ibv_device_attr* device_attr;
    struct ibv_port_attr *port_attr;
    char* buf;
    struct ibv_device ** device_list;
    struct ibv_context * device_content;// no malloc
    int sock;
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x)
{//从主机字节顺序转换成网络字节顺序
    return (((uint64_t) htonl(x)) << 32) + htonl(x >> 32);
}
static inline uint64_t ntohll(uint64_t x)
{//从网络字节顺序转换成主机字节顺序
    return (((uint64_t) ntohl(x)) << 32) + ntohl(x >> 32);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return x;
}
static inline uint64_t ntohll(uint64_t x)
{
    return x;
}
#endif
static int sock_connect(const char *servername, int port)
{
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;
    int tmp;
    struct addrinfo hints =
    {
        .ai_flags    = AI_PASSIVE,
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    if(sprintf(service, "%d", port) < 0)
    {
        goto sock_connect_exit;
    }

    /* Resolve DNS address, use sockfd as temp storage */
    sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);
    if(sockfd < 0)
    {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(sockfd), servername, port);
        goto sock_connect_exit;
    }

    /* Search through results and find the one we want */
    for(iterator = resolved_addr; iterator ; iterator = iterator->ai_next)
    {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
        if(sockfd >= 0)
        {
            if(servername)
			{
                /* Client mode. Initiate connection to remote */
                if((tmp=connect(sockfd, iterator->ai_addr, iterator->ai_addrlen)))
                {
                    fprintf(stdout, "failed connect \n");
                    close(sockfd);
                    sockfd = -1;
                }
			}
            else
            {
                /* Server mode. Set up listening socket an accept a connection */
                listenfd = sockfd;
                sockfd = -1;
                if(bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))
                {
                    goto sock_connect_exit;
                }
                listen(listenfd, 1);
                sockfd = accept(listenfd, NULL, 0);
            }
        }
    }

sock_connect_exit:
    if(listenfd)
    {
        close(listenfd);
    }

    if(resolved_addr)
    {
        freeaddrinfo(resolved_addr);
    }

    if(sockfd < 0)
    {
        if(servername)
        {
            fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        }
        else
        {
            perror("server accept");
            fprintf(stderr, "accept() failed\n");
        }
    }

    return sockfd;
}
ibv_cq* create_cq(ibv_context*device_content,int cq_size){
    struct ibv_cq*cq;
    cq = ibv_create_cq(device_content,cq_size,NULL,NULL,0);
    return cq;
}
ibv_qp* create_qp(ibv_pd *pd,ibv_cq *cq){
    struct ibv_qp*qp;
    struct ibv_qp_init_attr qp_init;
    memset(&qp_init,0,sizeof(struct ibv_qp_init_attr));
    qp_init.qp_type = IBV_QPT_RC;
    qp_init.send_cq = cq;
    qp_init.recv_cq = cq;
    qp_init.srq = NULL;
    /* If set, each Work Request (WR) submitted to the SQ generates a completion entry */
    qp_init.sq_sig_all = 1;
    //capacity
    qp_init.cap.max_recv_wr = 10;
    qp_init.cap.max_send_wr = 20;
    qp_init.cap.max_recv_sge = 10;
    qp_init.cap.max_send_sge = 20;
    qp = ibv_create_qp(pd,&qp_init);
    return qp;
}
int modify_qp_init(ibv_qp*qp){
    int err_code = 0;
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr,0,sizeof(struct ibv_qp_attr));
    int attr_mask ;
    qp_attr.qp_state = IBV_QPS_INIT;
    //pkey?
    qp_attr.pkey_index = 0;
    qp_attr.port_num = config.ib_port;
    qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE|IBV_ACCESS_REMOTE_WRITE|IBV_ACCESS_REMOTE_READ;
    attr_mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    
    err_code = ibv_modify_qp(qp,&qp_attr,attr_mask);

    if(err_code){
        printf("ibv_modify_qp init fail!");
        return err_code;
    }
    return err_code;
}
int modify_qp_RTR(struct resource *res){
    int err_code = 0;
    struct ibv_qp_attr qp_attr ;
    memset(&qp_attr,0,sizeof(struct ibv_qp_attr));
    int attr_mask ;
    qp_attr.qp_state = IBV_QPS_RTR;
    qp_attr.dest_qp_num = res->remote_data->qpn;
    //?
    qp_attr.rq_psn = 0;

    qp_attr.path_mtu = IBV_MTU_256;
    /*If  port  flag IBV_QPF_GRH_REQUIRED is set then ibv_create_ah() must be
       created with definition of 'struct ibv_ah_attr { .is_global = 1; .grh =
       {...}; }'.*/
    //RocE NEED GRH
    qp_attr.ah_attr.is_global = 1;
    memcpy(&qp_attr.ah_attr.grh.dgid,res->remote_data->gid,16);
    //why RC use address handler?
    qp_attr.ah_attr.port_num = 1;
    //hop_limit and traffic_class means?
    qp_attr.ah_attr.grh.flow_label = 0;
    qp_attr.ah_attr.grh.hop_limit = 100;
    qp_attr.ah_attr.grh.traffic_class = 0;
    qp_attr.ah_attr.grh.sgid_index = config.gid_idx;

    qp_attr.ah_attr.dlid = res->remote_data->lid;
    qp_attr.ah_attr.sl = 0;//service level
    qp_attr.ah_attr.src_path_bits = 0;
    //RocE NEED GRH
   
    /*Number of responder resources for handling incoming RDMA reads & atomic operations (valid only
 for RC QPs) */
    qp_attr.max_dest_rd_atomic = 10;
    /* Minimum RNR NAK timer (valid only for RC QPs) */
    qp_attr.min_rnr_timer = 18;

    attr_mask = IBV_QP_STATE | IBV_QP_AV|IBV_QP_PATH_MTU|
                      IBV_QP_DEST_QPN|IBV_QP_RQ_PSN|
                      IBV_QP_MAX_DEST_RD_ATOMIC|IBV_QP_MIN_RNR_TIMER;
    err_code = ibv_modify_qp(res->qp,&qp_attr,attr_mask);
    if(err_code){
        printf("ibv_modify_qp RTR fail!");
        return err_code;
    }
    return err_code;
}
int modify_qp_RTS(ibv_qp*qp){
    int return_value = 0;
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr,0,sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTS;
    qp_attr.sq_psn = 0;//?
    qp_attr.max_rd_atomic = 10;
    qp_attr.retry_cnt = 1;
    //RNR retry?
    qp_attr.rnr_retry = 0;
    qp_attr.timeout = 18;
    int mask = IBV_QP_STATE|IBV_QP_SQ_PSN|IBV_QP_MAX_QP_RD_ATOMIC|
                      IBV_QP_RETRY_CNT|IBV_QP_RNR_RETRY|IBV_QP_TIMEOUT;
    return_value = ibv_modify_qp(qp,&qp_attr,mask);
    if(return_value){
        printf("ibv_modify_qp RTS fail!");
        return return_value;
    }
    return return_value;
}

int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{//write_read exchange data to sync
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;
    rc = write(sock, local_data, xfer_size);

    if(rc < xfer_size)
    {
        fprintf(stderr, "Failed writing data during sock_sync_data\n");
    }
    else
    {
        rc = 0;
    }

    while(!rc && total_read_bytes < xfer_size)
    {
        read_bytes = read(sock, remote_data, xfer_size);
        if(read_bytes > 0)
        {
            total_read_bytes += read_bytes;
        }
        else
        {
            rc = read_bytes;
        }
    }
    return rc;
}
int post_recv(struct resource *res){
    int rc = 0;
    struct ibv_recv_wr wr ;
    struct ibv_sge sge ;
    memset(&sge,0,sizeof(struct ibv_sge));
    sge.lkey = res->mr->lkey;
    sge.addr = (uint64_t)res->buf;
    sge.length = res->mr->length;

    static int wr_id = 0;
    memset(&wr,0,sizeof(struct ibv_recv_wr));
    wr.num_sge = 1;
    wr.wr_id = wr_id++;
    wr.sg_list = &sge;
    wr.next = NULL;
    struct ibv_recv_wr*bad_wr;

    rc = ibv_post_recv(res->qp,&wr,&bad_wr);
    if(rc){
        printf("id:%d,numsge:%d,addr:%p,len:%d,lkey:%d",bad_wr->wr_id,bad_wr->num_sge,bad_wr->sg_list->addr,bad_wr->sg_list->length,bad_wr->sg_list->lkey);
        printf("%d fail to post recv\n",rc);
    }
    
    return rc;
}
int sync(struct resource *res){
    char temp_char[2];
    if(sock_sync_data(res->sock, 1, "Q", temp_char))  /* just send a dummy char back and forth */
    {
        fprintf(stderr, "sync error\n");
        return 1;
    }
    return 0;
}
int post_send(ibv_qp*qp,ibv_mr*mr,ibv_wr_opcode opcode,struct exchange_data*remote_data){
    //post send wr to sq
    int rc = 0;
    static int wr_id = 0;
    struct ibv_send_wr wr;
    struct ibv_sge sge;
    sge.lkey = mr->lkey;
    sge.addr = (uint64_t)mr->addr;
    sge.length = mr->length;

    wr.num_sge = 1;
    wr.wr_id = wr_id++;
    wr.sg_list = &sge;
    wr.next = NULL;
    wr.opcode = opcode;
    if(opcode!=IBV_WR_SEND){//READ or WRITE
        wr.wr.rdma.remote_addr = remote_data->va;
        wr.wr.rdma.rkey = remote_data->r_key;
    }

    struct ibv_send_wr*bad_wr;
    rc = ibv_post_send(qp,&wr,&bad_wr);
    return  rc;
}
int exchange_data(struct resource *res){
    struct exchange_data local_data;
    res->remote_data = (struct exchange_data*)malloc(sizeof(struct exchange_data));
    struct exchange_data temp_data;
    local_data.lid = htons(res->port_attr->lid);
    local_data.qpn = htonl(res->qp->qp_num);
    local_data.r_key = htonl(res->mr->rkey);
    local_data.va = htonll((unsigned long)res->mr->addr);
    memcpy(local_data.gid,res->gid,16);
    if(sock_sync_data(res->sock,sizeof(struct exchange_data),(char*)(&local_data),(char*)(&temp_data))){
        fprintf(stderr, "failed to exchange connection data between sides\n");
        return 1;
    }
    res->remote_data->lid = ntohs(temp_data.lid);
    res->remote_data->qpn = ntohl(temp_data.qpn);
    res->remote_data->r_key = ntohl(temp_data.r_key);
    res->remote_data->va = ntohll((unsigned long)temp_data.va);
    memcpy(res->remote_data->gid,temp_data.gid,16);

    fprintf(stdout, "Remote address = 0x%"PRIx64"\n", res->remote_data->va);
    fprintf(stdout, "Remote rkey = 0x%x\n", res->remote_data->r_key);
    fprintf(stdout, "Remote QP number = 0x%x\n", res->remote_data->qpn);
    fprintf(stdout, "Remote LID = 0x%x\n", res->remote_data->lid);
    return 0;
}
int poll_cq(ibv_cq* cq){
    int rc = 0;
    struct ibv_wc wc;
    int num_entries = 1;
    int res = 0;
    int max_attempts = 10000; 
    int attempts = 0;
    while(attempts<max_attempts){
        res = ibv_poll_cq(cq,num_entries,&wc);
        if(res>0){
            if (wc.status == IBV_WC_SUCCESS) {
        } else {
            printf("Work completion error: %d\n", wc.status);
        }
        break;
        }
        usleep(1000); // 如果没有完成事件，休眠1毫秒，避免轮询过频繁
        attempts++;
    }
    if (res < 0){//fail
        rc = 1;
        printf("failed to poll\n");
        return rc;
    }
    else if (res == 0){//empty
        printf("poll completion empty\n");
        rc = 1;
        return rc;
    }else{//succeed
        if(wc.status!=IBV_WC_SUCCESS){
        rc = 1;
        }
    }
    return rc;
}

void SEND_RECV(struct resource*res){//client wr->sq,server wr->rq;
    if(!config.server_name)//cliet侧
    {
        if(sync(res)){
            printf("fail to sync");
            return;
        }
        if(post_send(res->qp,res->mr,IBV_WR_SEND,res->remote_data)){
            printf("fail to send Write WR");
            return;
        }
         if(poll_cq(res->cq)){
            printf("fail to poll_cq");
            return;
        }
    }
    else{
        if(post_recv(res)){
            printf("fail to send Write WR");
            return;
        }
        if(sync(res)){
            printf("fail to sync");
            return;
        }
         if(poll_cq(res->cq)){
            printf("fail to poll_cq");
            return;
        }
    }
}
void WRITE(struct resource*res){
    if(post_send(res->qp,res->mr,IBV_WR_RDMA_WRITE,res->remote_data)){
            printf("fail to send Write WR");
            return;
        }
        if(poll_cq(res->cq)){
            printf("fail to poll_cq");
            return;
        }
}
void READ(struct resource*res){
        if(post_send(res->qp,res->mr,IBV_WR_RDMA_READ,res->remote_data)){
            printf("fail to send READ WR");
            return;
        }
        if(poll_cq(res->cq)){
            printf("fail to poll_cq");
            return;
        }
}
void destory_res(struct resource*res){
    //destory
    if(res->qp)
    ibv_destroy_qp(res->qp);
    if(res->mr)
    ibv_dereg_mr(res->mr);
    if(res->buf)
    free(res->buf);
    if(res->cq)
    ibv_destroy_cq(res->cq);
    if(res->pd)
    ibv_dealloc_pd(res->pd);
    /*ibv_close_device() does not release all the resources  allocated  using
       context  context.  To avoid resource leaks, the user should release all
       associated resources before closing a context.
*/
    if(res->device_content)
    ibv_close_device(res->device_content);
    if(res->device_list)
    ibv_free_device_list(res->device_list);
    if(res->gid)
    free(res->gid);
    if(res->device_attr)
    free(res->device_attr);
    if(res->port_attr)
    free(res->port_attr);
    if(res->sock>0)
    close(res->sock);

    free(res);
}
int main(int argc, char *argv[]){
    int num_device;
    struct resource *res = (struct resource*)malloc(sizeof(struct resource));
    memset(res,0,sizeof(struct resource));
    int rc = 0;
    char temp_char[10];
    int NUM_ITERATIONS = 10000;
    long long total_bytes = 0;

    res->device_list =ibv_get_device_list(&num_device);
    if(num_device <= 0||res->device_list == NULL){
        printf("no devices found!");
        return 0;
    }
    //use first device
    struct ibv_device * ibv = res->device_list[0];
    if(ibv ==NULL){
        printf("device_list no devices found!");
        return 0;
    }
    //ibv_open_device() returns a pointer to the allocated device context, or NULL if the request fails
    res->device_content=ibv_open_device(res->device_list[0]);
    if (res->device_content==NULL){
        printf("ibv_open_device fail!");
        return 0;
    }


    res->port_attr = (struct ibv_port_attr*)malloc(sizeof(struct ibv_port_attr));
    if(ibv_query_port(res->device_content,config.ib_port,res->port_attr)){
        printf("ibv_query_port fail!");
        return 0;
    }

    res->pd = ibv_alloc_pd(res->device_content);
    if(res->pd==NULL){
        printf("ibv_alloc_pd fail!");
        return 0;
    }

    int access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    
    size_t size = 4096;
    char * addr = (char*)malloc(size);
    res->buf = addr;
    memset(addr,0,size);

    res->mr = ibv_reg_mr(res->pd,addr,size,access);

    int cq_size = 1024;
    res->cq = create_cq(res->device_content,cq_size);
    if (res->cq==NULL){
        printf("ibv_create_cq fail!");
        return 0;
    }
    printf("mr reg! mr addr:%p,buf addr:%p\n",res->mr->addr,addr);
    
    printf("mr len:%d,buf size:%d\n",res->mr->length,size);
    fprintf(stdout, "MR was registered with addr=%p, lkey=0x%x, rkey=0x%x, flags=0x%x\n",
            addr, res->mr->lkey, res->mr->rkey);
    
    res->qp = create_qp(res->pd,res->cq);

    if (res->qp==NULL){
        printf("ibv_create_qp fail!");
        return 0;
    }

    rc = modify_qp_init(res->qp);
    if (rc){
        printf("fail to init qp\n");
        return 0;
    }
    printf("init\n");
    //socket建链
    res->sock = sock_connect(config.server_name, config.tcp_port);
        if(res->sock < 0)
        {
            fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n",
                    config.server_name, config.tcp_port);
            return 0;
        }
    res->gid = (ibv_gid*)malloc(sizeof(ibv_gid));
    if(config.gid_idx >= 0)
    {
        rc = ibv_query_gid(res->device_content, config.ib_port, config.gid_idx, res->gid);
        if(rc)
        {
            fprintf(stderr, "could not get gid for port %d, index %d\n", config.ib_port, config.gid_idx);
            return rc;
        }
    }
    else
    {
        memset(res->gid, 0, sizeof(ibv_gid));
    }
    //exchange
    if(exchange_data(res)){
        fprintf(stdout,"fail to exchange_data\n");
        rc = 1;
        goto exit;
    }
   
    //to RTR
    if(modify_qp_RTR(res)){
        printf("fail to RTR\n");
        rc = 1;
        goto exit;
    }
    //to RTS
    if(modify_qp_RTS(res->qp)){
        printf("fail to RTS\n");
        rc = 1;
        goto exit;
    }
    //write

    /* sync to make sure that both sides are in states that they can connect to prevent packet loose */
    if(sync(res))  /* just send a dummy char back and forth */
    {
        fprintf(stderr, "sync error after QPs are were moved to RTS\n");
        rc = 1;
        goto exit;
    }

    //measure byte width
    struct timeval start, end;
    memset(addr, 0xab, size);
    gettimeofday(&start, NULL);
    
    if(config.server_name){//client
        gettimeofday(&start, NULL);
        for(int i = 0; i < NUM_ITERATIONS;i++){
        WRITE(res);
        total_bytes+=size;
        }
        gettimeofday(&end, NULL);
        double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
        double bandwidth = (total_bytes / (1024.0 * 1024.0)) / elapsed_time;  // MB/s
        printf("Transferred %ld bytes in %.2f seconds, Bandwidth: %.2f MB/s\n", total_bytes, elapsed_time, bandwidth);
    }
    
    if(sync(res))  /* just send a dummy char back and forth */
    {
        fprintf(stderr, "sync error after QPs are were moved to RTS\n");
        rc = 1;
        goto exit;
    }
    exit:
    //destory
    destory_res(res);
    return rc;
}
