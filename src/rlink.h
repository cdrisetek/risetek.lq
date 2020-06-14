#ifndef __RLINK_H_
#define __RLINK_H_
#include <stdio.h>
#include <stdlib.h>

#include "basetype.h"
#include "lib/diet.h"
#include "lib/lq_queue.h"

#define FMT_CID        "%018llu"
#define FMT_PN         "%llu"
#define FMT_SID        "%03d"

#if 0
#define LQ_DEBUG_PKT(fmt, args...)
#else
#define LQ_DEBUG_PKT(fmt, args...) do{ fprintf(stderr, fmt, ##args); }while(0)
#endif

#if 1
#define LQ_DEBUG_CORE(fmt, args...) do{ fprintf(stderr, fmt, ##args); }while(0)
#else
#define LQ_DEBUG_CORE(fmt, args...)
#endif

#define LQ_DEBUG_ERROR(fmt, args...) do{ fprintf(stderr, fmt, ##args); }while(0)

#define LQ_DEBUG_APPL(fmt, args...) do{ fprintf(stderr, fmt, ##args); }while(0)

#if 0
#define LQ_DEBUG_MAIN(fmt, args...) do{ fprintf(stderr, fmt "\r\n", ##args); }while(0)
#else
#define LQ_DEBUG_MAIN(fmt, args...)
#endif

#define MARKLINE    fprintf(stderr, "%s %d\r\n", __FUNCTION__, __LINE__);

#define STREAM_ID_CRYPTO     0
#define STREAM_ID_ACK1       1  /* 立即ACK */
#define STREAM_ID_ACK2       2  /* ACK */

#define STREAM_EGRESS_ACK              (1 << 0)
#define STREAM_HAS_OFFSET              (1 << 1)
#define STREAM_HAS_LENGTH              (1 << 2)
#define STREAM_HAS_BUFFER              (1 << 3)
#define STREAM_INGRESS_IMM_ACK         (1 << 5)
#define STREAM_CORE                    (1 << 7)

#define DEFAULT_RTT_US                 20
#define DEFAULT_HEADER_BYTE            0x80

typedef enum {
    connection_init,
    connection_handshake,
    connection_idle,
    connection_closed
} connection_state;

struct r_connection;

typedef struct r_packet {
    RLINK_ADDR from_addr;
    RLINK_ADDR to_addr;
    struct r_packet *next;
    struct r_connection *connection;

    int len;
    cyg_uint8  buf[1500];

    //runtime
    int ref;
} RPACKET, *pRPACKET;

typedef struct r_stream_buffer {
    TYPE_STREAM_OFFSET offset;
    TYPE_BUFFER_SIZE len;
    TYPE_BUFFER_SIZE size;

    cyg_uint8 buffer[1500];

    // 接收处理
    pRPACKET packet;
    const cyg_uint8 *packet_pos;
    int packet_stream_len;

    /**
     * 待发送的stream buffer数据需要有状态可以识别，设计packet_nb基于以下考虑：
     * 1. 未发送的stream buffer标记为 0
     * 2. 已经发送但是没有得到确认/否认的stream buffer标记为发送这个stream buffer的packet的packet_nb
     * 3. 如果得到确认了，释放这个stream buffer
     * 4. 如果否认了，或者超时发生，重置这个stream buffer为 0
     * 5. 基于这个考虑，packet number的初始化值需要从 1 开始， 或者任何大于 0 的序号。
     **/
    TYPE_PACKET_NUMBER packet_nb;
    TYPE_TIMER_US ticks;
    struct r_stream_buffer *next;


    // DEBUG
} RSTREAM_BUFFER, *pRSTREAM_BUFFER;

typedef struct r_stream {
    TYPE_STREAM_ID id;
    TYPE_STREAM_OFFSET offset;
    int avaliable_len;
    pRSTREAM_BUFFER buffer_header;

    // APPLICATION
    cyg_uint32 notified_event;
    cyg_uint32 notify_event;
    cyg_uint32 interesting_event;
    // 应用层希望在给定时间点产生CONNECT_EVENT_TIMER事件
    TYPE_TIMER_US timer_interesting;

} RSTREAM, *pRSTREAM;

struct r_link;

// Packet Number Space
typedef struct pn_space {
    BOOL       need_ack;
    struct diet recv; ///< Received packet numbers still needing to be ACKed.
    cyg_uint32  pkts_rxed_since_last_ack_tx;
    cyg_uint32  rx_frm_types;
    TYPE_TIMER_US last_ack_time;
} PN_SPACE, *pPN_SPACE;

#define EVENT_ID_READABLE                          0
#define EVENT_ID_WRITEABLE                         1
#define EVENT_ID_TIMER                             2

#define CONNECTION_EVENT_READABLE                  (1 << EVENT_ID_READABLE)
#define CONNECTION_EVENT_WRITEABLE                 (1 << EVENT_ID_WRITEABLE)
#define CONNECTION_EVENT_TIMER                     (1 << EVENT_ID_TIMER)

struct ingress_crypto_stream_priv {
	int offset;
};

//typedef int connection_event_cb(struct r_connection *connection, TYPE_STREAM_ID stream_id, cyg_uint32 event);

typedef struct r_connection {
    RLINK_CID  local_cid;
    RLINK_CID  target_cid;
    connection_state state;
    PN_SPACE   pn_space;

    // ACK
    // Latest packet number contains ACK stream
    TYPE_PACKET_NUMBER ack_pn;
    struct diet acked;

    // TODO: 不同作用的stream分组进行管理？

    // send endpoints
    RSTREAM    egress_streams[NUMBER_OF_STREAMS+1];

    // receive endpoints
    RSTREAM    ingress_streams[NUMBER_OF_STREAMS+1];

    TYPE_PACKET_NUMBER packet_nb;
    pRPACKET received_packet_header;

    // CC
    TYPE_TIMER_US   rtt;

    struct r_link *rlink;
    struct r_connection *next;

    BOOL protocol_violate;

    // APPLICATION
    void * priv_t;

    // CORE
    struct ingress_crypto_stream_priv ingress_crypto_stream_ctx;

    // DEBUG
    RLINK_ADDR local_addr;
    RLINK_ADDR peer_addr;
    cyg_uint32 received_packet;
    cyg_uint32 sended_packet;
    cyg_uint32 received_ackonly;
    cyg_uint32 sended_ackonly;
    cyg_uint32 ack1_sended;
    cyg_uint32 ack2_sended;
} RCONNECTION, *pRCONNECTION;

typedef struct r_connection_mgr {
    pRCONNECTION connection_header;
} RCONNECTION_MGR, *pRCONNECTION_MGR;

#define MAX_LINK_PACKETS 100
typedef int application_handler(pRCONNECTION connection, TYPE_STREAM_ID id, cyg_uint32 event, void *ctx);

typedef struct r_link {
    BOOL isClient;
    RCONNECTION_MGR connections_mgr;
    RLINK_CID base_link_id;
    TYPE_TIMER_US ticks;
//    TYPE_TIMER_US last_ticks;

    RPACKET  __packets[MAX_LINK_PACKETS];
    pRPACKET free_packets;

    RSTREAM_BUFFER __stream_buffer[1000];
    pRSTREAM_BUFFER free_stream_header;

    // TEST
    RLINK_ADDR addr;
    int test_ok;
    BOOL protocol_violate;

    // process new connection construction.
    application_handler *link_handler;

    // DEBUG
    const char *debug_prompt;
} RLINK, *pRLINK;

typedef int stream_handler(pRCONNECTION connection, pRSTREAM stream);

typedef struct {
	cyg_uint32 type;
	stream_handler *handler;  // stream process handler
} STREAM_ARRT;

#define NO_ERROR                  0x0
#define INTERNAL_ERROR            0x1
#define FRAME_ENCODING_ERROR      0x7
#define PROTOCOL_VIOLATION        0xA

pRLINK rlink_create(BOOL isClient, pRLINK_ADDR addr);
pRCONNECTION rlink_connect(pRLINK link, pRLINK_ADDR addr);
void rlink_cleanstream(pRLINK rlink);
void rlink_upstream(pRLINK rlink);
int rlink_egress(pRLINK link, pRPACKET packet);
int rlink_ingress(pRLINK link, pRPACKET packet);
void rlink_scheduler_core(pRLINK rlink);
//pRCONNECTION accept_connection(pRLINK link);
//void cleanstream_streams(pRCONNECTION connection, pRSTREAM stream);
void log_packet(const char *logger, pRPACKET packet);
//typedef int construction_handler(pRCONNECTION connection, TYPE_STREAM_ID id);
int register_application(pRLINK rlink, application_handler *handler, void *ctx);
void rlink_destroy(pRLINK rlink);
void request_write(pRCONNECTION connection, TYPE_STREAM_ID id);
void request_read(pRCONNECTION connection, TYPE_STREAM_ID id);
void request_timer(pRCONNECTION connection, TYPE_STREAM_ID id, TYPE_TIMER_US delay_us);

TYPE_BUFFER_SIZE lq_write(pRCONNECTION connection, TYPE_STREAM_ID id, cyg_uint8 const *val, TYPE_STREAM_LENGTH len);
TYPE_BUFFER_SIZE lq_read(pRCONNECTION connection, TYPE_STREAM_ID id, char *buffer, TYPE_BUFFER_SIZE length);

#define CHK_FAILED_CORE(condition, fmt, args...) do{if(!(condition)){LQ_DEBUG_CORE(fmt, ##args); goto failed;}}while(0)

#endif // __RLINK_H_




