#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include "lib/marshall.h"
#include "rlink.h"

#include <signal.h>
#include <execinfo.h>
static void print_trace(void) {
	void           *array[32];    /* Array to store backtrace symbols */
	size_t          size;     /* To store the exact no of values stored */
	char          **strings;    /* To store functions from the backtrace list in ARRAY */
	size_t          nCnt;

	size = backtrace(array, 32);

	strings = backtrace_symbols(array, size);

	if(NULL == strings)
		fprintf(stderr,"print_trace: do not got strings\r\n");
	/* prints each string of function names of trace*/
	for (nCnt = 0; nCnt < size; nCnt++) {
		char *message = strings[nCnt];
		fprintf(stderr,"%s\r\n", message);
	  // free(message);
	}
}

static void sigroutine(int dunno) {
	switch (dunno) {
		case SIGHUP:
			printf("Get a signal -- SIGHUP\r\n");
			break;
		case SIGINT:
			printf("Get a signal -- SIGINT\r\n");
			break;
		case SIGQUIT:
			printf("Get a signal -- SIGQUIT\r\n");
			break;
		case SIGABRT:
			printf("Get a signal -- SIGABRT\r\n");
			print_trace();
			break;
		case SIGSEGV:
			printf("Get a signal -- SIGSEGV\r\n");
			print_trace();
			break;
		default:
			printf("Get a signal -- %d\r\n", dunno);
			break;
	}
	_exit(0);
}

static BOOL islucky(void) {
//	return TRUE;
	if(rand() < (RAND_MAX/100*50))
        return TRUE;
    return FALSE;
}

const char *state_name[] = {
	    "connection init",
	    "connection handshake",
	    "connection idle",
	    "connection closed"
};

const char *event_name[] = {
		"READABLE",
		"WRITEABLE",
		"TIMER"
};

static void show_connection(pRCONNECTION connection) {
    LQ_DEBUG_SUMMARY("        Sending Packet Number: %llu\r\n", connection->packet_nb);
    LQ_DEBUG_SUMMARY("           Undelivered packet: %u\r\n", connection->lost_packet);
    LQ_DEBUG_SUMMARY("               Status Machine: %s\r\n", state_name[connection->state]);
    LQ_DEBUG_SUMMARY("             Received Packets: %6u,   Sended Packets: %6u\r\n", connection->received_packet, connection->sended_packet);
    LQ_DEBUG_SUMMARY("             Received AckOnly: %6u,   Sended AckOnly: %6u\r\n", connection->received_ackonly, connection->sended_ackonly);
    LQ_DEBUG_SUMMARY("                  Sended Ack1: %6u,      Sended Ack2: %6u\r\n", connection->ack1_sended, connection->ack2_sended);
    int loop;
    for(loop = 0; loop < sizeof(connection->egress_streams)/sizeof(connection->egress_streams[0]); loop++) {
    	pESTREAM stream = &connection->egress_streams[loop];
    	if((stream->sended_size > 0) || (stream->pending_size > 0))
            LQ_DEBUG_SUMMARY("     > Stream[" FMT_SID "] write size: %6llu,     pending size: %6llu,"
            			     "    egressed: %4llu bytes, Timeout: %4llu frames\r\n",
            		loop, stream->sended_size, stream->pending_size, stream->egress_size, stream->timeout_frames);
        if(NULL != stream->buffer_header)
            LQ_DEBUG_SUMMARY("       Stream[" FMT_SID "] contains datas\r\n", loop);
    }

    for(loop = 0; loop < sizeof(connection->ingress_streams)/sizeof(connection->ingress_streams[0]); loop++) {
    	pINSTREAM stream = &connection->ingress_streams[loop];
    	if((stream->received_size > 0) || (stream->offset > 0))
            LQ_DEBUG_SUMMARY("  < Stream[" FMT_SID "] received size: %6llu,      readed size: %6llu,  ingress size:  %6llu"
            		         "    Received duplicate: %6llu bytes [%4llu frames]\r\n",
            		loop, stream->received_size, stream->offset, stream->ingress_size, stream->dup_bytes, stream->dup_transfer);
    	if(NULL != stream->slinker.packet)
            LQ_DEBUG_SUMMARY("       Stream[" FMT_SID "] contains datas\r\n", loop);
    }

    struct diet *p_acked = &connection->acked;
    if(!diet_empty(p_acked)) {
	    LQ_DEBUG_SUMMARY("   packet number %6llu acked: ", connection->ack_pn);
	    int br = 0;
    	struct ival *i;
    	diet_foreach(i, diet, p_acked) {
    	    LQ_DEBUG_SUMMARY("[%u:%u] ", i->lo, i->hi);
    	    if(++br%10 == 0)
    		    LQ_DEBUG_SUMMARY("\r\n%30s", ":");
    	}
	    LQ_DEBUG_SUMMARY("\r\n");
    }

    struct diet *pn = &connection->pn_space.recv;
    if(!diet_empty(pn)) {
    	struct ival *i;
	    LQ_DEBUG_SUMMARY("%31s", "received packet space: ");
	    int br = 0;
    	diet_foreach(i, diet, pn) {
    	    LQ_DEBUG_SUMMARY("[%u:%u] ", i->lo, i->hi);
    	    if(++br%10 == 0)
    		    LQ_DEBUG_SUMMARY("\r\n%30s", ":");
    	}
	    LQ_DEBUG_SUMMARY("\r\n");
    }

    pRPACKET p = connection->received_packet_header;
    while(NULL != p) {
	    LQ_DEBUG_SUMMARY("%30s %d  (%p)\r\n", "received packets refs:", p->ref, p);
    	p = p->next;
    }
}

static void show_rlink(pRLINK rlink) {
    LQ_DEBUG_SUMMARY("-------- RLINK %p (%s) status --------------------------------\r\n", rlink, rlink->isClient?" CLIENT" : "SERVER");
    int count = 0;
    pRCONNECTION connect = rlink->connections_mgr.connection_header;

    for(; NULL != connect; count++, connect = connect->next) {
        LQ_DEBUG_SUMMARY("  -- CONNECTION [%d] ---- SCID: %llu  DCID: %llu\r\n", count+1, connect->local_cid, connect->target_cid);
        show_connection(connect);
    }
    LQ_DEBUG_SUMMARY(" ------------  total connections: %d -----------------------------\r\n", count);
    LQ_DEBUG_SUMMARY("      TEST: %s\r\n", rlink->test_ok ? "finished" : "continue");
}

static int global_stop = 0;
static BOOL stop_condiction(pRLINK server, pRLINK client) {

	if(fgetc(stdin) > 0) {
        global_stop = 1;
		return TRUE;
	}

    if(server->protocol_violate == TRUE) {
        LQ_DEBUG_SUMMARY("Server Protocol violate\r\n");
        global_stop = 1;
        return true;
    }

    if(client->protocol_violate == TRUE) {
        LQ_DEBUG_SUMMARY("Client Protocol violate\r\n");
        global_stop = 1;
        return true;
    }

    pRCONNECTION connect = server->connections_mgr.connection_header;
    for(; NULL != connect; connect = connect->next) {
    	if(connect->state != connection_idle)
    		return false;

        int loop;
        for(loop = 0; loop < sizeof(connect->egress_streams)/sizeof(connect->egress_streams[0]); loop++) {
            if(NULL != connect->egress_streams[loop].buffer_header)
        		return false;
        }

    }

    connect = client->connections_mgr.connection_header;
	for(; NULL != connect; connect = connect->next) {
		if(connect->state != connection_idle)
			return false;
		int loop;
		for(loop = 0; loop < sizeof(connect->egress_streams)/sizeof(connect->egress_streams[0]); loop++) {
			if(NULL != connect->egress_streams[loop].buffer_header)
				return false;
		}
	}

	if(!server->test_ok)
		return false;

	if(!client->test_ok)
		return false;

	return true;
}

void log_packet(const char *logger, pRPACKET packet) {
    LQ_DEBUG_PKT("\r\n||-------- Logger %s for packet %p------------------------------------------------------------------------------------------\r\n", logger, packet);
    LQ_DEBUG_PKT("|| Packet   from: ");
    int index;
    pRLINK_ADDR paddr = &packet->from_addr;
    for(index = 0; index < sizeof(paddr->addr); index++)
    	LQ_DEBUG_PKT("%02X", (cyg_uint8)paddr->addr[index]);
    LQ_DEBUG_PKT("\r\n");

    cyg_uint8 const *pos = packet->buf;
    cyg_uint8 *end = packet->buf + packet->len;

    cyg_uint8 header_byte;
    dec1(&header_byte, &pos, end);

    RLINK_CID target_id;
    dec8(&target_id, &pos, end);

    TYPE_PACKET_NUMBER packet_nb;
    decv(&packet_nb, &pos, end);

    LQ_DEBUG_PKT("|| Packet Length: %d%s, Header byte: %02X\r\n", packet->len, (packet->len > sizeof(packet->buf))?"--!!!Overflow!!!":"",  header_byte);
    // LQ_DEBUG_PKT("Packet Header: %02X\r\n", header_byte);
    LQ_DEBUG_PKT("||     Target-ID: " FMT_CID "\r\n", target_id);
    LQ_DEBUG_PKT("|| Packet Number: " FMT_PN "\r\n", packet_nb);


    while(packet->len > (pos - (packet->buf))) {
        // decode stread id
        TYPE_STREAM_ID id;
        dec1(&id, &pos, end);
        if(STREAM_ID_ACK1 == id || STREAM_ID_ACK2 == id) {
            TYPE_PACKET_NUMBER lg_ack = 0;
            decv(&lg_ack, &pos, end);
            TYPE_TIMER_US ack_delay = 0;
            decv(&ack_delay, &pos, end);
            uint64_t ack_rng_cnt = 0;
            decv(&ack_rng_cnt, &pos, end);

            // this is a similar loop as in dec_ack_frame() - keep changes in sync
            uint64_t n;
            LQ_DEBUG_PKT("||   Stream[" FMT_SID "]:", id);
            for (n = ack_rng_cnt + 1; n > 0; n--) {
                uint64_t ack_rng = 0;
                decv(&ack_rng, &pos, end);

                LQ_DEBUG_PKT(" [%llu:%llu]", lg_ack, (lg_ack - ack_rng));

                if (n > 1) {
                    uint64_t gap = 0;
                    decv(&gap, &pos, end);
                    lg_ack -= ack_rng + gap + 2;
                }
            }
            LQ_DEBUG_PKT("\r\n");
            continue;
        }
        // decode stream offset
        TYPE_STREAM_OFFSET offset;
        decv(&offset, &pos, end);
        // encode stream length
        TYPE_STREAM_LENGTH stream_len;
        dec2(&stream_len, &pos, end);
        LQ_DEBUG_PKT("||   Stream[" FMT_SID "]: Offset: %llu, Length: %d at buffer data from %p\r\n", id, offset, stream_len, pos);
        pos += stream_len;
        if(pos > end) {
            LQ_DEBUG_PKT("[LOG PACKET] Fatal: stream end of packet\r\n");
            exit(0);
        }
    }
//    LQ_DEBUG_PKT("-------- End of Logger %s for packet %p-----------------------------------------------------------------------------------\r\n", logger, packet);
}

// NOTE: 应用是建立在RLINK基础上的，也就是说，一个RLINK，不管多少CONNECTION，它们处理的工作是一样的。这样设计有利于CLIENT和SERVER的一致性。
// 一个RLINK可以存在多个链接，特别是SERVER端，当链接建立后，需要为每个CONNECTION分配其上下文（为STREAM？）

struct application_ctx_demo {
	int read_bytes;
};

struct server_ctx_demo {
	TYPE_STREAM_OFFSET app_16_offset;
	int send_bytes;
};

#define DEMO_TRANSFER_BLOCK_SIZE 100
#define DEMO_BLOCK_CONTENT  "2345678901234567890123456789012345678901234567890123456789012345678901234567890"

// NOTE: 也许可以设计，当 stream_id == 0 的是否，是connection初期建立。
int application_impl(pRCONNECTION connection, TYPE_STREAM_ID id, cyg_uint32 event, void *ctx) {
	struct application_ctx_demo *demo_ctx = (struct application_ctx_demo *)ctx;
	if(0 == id) {
		// ASERT(demo_ctx == NULL);
		connection->priv_t = calloc(1, sizeof(struct application_ctx_demo));
		LQ_DEBUG_APPL("[DEBUG:APPL] new connection for client\r\n");

		// STREAM OPEN(connection, 16 /* STREAM_ID */, CONNECTION_EVENT_READABLE);
		request_read(connection, 16);
	} else if(1 == id) {
		free(connection->priv_t);
		LQ_DEBUG_APPL("[DEBUG:APPL] should be destroyed connection for client\r\n");
	} else if(16 == id ) {
		if(event == EVENT_ID_READABLE) {
			// LQ_DEBUG_APPL("[DEBUG:APPL] {Client} connection for client\r\n");
			char buf[128];
			int len = lq_read(connection, 16, buf, 1);
//			len += lq_read(connection, 16, &buf[1], 1);
//			len += lq_read(connection, 16, &buf[2], sizeof(DEMO_BLOCK_CONTENT) - len);
			LQ_DEBUG_APPL("[DEBUG:APPL] {Client} Get size %d\r\n", len);

			demo_ctx->read_bytes += len;
			if(demo_ctx->read_bytes < (DEMO_TRANSFER_BLOCK_SIZE * sizeof(DEMO_BLOCK_CONTENT))) {
				request_read(connection, 16);
			} else
				// Delay 2000 us to get test OK.
				request_timer(connection, 16, 2000);
		} else if(event == EVENT_ID_TIMER) {
			connection->rlink->test_ok = TRUE;
			LQ_DEBUG_APPL("[DEBUG:APPL] {Client} Test OK!!!\r\n");
		}
	} else {
		LQ_DEBUG_APPL("[DEBUG:APPL] {Client} connection [%s] on Stream[" FMT_SID "]\r\n", event_name[event], id);
	}
}

#if 0
void application_impl(CONNECTION_EVENT *event) {
	void *connection_t = event->connection;
	struct application_ctx_demo *demo_ctx;
	CONNECTION_EVENT e;
	switch(event->type) {
	CONNECTION_INITIAL:
		e.type = CONNECTION_APPCTX;
		demo_ctx = calloc(1, sizeof(*demo_ctx));
		e.ctx = demo_ctx;
		lqevent(connection_t, &e);
		e.type = REQUEST_READ;
		e.ctx = 16; /* stream id */
		lqevent(connection_t, &e);
		break;
	CONNECTION_DESTROY:
		demo_ctx = event->ctx;
		// Do something about ctx!?
		free(demo_ctx);
		LQ_DEBUG_APPL("[DEBUG:APPL] should be destroyed connection for client\r\n");
		break;
	CONNECTION_TIMER:
		e.type = REQUEST_WRITE;
		e.ctx = 16; /* stread id */
		lqevent(connection_t, &e);
		break;
	CONNECTION_READ:
		if(event->ctx == 16) {
			int len = lq_write(connection, 16, DEMO_BLOCK_CONTENT, sizeof(DEMO_BLOCK_CONTENT));
			if(len > 0)
				demo_ctx->send_bytes += len;
			else
				LQ_DEBUG_APPL("[DEBUG:APPL] {Server} Write operation depended\r\n");

			if(demo_ctx->send_bytes < (DEMO_TRANSFER_BLOCK_SIZE * sizeof(DEMO_BLOCK_CONTENT))) {
				e.type = REQUEST_WRITE;
				e.ctx = 16; /* stread id */
				lqevent(connection_t, &e);
			} else {
				e.type = APP_SPECIAL;
				e.ctx = 16; /* stread id */
				lqevent(connection_t, &e);
			}
		}
		break;
	CONNECTION_APP:
		LQ_DEBUG_APPL("[DEBUG:APPL] {Server} Test OK!!!\r\n");
		// connection->rlink->test_ok = TRUE;
		e.type = CONNECTION_DEBUG;
		e.ctx = 0; /* stream id */

		// or: lq_write(connection_t, 0 /* control stream id */, CONNECTION_DEBUG /* key */, TEST_OK /* value */, sizeof(TEST_OK) /* sizeof value */);
		lqevent(connection_t, &e);
		break;
	default:
		LQ_DEBUG_APPL("[DEBUG:APPL] server error.\r\n");
		break;
	}
}

void server_impl(CONNECTION_EVENT *event) {
	void *connection_t = event->connection;
	struct server_ctx_demo *demo_ctx;
	CONNECTION_EVENT e;

	switch(event->type) {
	CONNECTION_INITIAL:
		e.type = CONNECTION_APPCTX;
		demo_ctx = calloc(1, sizeof(*demo_ctx));
		e.ctx = demo_ctx;
		lqevent(connection_t, &e);
		e.type = REQUEST_TIMER;
		e.ctx = 20; /* us */
		lqevent(connection_t, &e);
		break;
	CONNECTION_DESTROY:
		demo_ctx = event->ctx;
		// Do something about ctx!?
		free(demo_ctx);
		LQ_DEBUG_APPL("[DEBUG:APPL] should be destroyed connection for server\r\n");
		break;
	CONNECTION_TIMER:
		e.type = REQUEST_WRITE;
		e.ctx = 16; /* stread id */
		lqevent(connection_t, &e);
		break;
	CONNECTION_WRITE:
		if(event->ctx == 16) {
			int len = lq_write(connection, 16, DEMO_BLOCK_CONTENT, sizeof(DEMO_BLOCK_CONTENT));
			if(len > 0)
				demo_ctx->send_bytes += len;
			else
				LQ_DEBUG_APPL("[DEBUG:APPL] {Server} Write operation depended\r\n");

			if(demo_ctx->send_bytes < (DEMO_TRANSFER_BLOCK_SIZE * sizeof(DEMO_BLOCK_CONTENT))) {
				e.type = REQUEST_WRITE;
				e.ctx = 16; /* stread id */
				lqevent(connection_t, &e);
			} else {
				e.type = APP_SPECIAL;
				e.ctx = 16; /* stread id */
				lqevent(connection_t, &e);
			}
		}
		break;
	CONNECTION_APP:
		LQ_DEBUG_APPL("[DEBUG:APPL] {Server} Test OK!!!\r\n");
		// connection->rlink->test_ok = TRUE;
		e.type = CONNECTION_DEBUG;
		e.ctx = 0; /* stream id */

		// or: lq_write(connection_t, 0 /* control stream id */, CONNECTION_DEBUG /* key */, TEST_OK /* value */, sizeof(TEST_OK) /* sizeof value */);
		lqevent(connection_t, &e);
		break;
	default:
		LQ_DEBUG_APPL("[DEBUG:APPL] server error.\r\n");
		break;
	}
}
#endif

int server_impl(pRCONNECTION connection, TYPE_STREAM_ID id, cyg_uint32 event, void *ctx) {
	struct server_ctx_demo *demo_ctx  = (struct server_ctx_demo *)ctx;
	if(0 == id) {
		connection->priv_t = calloc(1, sizeof(struct server_ctx_demo));
		LQ_DEBUG_APPL("[DEBUG:APPL] new connection for server\r\n");

		// Register event interesting for STREAM_ID 16.
		// Delay 20 us to write message.
		request_timer(connection, 16, 20);
	} else if(1 == id) {
		free(connection->priv_t);
		LQ_DEBUG_APPL("[DEBUG:APPL] should be destroyed connection for server\r\n");
	} else if(16 == id) {
		if(event == EVENT_ID_TIMER) {
			LQ_DEBUG_APPL("[DEBUG:APPL] !!!!!!!!!!!! TIMER !!!!!!!!!!!!!!!!!!!!\r\n");
			request_write(connection, 16);
		} else if((event == EVENT_ID_WRITEABLE) && demo_ctx->send_bytes < (DEMO_TRANSFER_BLOCK_SIZE * sizeof(DEMO_BLOCK_CONTENT))) {
			int len = lq_write(connection, 16, DEMO_BLOCK_CONTENT, sizeof(DEMO_BLOCK_CONTENT));
			if(len > 0) {
				LQ_DEBUG_APPL("[DEBUG:APPL] {Server} Push server stream\r\n");
				demo_ctx->send_bytes += len;
				demo_ctx->app_16_offset += sizeof(DEMO_BLOCK_CONTENT);
			} else {
				LQ_DEBUG_APPL("[DEBUG:APPL] {Server} Write operation depended\r\n");
			}
			request_write(connection, 16);
		} else if((event == EVENT_ID_WRITEABLE) && demo_ctx->app_16_offset >= (DEMO_TRANSFER_BLOCK_SIZE * sizeof(DEMO_BLOCK_CONTENT))) {
			LQ_DEBUG_APPL("[DEBUG:APPL] {Server} Test OK!!!\r\n");
			connection->rlink->test_ok = TRUE;
		}
	} else {
		LQ_DEBUG_APPL("[DEBUG:APPL] {Server} connection [%s] on Stream[" FMT_SID "]\r\n", event_name[event], id);
	}
}

TYPE_TIMER_US getCurrentTimeUS(void) {
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return 1000000 * tv.tv_sec + tv.tv_usec;
}

static void rlink_test_loop(int sleep_sec) {
    int loop_times = 0;
    pRLINK server, client;

    // Create Server
    RLINK_ADDR server_addr;
    memset(server_addr.addr, 0x0, sizeof(server_addr.addr));
    memcpy(server_addr.addr, "1111111111", sizeof("1111111111"));
    server = rlink_create(FALSE, &server_addr);
    register_application(server, server_impl, NULL);

    // Create Client
    RLINK_ADDR client_addr;
    memset(client_addr.addr, 0x0, sizeof(client_addr.addr));
    memcpy(client_addr.addr, "9999999999", sizeof("9999999999"));
    client = rlink_create(TRUE, &client_addr);
    register_application(client, application_impl, NULL);

    // get Client connection to Server, this trigger connect.
    pRCONNECTION connection = rlink_connect(client, &server_addr);

    RPACKET packet;

    while(TRUE) {

    // LQ_DEBUG_CORE("--------------------- Loop: %d -------------------------------------\r\n", loop_times++);

        // 模拟网络时间
		client->current_time_us = getCurrentTimeUS();

		// 清理stream中已经用完的stream buffer空间。
		// 老化超过 RTT 的 stream_buffer
    	client->debug_prompt = "CLEAN";
		rlink_cleanstream(client);

        // 处理rlink向上层（内部控制层、应用层）提交的数据。因为状态的变迁、收到新的报文等因素，
        // 内部stream存在需要上层处理的数据，需要通知、调用上层功能进行处理。
        // TODO: named to stream_egress ?
    	client->debug_prompt = "UPSTREAM";
		rlink_upstream(client);

		// rlink完成了内部状态的变迁后，存在需要发送的数据，
		// 组织这些数据到packet并发送到目的地。

		for(;;) {
			// 从client组织packet
	    	client->debug_prompt = "EGRESS";
			rlink_egress(client, &packet);
			if(0 == packet.len)
				break;

			// TODO: fill packet src and dst address here

			// TODO: 更好地模拟网络发送的过程，应该是用 client的packet数据拷贝到server的接收packet空间。

			// Ingree c.packet to Server
			if(islucky())
			{
				server->debug_prompt = "INGRESS";
				if(NO_ERROR != rlink_ingress(server, &packet))
					break;
			}
			else {
				packet.connection->lost_packet++;
			}
		}

		// 模拟网络时间
		server->current_time_us = getCurrentTimeUS();

		// 清理stream中已经用完的stream buffer空间。
    	server->debug_prompt = "CLEAN";
		rlink_cleanstream(server);

    	server->debug_prompt = "UPSTREAM";
		rlink_upstream(server);

		for(;;) {
	    	server->debug_prompt = "EGRESS";
			rlink_egress(server, &packet);
			if(0 == packet.len)
				break;

			// TODO: fill packet src and dst address here
	// Ingress s.packet to Client
			if(islucky())
			{
				client->debug_prompt = "INGRESS";
				if(NO_ERROR != rlink_ingress(client, &packet)) {
					break;
				}
			}
			else packet.connection->lost_packet++;
		}

		if(sleep_sec)
			sleep(sleep_sec);

    	if(stop_condiction(server, client)) break;
    }

    show_rlink(client);
    show_rlink(server);

    rlink_destroy(client);
    rlink_destroy(server);
}

int main(int argc, char *argv[]) {
	signal(SIGHUP, sigroutine); //* 下面设置三个信号的处理方法
	signal(SIGINT, sigroutine);
	signal(SIGQUIT, sigroutine);
	signal(SIGSEGV, sigroutine);
	signal(SIGABRT, sigroutine);

	int loop_times = 0;
	int sleep_sec = 0;

	int option;
	// put ':' at the starting of the string so compiler can distinguish between '?' and ':'
	while((option = getopt(argc, argv, ":n:s:")) != -1) {
		//get option from the getopt() method
		switch(option){
			case 'n':
				loop_times = atoi(optarg);
				break;
			case 's':
				sleep_sec = atoi(optarg);
				break;
			case ':':
				printf("option needs a value\n");
				break;
			case '?': //used for some unknown options
				printf("unknown option: %c\n", optopt);
				break;
			}
	}

	int fd = fileno(stdin);
	int flags  = fcntl(fd, F_GETFL, 0 );
	flags |= O_NONBLOCK;
	flags = fcntl(fd, F_SETFL, flags);

	time_t t;
	/* Intializes random number generator */
	srand((unsigned) time(&t));

	for(int i = 0; (i <= loop_times) && (global_stop == 0); i++)
		rlink_test_loop(sleep_sec);

	return 0;
}
