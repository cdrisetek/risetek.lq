#include "rlink.h"
#include <string.h>
#include <errno.h>
#include "lib/marshall.h"

#define CLIENTHELLO "ClientHELLO"
#define HANDSHAKE   "HandShake"

const STREAM_ARRT STREAM_EGRESS_ATTR[] = {
		{ (STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER | STREAM_CORE), NULL}, // STREAM_ID_CRYPTO
		{ (STREAM_EGRESS_ACK | STREAM_CORE), NULL}, // STREAM_ID_ACK1
		{ (STREAM_EGRESS_ACK | STREAM_CORE), NULL}, // STREAM_ID_ACK2
		{ 0, NULL}, // STREAM_ID_3
		{ 0, NULL}, // STREAM_ID_4
		{ 0, NULL}, // STREAM_ID_5
		{ 0, NULL}, // STREAM_ID_6
		{ 0, NULL}, // STREAM_ID_7

		{ 0, NULL}, // STREAM_ID_8
		{ 0, NULL}, // STREAM_ID_9
		{ 0, NULL}, // STREAM_ID_10
		{ 0, NULL}, // STREAM_ID_11
		{ 0, NULL}, // STREAM_ID_12
		{ 0, NULL}, // STREAM_ID_13
		{ 0, NULL}, // STREAM_ID_14
		{ 0, NULL}, // STREAM_ID_15

		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_16
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_17
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_18
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_19
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_20
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_21
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_22
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_23
};

const STREAM_ARRT STREAM_INGRESS_ATTR[] = {
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER | STREAM_INGRESS_IMM_ACK | STREAM_CORE), NULL},     // STREAM_ID_CRYPTO
		{ STREAM_CORE, NULL}, // STREAM_ID_ACK1
		{ STREAM_CORE, NULL}, // STREAM_ID_ACK2
		{ 0, NULL}, // STREAM_ID_3
		{ 0, NULL}, // STREAM_ID_4
		{ 0, NULL}, // STREAM_ID_5
		{ 0, NULL}, // STREAM_ID_6
		{ 0, NULL}, // STREAM_ID_7

		{ 0, NULL}, // STREAM_ID_8
		{ 0, NULL}, // STREAM_ID_9
		{ 0, NULL}, // STREAM_ID_10
		{ 0, NULL}, // STREAM_ID_11
		{ 0, NULL}, // STREAM_ID_12
		{ 0, NULL}, // STREAM_ID_13
		{ 0, NULL}, // STREAM_ID_14
		{ 0, NULL}, // STREAM_ID_15

		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_16
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_17
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_18
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_19
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_20
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_21
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_22
		{(STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER),  NULL}, // STREAM_ID_23
};

const STREAM_ARRT CORE_STREAM_INGRESS_ATTR[] = {
		{(STREAM_CORE | STREAM_HAS_OFFSET | STREAM_HAS_LENGTH | STREAM_HAS_BUFFER | STREAM_INGRESS_IMM_ACK), NULL},     // STREAM_ID_CRYPTO
		{(STREAM_CORE), NULL}, // STREAM_ID_ACK1
		{(STREAM_CORE), NULL}, // STREAM_ID_ACK2
		{ 0, NULL}, // STREAM_ID_3
		{ 0, NULL}, // STREAM_ID_4
		{ 0, NULL}, // STREAM_ID_5
		{ 0, NULL}, // STREAM_ID_6
		{ 0, NULL}, // STREAM_ID_7
};

// find and set linker's next to linker
static struct SLinker *nextslink(struct SLinker *linker, TYPE_STREAM_OFFSET *offset,
		TYPE_STREAM_LENGTH *stream_len, const cyg_uint8 **retpos) {
	pRPACKET p = (pRPACKET)linker->packet;
	const cyg_uint8 *pos = &p->buf[linker->soffset];
	cyg_uint8 *end = &p->buf[p->len];
	TYPE_STREAM_ID item; // this for fitem.
    dec1(&item, &pos, end);

    // decode stream offset
    TYPE_STREAM_OFFSET _offset;
	decv(&_offset, &pos, end);
    if(NULL != offset)
    	*offset = _offset;
    // decode stream length
    TYPE_STREAM_LENGTH _stream_len;
	dec2(&_stream_len, &pos, end);
    if(NULL != stream_len)
    	*stream_len = _stream_len;
    if(retpos != NULL)
    	*retpos = pos;
    struct SLinker *links = (struct SLinker *)&p->buf[p->len];
    return &links[item];
}

// 从 stream 读取期望数量的数据。
TYPE_BUFFER_SIZE lq_read(pRCONNECTION connection, TYPE_STREAM_ID id, char *buffer, TYPE_BUFFER_SIZE length) {
	pRLINK rlink = connection->rlink;
	pINSTREAM stream = &connection->ingress_streams[id];
	struct SLinker *linker = &stream->slinker;

	TYPE_STREAM_OFFSET offset = 0;
	TYPE_STREAM_LENGTH stream_len = 0;
	const cyg_uint8 *pos;

	TYPE_BUFFER_SIZE l = 0;
	while(l < length) {
		pRPACKET p = (pRPACKET)linker->packet;
		if(NULL == p)
			break;

		struct SLinker *next = nextslink(linker, &offset, &stream_len, &pos);

		if(stream->offset != (offset + stream->leave_offset)) {
			LQ_DEBUG_CORE("[%s] {%s} lq_read failed, available: %llu, request: %llu\r\n",
					rlink->debug_prompt, CSPROMPT(rlink),
					stream->offset, offset);
			break;
		}

		TYPE_STREAM_LENGTH to_read = length - l;
		to_read = to_read > stream_len ? stream_len:to_read;

		pos += stream->leave_offset;
		stream->leave_offset += to_read;
		if(stream->leave_offset == stream_len) {
			p->ref--;
			linker->packet = next->packet;
			linker->soffset = next->soffset;
			stream->leave_offset = 0;
		}

		memcpy(buffer, pos, to_read);
		l += to_read;
		buffer += to_read;

		stream->avaliable_len -= to_read;
		stream->offset += to_read;

	}
	return l;
}

// 从 stream 读取期望数量的数据。
static int stream_read(pRCONNECTION connection, TYPE_STREAM_ID id, char *buffer, int length) {
	return lq_read(connection, id, buffer, length);
}

static int crypto_egress_stream_process(pRCONNECTION connection, pESTREAM stream) {
	pRLINK rlink = connection->rlink;

	if(stream->offset == 0) {
		LQ_DEBUG_CORE("[%s] {%s} Crypto egress initial stream\r\n", rlink->debug_prompt, CSPROMPT(rlink));

		lq_write(connection, STREAM_ID_CRYPTO, (cyg_uint8 const *)CLIENTHELLO, sizeof(CLIENTHELLO));
        // Stream 0 发送LocalCID到对端
        lq_write(connection, STREAM_ID_CRYPTO, (cyg_uint8 *)&connection->local_cid, sizeof(connection->local_cid));
	}

	if(connection->state >= connection_handshake && (stream->offset == sizeof(CLIENTHELLO) + sizeof(connection->local_cid))) {
		LQ_DEBUG_CORE("[%s] {%s} Crypto egress handshake stream\r\n", rlink->debug_prompt, CSPROMPT(rlink));
		lq_write(connection, STREAM_ID_CRYPTO, (cyg_uint8 const *)HANDSHAKE, sizeof(HANDSHAKE));
		stream->interesting_event &= ~CONNECTION_EVENT_WRITEABLE;
	}

	return NO_ERROR;
}

static int crypto_ingress_stream_process(pRCONNECTION connection, pINSTREAM stream) {
	pRLINK rlink = connection->rlink;

	if(stream->id != STREAM_ID_CRYPTO) {
		LQ_DEBUG_ERROR("[%s] {%s} Error on crypto_ingress_stream_process, stream id: %d\r\n",
				rlink->debug_prompt, CSPROMPT(rlink), stream->id);
		return PROTOCOL_VIOLATION;
	}

	if(stream->avaliable_len == 0) {
		LQ_DEBUG_ERROR("[%s] {%s} Crypto_ingress_stream_process no avaliable\r\n",
				rlink->debug_prompt, CSPROMPT(rlink));
		return PROTOCOL_VIOLATION;
	}

	char buffer[100];
	if(stream->offset == 0) {

		int len = stream_read(connection, stream->id, buffer, sizeof(CLIENTHELLO) + sizeof(connection->target_cid));
#if 0
		if( stream_read(connection, stream->id, buffer, sizeof(CLIENTHELLO)) != sizeof(CLIENTHELLO)) {
			LQ_DEBUG_ERROR("[%s] {%s} 1 Crypto_ingress_stream_process protocol violate\r\n",
					rlink->debug_prompt, CSPROMPT(rlink));
			exit(0);
			return PROTOCOL_VIOLATION;
		}
#endif

		if(memcmp(buffer, CLIENTHELLO, sizeof(CLIENTHELLO)) != 0) {
			LQ_DEBUG_ERROR("[%s] {%s} 2 Crypto_ingress_stream_process protocol violate\r\n",
					rlink->debug_prompt, CSPROMPT(rlink));
			exit(0);
			return PROTOCOL_VIOLATION;
		}

		LQ_DEBUG_CORE("[%s:CORE] {%s} Read 'HELLO'\r\n", rlink->debug_prompt, CSPROMPT(rlink));

		memcpy(&connection->target_cid, &buffer[sizeof(CLIENTHELLO)], sizeof(connection->target_cid));
		connection->state = connection_handshake;
		LQ_DEBUG_CORE("[%s:CORE] {%s} Read Destination CID:" FMT_CID "\r\n",
				rlink->debug_prompt, CSPROMPT(rlink), connection->target_cid);

	}
#if 0
	if(stream->offset == sizeof(CLIENTHELLO)) {
		if( stream_read(connection, stream->id, buffer, sizeof(connection->target_cid)) != sizeof(connection->target_cid)) {
			LQ_DEBUG_ERROR("[%s] {%s} 3 Crypto_ingress_stream_process protocol violate\r\n",
					rlink->debug_prompt, CSPROMPT(rlink));
			exit(0);
			return PROTOCOL_VIOLATION;
		}

		memcpy(&connection->target_cid, buffer, sizeof(connection->target_cid));
		connection->state = connection_handshake;
		LQ_DEBUG_CORE("[%s:CORE] {%s} Read Destination CID:" FMT_CID "\r\n",
				rlink->debug_prompt, CSPROMPT(rlink), connection->target_cid);
	}
#endif
	if((stream->avaliable_len != 0) && (stream->offset == sizeof(CLIENTHELLO) + sizeof(connection->target_cid))) {
		if( stream_read(connection, stream->id, buffer, sizeof(HANDSHAKE)) != sizeof(HANDSHAKE)) {
			LQ_DEBUG_ERROR("[%s] {%s} 4 Crypto_ingress_stream_process protocol violate\r\n", rlink->debug_prompt, CSPROMPT(rlink));
			exit(0);
			return PROTOCOL_VIOLATION;
		}

		LQ_DEBUG_CORE("[%s:CORE] {%s} Read HandShake\r\n", rlink->debug_prompt, CSPROMPT(rlink));
		// advanced to 1-RTT.
		connection->state = connection_idle;
	}
	return NO_ERROR;
}

static int core_egress_stream_process(pRCONNECTION connection, pESTREAM stream) {
	pRLINK rlink = connection->rlink;
	switch(stream->id) {
	case STREAM_ID_CRYPTO:
		return crypto_egress_stream_process(connection, stream);
	case STREAM_ID_ACK1:
	case STREAM_ID_ACK2:
		break;
	default:
		LQ_DEBUG_CORE("[%s:CORE] {%s} Core egress Stream[" FMT_SID "] failed\r\n", rlink->debug_prompt, CSPROMPT(rlink), stream->id);
		break;
	}
	return NO_ERROR;
}

static int core_ingress_stream_process(pRCONNECTION connection, pINSTREAM stream) {
	pRLINK rlink = connection->rlink;
	switch(stream->id) {
	case STREAM_ID_CRYPTO:
		return crypto_ingress_stream_process(connection, stream);
	case STREAM_ID_ACK1:
	case STREAM_ID_ACK2:
		break;
	default:
		LQ_DEBUG_CORE("[%s:CORE] {%s} Core egress Stream[" FMT_SID "] failed\r\n", rlink->debug_prompt, CSPROMPT(rlink), stream->id);
		break;
	}
	return NO_ERROR;
}

static int application_egress_stream_process(pRCONNECTION connection, pESTREAM stream, cyg_uint32 event_id) {
	pRLINK rlink = connection->rlink;

	stream->interesting_event &= ~(1 << event_id);
	(connection->rlink->link_handler)(connection, stream->id, event_id, connection->priv_t);
	return NO_ERROR;
}

static int application_ingress_stream_process(pRCONNECTION connection, pINSTREAM stream) {
	pRLINK rlink = connection->rlink;

	stream->interesting_event &= ~CONNECTION_EVENT_READABLE;
	(connection->rlink->link_handler)(connection, stream->id, EVENT_ID_READABLE, connection->priv_t);

	return NO_ERROR;
}

// 根据缓存空间和其它逻辑判断。
BOOL connection_is_writeable(pRCONNECTION connection) {
	if(connection->rlink->free_stream_header != NULL)
		return TRUE;
	else
		return FALSE;
}

BOOL stream_is_writeable(pRCONNECTION connection, pESTREAM pstream) {
	if((connection->rlink->free_stream_header != NULL) && (pstream->pending_size < DEFAULT_MAX_PENDING_SIZE))
		return TRUE;
	else
		return FALSE;
}

/**
 * 处理各个RSTREAM内部的数据，向上层（应用层）提交接收好的RSTREAM数据
 **/

static void connection_upstream(pRCONNECTION connection) {
	pRLINK rlink = connection->rlink;
    int loop;

    // INGRESS process
    for(loop = 0; loop < sizeof(STREAM_INGRESS_ATTR)/sizeof(STREAM_INGRESS_ATTR[0]); loop++) {
    	pINSTREAM pstream = &connection->ingress_streams[loop];
    	if(pstream->slinker.packet == NULL)
    		continue;
		// for core stream, always readable
		if(STREAM_INGRESS_ATTR[loop].type & STREAM_CORE)
			core_ingress_stream_process(connection, pstream);
		else if((rlink->link_handler != NULL)
				&& (pstream->interesting_event & CONNECTION_EVENT_READABLE)
				&& (pstream->notify_event & CONNECTION_EVENT_READABLE)) {
			// TODO: connection state should be idle
			application_ingress_stream_process(connection, pstream);
		}

		// READ完成后，重新判断stream是否有数据可读
		pstream->notify_event &= ~CONNECTION_EVENT_READABLE;
		struct SLinker *slinker =  &pstream->slinker;
		TYPE_STREAM_OFFSET _o;
		if(slinker->packet != NULL) {
			slinker = nextslink(slinker, &_o, NULL, NULL);
			if((_o + pstream->leave_offset) == pstream->offset)
				pstream->notify_event |= CONNECTION_EVENT_READABLE;
		}
    }

    // EGRESS process
	for(loop = 0; loop < sizeof(STREAM_EGRESS_ATTR)/sizeof(STREAM_EGRESS_ATTR[0]); loop++) {
		pESTREAM pstream = &connection->egress_streams[loop];

		// TIMER Process
		if(((STREAM_EGRESS_ATTR[loop].type & STREAM_CORE) == 0)
				&& (rlink->link_handler != NULL)
				&& (connection->state == connection_idle)
				&& (pstream->interesting_event & CONNECTION_EVENT_TIMER)
				&& (pstream->timer_interesting < rlink->current_time_us)) {
            LQ_DEBUG_CORE("TIMER %llu -- %llu\r\n", pstream->timer_interesting, rlink->current_time_us);
			application_egress_stream_process(connection, pstream, EVENT_ID_TIMER);
		}

		// TODO: check on stream.
		if(!(connection_is_writeable(connection)))
			continue;

		// for core stream, always writeable.
		if(STREAM_EGRESS_ATTR[loop].type & STREAM_CORE) {
			core_egress_stream_process(connection, pstream);
		} else if((rlink->link_handler != NULL)
				&& (connection->state == connection_idle)
				&& stream_is_writeable(connection, pstream)
				&& (pstream->interesting_event & CONNECTION_EVENT_WRITEABLE)) {
			application_egress_stream_process(connection, pstream, EVENT_ID_WRITEABLE);
		}

	}

    // Free unalloced packet space in connections.
    /**
     * packet 的 ref 计数为 0，说明这个packet已经被使用完毕，可以回归到 rlink的 free 队列。
     */

	pRPACKET *ppacket = &connection->received_packet_header;
	while(NULL != *ppacket) {
		if((*ppacket)->ref == 0) {
			pRPACKET p = *ppacket;
			*ppacket = (*ppacket)->next;

			p->next = connection->rlink->free_packets;
			connection->rlink->free_packets = p;
		}
		else
			ppacket = &(*ppacket)->next;
	}
}

void rlink_upstream(pRLINK rlink) {
    pRCONNECTION pRCONNECTION = rlink->connections_mgr.connection_header;
    for(; pRCONNECTION != NULL; pRCONNECTION = pRCONNECTION->next)
        connection_upstream(pRCONNECTION);
}

pRLINK rlink_create(BOOL isClient, pRLINK_ADDR addr) {
    pRLINK link = (pRLINK)calloc(1, sizeof(*link));
    link->isClient = isClient;
    memset(&link->addr.addr, 0x0, sizeof(link->addr.addr));
    RLINK_ADDR_CPY(&link->addr, addr);

    // for CID Genetator.
    link->base_link_id = rand();
    link->connections_mgr.connection_header = NULL;
    link->test_ok = 0;
    link->current_time_us = 0;
    link->protocol_violate = FALSE;
    link->sending_packet_header = NULL;
    // pRPACKET
    link->free_packets = NULL;
    int index;
    for(index = 0; index < sizeof(link->__packets)/sizeof(link->__packets[0]); index++)
    	LQQ_INSERT_HEAD((link->free_packets), (&link->__packets[index]));

    // RSTREAM_BUFFER
    // 初始化stream接收buffer的链表结构。
    for(index = 0; index < sizeof(link->__stream_buffer)/sizeof(link->__stream_buffer[0]); index++)
    	LQQ_INSERT_HEAD((link->free_stream_header), (&link->__stream_buffer[index]));

    return link;
}

void connection_destroy(pRCONNECTION connection) {
    if(connection->rlink->link_handler)
    	(connection->rlink->link_handler)(connection, 1, 0, NULL);

    free(connection);
}

void rlink_destroy(pRLINK rlink) {
    while(NULL != rlink->connections_mgr.connection_header) {
        pRCONNECTION connection = rlink->connections_mgr.connection_header;
        rlink->connections_mgr.connection_header = connection->next;

    	connection_destroy(connection);
    }

    free(rlink);
}

pRCONNECTION _new_connection(pRLINK link, pRLINK_ADDR addr) {
    pRCONNECTION connection = (pRCONNECTION)calloc(1, sizeof(*connection));
    //pRLINK_ADDR to = &connection->peer_addr;
    RLINK_ADDR_CPY(&connection->peer_addr, addr);
    connection->state = connection_init;
    connection->packet_nb = INIT_PACKET_NUMBER;
//    connection->pn_space.need_ack = FALSE;
    connection->received_packet_header = NULL;
    connection->rtt_us = DEFAULT_RTT_US;
    connection->rlink = link;
    diet_init(&connection->pn_space.recv);

    int loop;

    for(loop = 0; loop < sizeof(connection->egress_streams)/sizeof(connection->egress_streams[0]); loop++) {
        connection->egress_streams[loop].id = loop;
        connection->egress_streams[loop].buffer_header = NULL;
        connection->egress_streams[loop].offset = 0;

        connection->ingress_streams[loop].id = loop;
        connection->ingress_streams[loop].offset = 0;
    }

    connection->local_cid = link->base_link_id++;
    connection->target_cid = RLINK_CID_NULL;

    if(link->link_handler)
    	(link->link_handler)(connection, 0, 0, NULL);

    return connection;
}

/**
 * 检测每个stream的buffer，如果这些buffer已经承载到packet上，并且经历
 * 了 RTT 的时常后没有被确认，那么这些buffer被认为是丢失了，更新其状态，等待重发。
 *
 * TODO: 还有一种办法是判断packet是不是超时未被确认，从而利用packet number判断
 * buffer是否丢失。
 */

static inline void connection_cleanstream(pRCONNECTION connection) {
	pRLINK rlink = connection->rlink;
    int loop;
    for(loop = 0; loop < sizeof(connection->egress_streams)/sizeof(connection->egress_streams[0]); loop++) {
    	pESTREAM stream = &connection->egress_streams[loop];
    	if((STREAM_EGRESS_ATTR[stream->id].type & STREAM_HAS_BUFFER) == 0)
    		continue;

    	pRSTREAM_BUFFER pbuffer = stream->buffer_header;
		for(; pbuffer != NULL; pbuffer = pbuffer->next) {
			if((pbuffer->packet_nb != MIN_PACKET_NUMBER)
				&& (rlink->current_time_us > (pbuffer->time_us + 20*connection->rtt_us))) {
				// 激活超过 RTT 的 stream buffer
				stream->timeout_frames++;
				pbuffer->packet_nb = MIN_PACKET_NUMBER;
			}
		}
    }
}

void rlink_cleanstream(pRLINK rlink) {
    pRCONNECTION pRCONNECTION = rlink->connections_mgr.connection_header;
    for(; pRCONNECTION != NULL; pRCONNECTION = pRCONNECTION->next)
        connection_cleanstream(pRCONNECTION);
}

static void cleanstream_range_connection(pRCONNECTION connection, TYPE_PACKET_NUMBER max, TYPE_PACKET_NUMBER min) {
	pRLINK rlink = connection->rlink;

	// ACK for ACK process
	/*
	 * * 接收到的packet包含inACK
	 * * inACK确认的egress PACKET中包含发送的eACK
	 * * eACK所指明的packet number是用于确认接收到的远端发送的报文包号(ingress pn)
	 * * 这个阶段说明远端已经确认发送达到,本地端整理ingress pn space,不再确认已经被确认了的pn.
	 */
    struct ival * b;
	if(connection->ack_pn <= max && connection->ack_pn >= min) {
		LQ_DEBUG_CORE("[%s] {%s} <%llu-%llu-%llu> ack for ack:", rlink->debug_prompt,
				      CSPROMPT(rlink), min, connection->ack_pn, max);
		diet_foreach_rev (b, diet, &connection->acked) {
			LQ_DEBUG_CORE(" [%u:%u]", b->lo, b->hi);
			diet_remove_ival(&connection->pn_space.recv,
							 &(const struct ival){.lo = b->lo, .hi = b->hi});
		}
		LQ_DEBUG_CORE("\r\n");

		diet_free(&connection->acked);
	}

	int loop;
    for(loop = 0; loop < sizeof(connection->egress_streams)/sizeof(connection->egress_streams[0]); loop++) {
    	pESTREAM stream = &connection->egress_streams[loop];

    	pRSTREAM_BUFFER *ppbuffer = &stream->buffer_header;
        while(NULL != *ppbuffer) {
            pRSTREAM_BUFFER pbuffer = *ppbuffer;
           if((pbuffer->packet_nb != MIN_PACKET_NUMBER)
        	  && (pbuffer->packet_nb >= min && pbuffer->packet_nb <= max)) {
            	if(STREAM_EGRESS_ATTR[stream->id].type & STREAM_HAS_OFFSET)
            		LQ_DEBUG_CORE("[%s:CORE] {%s} Stream[" FMT_SID ":%llu] buffer clean by pn %llu\r\n",
            				rlink->debug_prompt, CSPROMPT(rlink), stream->id, pbuffer->offset, pbuffer->packet_nb);
            	else
            		LQ_DEBUG_CORE("[%s:CORE] {%s} Stream[" FMT_SID "] buffer clean by pn %llu\r\n",
            				rlink->debug_prompt, CSPROMPT(rlink), stream->id, pbuffer->packet_nb);
                // 清理获得确认的stream buffer
                *ppbuffer = (*ppbuffer)->next;
                // 已经确定被对端接收到的packet所包含的stream buffer归还到可用buffer空间。
                stream->pending_size -= pbuffer->len;
                pbuffer->packet_nb = MIN_PACKET_NUMBER;
                pbuffer->next = rlink->free_stream_header;
                rlink->free_stream_header = pbuffer;
            }
            else {
                ppbuffer = &(*ppbuffer)->next;
            }
        }
    }
}

/*
 * ACK确认远端已经接收到的报文，因此可以释放这些已经送达的数据所占用的空间。
 */

void connection_handler_ack(cyg_uint8 const **pos, cyg_uint8* end, pRCONNECTION connection) {
    TYPE_PACKET_NUMBER lg_ack = 0;
    decv(&lg_ack, pos, end);
    TYPE_TIMER_US ack_delay = 0;
    decv(&ack_delay, pos, end);
    uint64_t ack_rng_cnt = 0;
    decv(&ack_rng_cnt, pos, end);

    // this is a similar loop as in dec_ack_frame() - keep changes in sync
    uint64_t n;
    for (n = ack_rng_cnt + 1; n > 0; n--) {
        uint64_t ack_rng = 0;
        decv(&ack_rng, pos, end);

        cleanstream_range_connection(connection, lg_ack, (lg_ack - ack_rng));

        if (n > 1) {
            uint64_t gap = 0;
            decv(&gap, pos, end);
            lg_ack -= ack_rng + gap + 2;
        }
    }
}
static void core_stream_preprocess(pRCONNECTION connection, pRPACKET packet, cyg_uint8 const **pos) {
	int stream;
	for(stream = 0; stream < sizeof(connection->ingress_core_streams)/sizeof(connection->ingress_core_streams[0]); stream++) {

	}
}

#if 1
static int stream_slot_handler_ingress(pRCONNECTION connection, pRPACKET packet, TYPE_STREAM_ID id, cyg_uint8 *spos, const cyg_uint8 **pos, cyg_uint8 *end) {

        // Overwrite stream id to slink item index.
		TYPE_STREAM_ID fitem = packet->f_link_item++;
		*spos = fitem;

        // decode stream offset
        TYPE_STREAM_OFFSET offset;
       	decv(&offset, pos, end);
        // decode stream length
        TYPE_STREAM_LENGTH stream_len;
       	dec2(&stream_len, pos, end);

        // 早期QUCI规范不允许长度为 0 的 stream， 后来取消了这个规定，为什么？
        // TODO: handle Stream Length equal 0.
        if(0 == stream_len) {
            LQ_DEBUG_CORE("stream length should greater than 0\r\n");
            connection->rlink->protocol_violate = TRUE;
        }

        // TODO: 有可能是重复接收到的数据，而且麻烦的是其长度还可能不一样！
        // 这个问题实际是对发送端的要求问题。
		// 重复数据如果长度不同，应该按照protocol_violation处理。

		pINSTREAM instream = &connection->ingress_streams[id];
		instream->ingress_size += stream_len;
    	int dup = 0;
    	// TODO: STREAM_HAS_OFFSET
    	if(offset < instream->offset)
    		dup = 1;
    	else
        {
			// PACKET remain style
			struct SLinker *slinker =  &instream->slinker;
			TYPE_STREAM_OFFSET _o;
			TYPE_STREAM_LENGTH _l;
			while(slinker->packet != NULL) {
				slinker = nextslink(slinker, &_o, &_l, NULL);
				// TODO: _o is ordered, so should only compare < ?
				if(_o != offset)
					continue;

				// 这个地方应该怎么处理？接收到的数据长度不同，会引起内部处理的复杂性
				if(_l != stream_len) {
					LQ_DEBUG_ERROR("duplicate packet for stream[%d] offset: %llu has different length: %u - %u\r\n",
							id, offset, _l, stream_len);
					exit(0);
				}

				LQ_DEBUG_CORE("duplicate packet for stream[%d] offset: %llu\r\n", id, offset);
				dup = 1;
				break;
			}
        }

		if(dup) {
			instream->dup_bytes += stream_len;
			instream->dup_transfer++;
		}
		else
		{
			// PACKET remain style
			// the end of buffer space for links.
			// TODO: should be 4 byte align?
			struct SLinker *slink =  &instream->slinker;
			while(slink->packet != NULL)
			{
				TYPE_STREAM_OFFSET _o;
				struct SLinker *s = nextslink(slink, &_o, NULL, NULL);
				if(offset < _o)
					break;
				slink = s;
			}
			// Now we move to the right position
			// fill my slink to next slink.
			struct SLinker *links = (struct SLinker *)&packet->buf[packet->len];
	        struct SLinker *fill = &links[fitem];
	        if((cyg_uint8 *)fill > (packet->buf + sizeof(packet->buf))) {
	        	fprintf(stderr, "Slink Fill out of space: %p buffer address: %p, item: %d\r\n", fill, packet->buf, fitem);
	        	exit(1);
	        }
			fill->packet = slink->packet;
			fill->soffset = slink->soffset;

			// fill located slink to my self;
			slink->packet = packet;
			slink->soffset = spos - packet->buf;
			// END of PACKET remain style

			instream->received_size += stream_len;
			packet->ref++;

			// 计算连续的可用数据长度
			TYPE_STREAM_OFFSET offset_tail = instream->offset;

			// PACKET remain style
			struct SLinker *slinker =  &instream->slinker;
			TYPE_STREAM_OFFSET _o;
			TYPE_STREAM_LENGTH _l;
			while(slinker->packet != NULL) {
				slinker = nextslink(slinker, &_o, &_l, NULL);
				if(_o == offset_tail) {
					offset_tail += _l;
				} else
					break;
			}
			instream->avaliable_len = offset_tail - instream->offset;
			LQ_DEBUG_CORE("[DEBUG:CORE] Stream[" FMT_SID "] readable %08X, received offset: %llu\r\n",
					instream->id, instream->notify_event, offset);
		}

		// 如果buffer的位置与读取的位置相等，说明有数据可读
		instream->notify_event &= ~CONNECTION_EVENT_READABLE;
		struct SLinker *slinker =  &instream->slinker;
		TYPE_STREAM_OFFSET _o;
		TYPE_STREAM_LENGTH _l;
		if(slinker->packet != NULL) {
			slinker = nextslink(slinker, &_o, &_l, NULL);
			if(_o == instream->offset)
				instream->notify_event |= CONNECTION_EVENT_READABLE;
		}
		*pos += stream_len;
}
#endif
static void connection_ingress(pRCONNECTION connection, pRPACKET packet) {
	// packet initial
	packet->f_link_item = 0;

	pRLINK rlink = connection->rlink;
    cyg_uint8 const *pos = packet->buf;
    cyg_uint8 *end = packet->buf + packet->len;


    cyg_uint8 header_byte;
    dec1(&header_byte, &pos, end);
    RLINK_CID target_id;
    dec8(&target_id, &pos, end);

    if(RLINK_CID_NULL == target_id && connection->rlink->isClient) {
        LQ_DEBUG_CORE("Warning: TODO received packet not for client, protocol voilate?\r\n");
        connection->rlink->protocol_violate = TRUE;
        return;
    }

    if(target_id != RLINK_CID_NULL && target_id != connection->local_cid) {
        LQ_DEBUG_CORE("    Target-ID: %016llu --- %016llu\r\n", target_id, connection->local_cid);
        return;
    }

	// TODO: 这里的实现方式是将接收到的packet内容分别拷贝到stream的接收链表中
	// 也可以考虑用rlink提供packet接收空间，让stream分别指向packet接受空间的区域
	// 当stream消耗完成后，释放packet接收空间。
	if(NULL == rlink->free_stream_header) {
		LQ_DEBUG_CORE("TODO: no free space\r\n");
		//break;
		exit(0);
	}

    TYPE_PACKET_NUMBER packet_nb;
    decv(&packet_nb, &pos, end);

    pPN_SPACE pn = &connection->pn_space;

    // 如果新接入的packet number 比预期的不止大一个，说明有丢包情况出现，需要 立即回应 ACK.
    const struct ival * const first_rng = diet_max_ival(&pn->recv);
    if((NULL != first_rng) && (packet_nb > (first_rng->hi + 1))) {
   		LQ_DEBUG_CORE("[%s:CORE] {%s} Lost packet, want %u, but %llu\r\n",
   				rlink->debug_prompt, CSPROMPT(rlink), (first_rng->hi + 1), packet_nb);
   		pn->rx_frm_types |= STREAM_INGRESS_IMM_ACK;
    }

    diet_insert(&pn->recv, packet_nb, 0);

	core_stream_preprocess(connection, packet, &pos);

    while(packet->len > (pos - (packet->buf))) {

    	cyg_uint8 *spos = (cyg_uint8 *)pos;
        // decode stread id
        TYPE_STREAM_ID id;
        dec1(&id, &pos, end);

        if(id > sizeof(STREAM_INGRESS_ATTR)/sizeof(STREAM_INGRESS_ATTR[0])) {
        	LQ_DEBUG_ERROR("STREAM id overflow\r\n");
        	exit(0);
        }

        pn->rx_frm_types |= STREAM_INGRESS_ATTR[id].type;

        if(STREAM_ID_ACK1 == id || STREAM_ID_ACK2 == id) {
            connection_handler_ack(&pos, end, connection);
            continue;
        }
#if 0
        // PACKET remain style, overwrite stream id to slink item index.
		TYPE_STREAM_ID fitem = packet->f_link_item++;
		*spos = fitem;

        // decode stream offset
        TYPE_STREAM_OFFSET offset = 0;
        if(STREAM_INGRESS_ATTR[id].type & STREAM_HAS_OFFSET)
        	decv(&offset, &pos, end);
        // decode stream length
        TYPE_STREAM_LENGTH stream_len = 0;
        if(STREAM_INGRESS_ATTR[id].type & STREAM_HAS_LENGTH)
        	dec2(&stream_len, &pos, end);

        // 早期QUCI规范不允许长度为 0 的 stream， 后来取消了这个规定，为什么？
        // TODO: handle Stream Length equal 0.
        if(0 == stream_len) {
            LQ_DEBUG_CORE("stream length should greater than 0\r\n");
            connection->rlink->protocol_violate = TRUE;
        }

        // TODO: 有可能是重复接收到的数据，而且麻烦的是其长度还可能不一样！
        // 这个问题实际是对发送端的要求问题。

		pINSTREAM instream = &connection->ingress_streams[id];
		instream->ingress_size += stream_len;
    	int dup = 0;
    	// TODO: STREAM_HAS_OFFSET
    	if(offset < instream->offset)
    		dup = 1;
    	else
        {
			// PACKET remain style
			struct SLinker *slinker =  &instream->slinker;
			TYPE_STREAM_OFFSET _o;
			TYPE_STREAM_LENGTH _l;
			while(slinker->packet != NULL) {
				slinker = nextslink(slinker, &_o, &_l, NULL);
				if(_o != offset)
					continue;

				// 这个地方应该怎么处理？接收到的数据长度不同，会引起内部处理的复杂性
				if(_l != stream_len) {
					LQ_DEBUG_ERROR("duplicate packet for stream[%d] offset: %llu has different length: %u - %u\r\n",
							id, offset, _l, stream_len);
					exit(0);
				}

				LQ_DEBUG_CORE("duplicate packet for stream[%d] offset: %llu\r\n", id, offset);
				dup = 1;
				break;
			}
        }

		if(dup) {
			instream->dup_bytes += stream_len;
			instream->dup_transfer++;
		}
		else
		{
			// PACKET remain style
			// the end of buffer space for links.
			// TODO: should be 4 byte align?
			struct SLinker *slink =  &instream->slinker;
			while(slink->packet != NULL)
			{
				TYPE_STREAM_OFFSET _o;
				struct SLinker *s = nextslink(slink, &_o, NULL, NULL);
				if(offset < _o)
					break;
				slink = s;
			}
			// Now we move to the right position
			// fill my slink to next slink.
			struct SLinker *links = (struct SLinker *)&packet->buf[packet->len];
	        struct SLinker *fill = &links[fitem];
	        if((cyg_uint8 *)fill > (packet->buf + sizeof(packet->buf))) {
	        	fprintf(stderr, "Slink Fill out of space: %p buffer address: %p, item: %d\r\n", fill, packet->buf, fitem);
	        	exit(1);
	        }
			fill->packet = slink->packet;
			fill->soffset = slink->soffset;

			// fill located slink to my self;
			slink->packet = packet;
			slink->soffset = spos - packet->buf;
			// END of PACKET remain style

			instream->received_size += stream_len;
			packet->ref++;

			// 计算连续的可用数据长度
			TYPE_STREAM_OFFSET offset_tail = instream->offset;

			// PACKET remain style
			struct SLinker *slinker =  &instream->slinker;
			TYPE_STREAM_OFFSET _o;
			TYPE_STREAM_LENGTH _l;
			while(slinker->packet != NULL) {
				slinker = nextslink(slinker, &_o, &_l, NULL);
				if(_o == offset_tail) {
					offset_tail += _l;
				} else
					break;
			}
			instream->avaliable_len = offset_tail - instream->offset;
			LQ_DEBUG_CORE("[DEBUG:CORE] Stream[" FMT_SID "] readable %08X, received offset: %llu\r\n",
					instream->id, instream->notify_event, offset);
		}

		// 如果buffer的位置与读取的位置相等，说明有数据可读
		instream->notify_event &= ~CONNECTION_EVENT_READABLE;
		struct SLinker *slinker =  &instream->slinker;
		TYPE_STREAM_OFFSET _o;
		TYPE_STREAM_LENGTH _l;
		if(slinker->packet != NULL) {
			slinker = nextslink(slinker, &_o, &_l, NULL);
			if(_o == instream->offset)
				instream->notify_event |= CONNECTION_EVENT_READABLE;
		}
		pos += stream_len;
#else
	stream_slot_handler_ingress(connection, packet, id, spos, &pos, end);
#endif

        if(pos > end) {
            LQ_DEBUG_CORE("Fatal: stream end of packet\r\n");
            exit(0);
        }
    }

    // 判断是否只有ACK。不应该去回应(ACK)只有ACK的PACKET.
    // DEBUG Statistics:
    if((pn->rx_frm_types & ~(STREAM_INGRESS_IMM_ACK|STREAM_CORE)) == 0)
    	connection->received_ackonly++;

    // NOTE: 规范上是不能回应只有ACK的报文，可是如果对端没有别的信息发送而只是接收信息，它就没有机会消化pn_space里面的记录.
//    else
    	pn->pkts_rxed_since_last_ack_tx++;
    connection->received_packet++;
}

/**
 * 系统内部产生stream buffer的辅助函数
 **/
// TODO: 没有考虑超过一个缓冲区大小的写入
TYPE_BUFFER_SIZE lq_write(pRCONNECTION connection, TYPE_STREAM_ID id, cyg_uint8 const *val, TYPE_STREAM_LENGTH len) {
	pRLINK rlink = connection->rlink;
	if(connection->egress_streams[id].pending_size > DEFAULT_MAX_PENDING_SIZE) {
        LQ_DEBUG_CORE("TODO: stream max pending size limited\r\n");
        return 0;
    }

	if(NULL == rlink->free_stream_header) {
        LQ_DEBUG_CORE("TODO: no free space\r\n");
        return 0;
    }

	// alloc and init stream buffer
    pRSTREAM_BUFFER sb = rlink->free_stream_header;
    rlink->free_stream_header = rlink->free_stream_header->next;

    sb->packet_nb = MIN_PACKET_NUMBER;
    sb->next = NULL;
    sb->offset = connection->egress_streams[id].offset;
    // end of alloc and init stream buffer

    cyg_uint8 *pos = sb->buffer;
    cyg_uint8 *end = sb->buffer + sizeof(sb->buffer);
    encb(&pos, end, val, len);
    sb->len = pos - sb->buffer;

    // link stream buffer to tail
    pRSTREAM_BUFFER *ppbuffer = &connection->egress_streams[id].buffer_header;
    // find the tail.
    while(NULL != *ppbuffer) ppbuffer = &(*ppbuffer)->next;
    *ppbuffer = sb;

    connection->egress_streams[id].offset += sb->len;
    connection->egress_streams[id].pending_size += sb->len;
    connection->egress_streams[id].sended_size += sb->len;
    return sb->len;
}

pRCONNECTION rlink_connect(pRLINK link, pRLINK_ADDR addr) {
    pRCONNECTION *ppRCONNECTION = &link->connections_mgr.connection_header;

    // TODO: 我们是不是应该禁止去连接同一个目标地址呢？当发现试图连接同一个目标地址的是否，应该返回NULL.
    while(NULL != *ppRCONNECTION) {
        if(RLINK_ADDR_CMP(addr, &(*ppRCONNECTION)->peer_addr) == 0)
            return *ppRCONNECTION;
        ppRCONNECTION = &(*ppRCONNECTION)->next;
    }

    pRCONNECTION connection = _new_connection(link, addr);
    *ppRCONNECTION = connection;
    return connection;
}

/**
 * STEAM帧结构如下：
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                           流 ID (i)                         ...
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                           [偏移 (i)]                         ...
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                          [长度 (i)]                         ...
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                           流数据 (*)                         ...
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * Figure 20: STREAM帧格式
 **/

/**
 * 考虑到接收端实现的简易性，预留Stream Linker Struct接收端
 */
static BOOL stream_buffer_egress(pRCONNECTION connection, pRPACKET packet, pESTREAM stream, cyg_uint8 **pos, cyg_uint8 *end) {
	pRLINK rlink = connection->rlink;
	BOOL hasStream = FALSE;

    pRSTREAM_BUFFER pbuffer = stream->buffer_header;
    for(; NULL != pbuffer; pbuffer = pbuffer->next) {
        if(pbuffer->packet_nb != MIN_PACKET_NUMBER)
            continue;

        // TODO: check space!!!
    	//  考虑到接收端实现的简易性，预留Stream Linker Struct接收端
        int require = 1 /* stream id */ + sizeof(TYPE_STREAM_LENGTH) + sizeof(TYPE_STREAM_OFFSET) + pbuffer->len;
        if((end - *pos - packet->slink_size) < require) {
        	fprintf(stderr, "no packet space for stream\r\n");
        	break;
        }
        // encode stread id
        enc1(pos, end, stream->id);

        // encode stream offset
        if(STREAM_EGRESS_ATTR[stream->id].type & STREAM_HAS_OFFSET)
            encv(pos, end, pbuffer->offset);
            // encode stream length
        if(STREAM_EGRESS_ATTR[stream->id].type & STREAM_HAS_LENGTH)
            enc2(pos, end, pbuffer->len);

        // encode datas
        encb(pos, end, pbuffer->buffer, pbuffer->len);
        pbuffer->packet_nb = connection->packet_nb;
        pbuffer->time_us = rlink->current_time_us;
        stream->egress_size += pbuffer->len;

        packet->slink_size += SLINK_SIZE;
        hasStream = TRUE;
    }
    return hasStream;
}

/*
 *  ACK的产生有两种可能
 *  immediate ack在STREAM_ID_ACK1里面产生，当接收到的packet需要立即ACK的时候，接收端应该及早回应。
 *  RTT时长超过以后，需要ACK这个期间接收到的packet number.这个在STREAM_ID_ACK2里面产生。
 */
BOOL generator_ack(pRCONNECTION connection, pRPACKET packet, TYPE_STREAM_ID stream_id, cyg_uint8 **pos, cyg_uint8 *end) {
	pRLINK rlink = connection->rlink;
    pPN_SPACE pn = &connection->pn_space;

    const struct ival * const first_rng = diet_max_ival(&pn->recv);
    if(first_rng == NULL)
    	return FALSE;

    if((STREAM_ID_ACK1 == stream_id) && !(pn->rx_frm_types & STREAM_INGRESS_IMM_ACK))
    	return FALSE;

    if((STREAM_ID_ACK2 == stream_id)
        && ((rlink->current_time_us < (pn->last_ack_time + connection->rtt_us))
		|| (pn->pkts_rxed_since_last_ack_tx == 0)))
	    return FALSE;

    // TODO: we need at least stream-id + largest-pn + delay + range-cnt + ()

    if((end - *pos - packet->slink_size) < (1 + sizeof(TYPE_PACKET_NUMBER) +
    		sizeof(uint64_t) /* ack delay */+ sizeof(uint_t) /* range count */
    		+ 2 * sizeof(uint64_t) /* One ACK range and One ACK Gap */)) {
    	fprintf(stderr, "no packet space for ACK%d\r\n", stream_id);
	    return FALSE;
    }


    enc1(pos, end, stream_id);
    encv(pos, end, first_rng->hi);

    const uint64_t ack_delay = 0;
    encv(pos, end, ack_delay);

    // TODO: what if packet space can not contains all ACK?
    const uint_t ack_rng_cnt = diet_cnt(&pn->recv) - 1;
    encv(pos, end, ack_rng_cnt);

    uint_t prev_lo = 0;
    struct ival * b;

    // TODO: recorder all acked packet ?
    // Free last cached acked packet number.
    struct diet *p_acked = &connection->acked;
    if(!diet_empty(p_acked)) {
#if 1 // DEBUG_CODE
        LQ_DEBUG_CORE("[%s] {%s} ACK%d replace packet: " FMT_PN " ",
        		rlink->debug_prompt, CSPROMPT(rlink), stream_id, connection->ack_pn);

        diet_foreach_rev (b, diet, &connection->acked) {
            uint_t gap = 0;
            if (prev_lo) {
                gap = prev_lo - b->hi - 2;
                LQ_DEBUG_CORE("-%u-", gap + 1);
            }
            const uint_t ack_rng = b->hi - b->lo;
            if(b->hi != b->lo)
            	LQ_DEBUG_CORE("[%u:%u]", b->hi, b->lo);
            else
            	LQ_DEBUG_CORE("[%u]", b->hi);

            prev_lo = b->lo;
        }
        LQ_DEBUG_CORE("\r\n");
#endif
        diet_free(p_acked);
    }

    LQ_DEBUG_CORE("[%s] {%s} Generator for ACK%d in packet: " FMT_PN " > ",
    		rlink->debug_prompt, CSPROMPT(rlink), stream_id, connection->packet_nb);
    prev_lo = 0;
    diet_foreach_rev (b, diet, &pn->recv) {

    	// TODO: check space!

        uint_t gap = 0;
        if (prev_lo) {
            gap = prev_lo - b->hi - 2;
            LQ_DEBUG_CORE("-%u-", gap + 1);
            encv(pos, end, gap);
        }
        const uint_t ack_rng = b->hi - b->lo;
        if(b->hi != b->lo)
        	LQ_DEBUG_CORE("[%u:%u]", b->hi, b->lo);
        else
        	LQ_DEBUG_CORE("[%u]", b->hi);

        encv(pos, end, ack_rng);

        // ack for ack cache.
        uint_t p = b->hi;
		do {
			diet_insert(p_acked, p, 0);
		}while(--p >= b->lo);
        // end of ack for ack cache.

        prev_lo = b->lo;
    }
    connection->ack_pn = connection->packet_nb;
    pn->pkts_rxed_since_last_ack_tx = 0;
    pn->last_ack_time = rlink->current_time_us;
    pn->rx_frm_types = 0;
    // pn->need_ack = FALSE;

    // DEBUG ONLY
    if(stream_id == STREAM_ID_ACK1)
    	connection->ack1_sended++;
    else
    	connection->ack2_sended++;
    LQ_DEBUG_CORE("\r\n");
    return TRUE;
}

// TODO: we should deliver LOST stream first somehow.
static void connection_egress(pRCONNECTION connection, pRPACKET packet) {
    packet->len = 0;
    packet->slink_size = 0;

	pRLINK rlink = connection->rlink;
    // 模拟对端接收到报文后能够知道报文发送源地址。
    RLINK_ADDR_CPY(&packet->from_addr, &connection->local_addr);
    // 设定packet需要发送去的目的地址。
    RLINK_ADDR_CPY(&packet->to_addr, &connection->peer_addr);

    cyg_uint32  send_frm_types = 0;

    cyg_uint8 *pos = packet->buf;
    cyg_uint8 *end = packet->buf + sizeof(packet->buf);

    enc1(&pos, end, DEFAULT_HEADER_BYTE);
    encb(&pos, end, (const cyg_uint8 *)&connection->target_cid, sizeof(connection->target_cid));
    encv(&pos, end, connection->packet_nb);

    cyg_uint8 const *check_pos = pos;

    if(stream_buffer_egress(connection, packet, &connection->egress_streams[STREAM_ID_CRYPTO], &pos, end) == TRUE)
   		send_frm_types |= STREAM_EGRESS_ATTR[STREAM_ID_CRYPTO].type;

    // 我们用STREAM SLOT 1来传输 ACK需要理解发送的PN 信息
    // ACK数据需要每次进行更新，所以不能缓存在STREAM BUFFER之中。
    // TODO: 但是ACK for ACK需要记录ACK的数据
   	if(generator_ack(connection, packet, STREAM_ID_ACK1, &pos, end))
   		send_frm_types |= STREAM_EGRESS_ATTR[STREAM_ID_ACK1].type;

    int stream_index;
    for(stream_index = 3; stream_index <= (sizeof(STREAM_EGRESS_ATTR)/sizeof(STREAM_EGRESS_ATTR[0])); stream_index++) {
        // 不应该被传输，原因之一是没有得到加密数据。
        if(stream_buffer_egress(connection, packet, &connection->egress_streams[stream_index], &pos, end) == TRUE)
       		send_frm_types |= STREAM_EGRESS_ATTR[stream_index].type;
    }

    if(generator_ack(connection, packet, STREAM_ID_ACK2, &pos, end))
    	send_frm_types |= STREAM_EGRESS_ATTR[STREAM_ID_ACK2].type;

    if(check_pos == pos)
        packet->len = 0;
    else {
        packet->len = pos - packet->buf;
        connection->packet_nb++;
#if 1 // DEBUG_ONLY?
        packet->connection = connection;
#endif
        if((send_frm_types & ~STREAM_CORE) == STREAM_EGRESS_ACK)
        	connection->sended_ackonly++;
    }

    if(pos > end)
    	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!! packet overflow %p %p len: %d	!!!!!!!!!!!!!!!!!!!!!!!\r\n", pos, end, packet->len);
}

// 生成需要发送的packet。
int rlink_egress(pRLINK link, pRPACKET packet) {
    packet->len = 0;

    again:;
	if(link->sending_packet_header != NULL) {
		pRPACKET p = link->sending_packet_header;
		link->sending_packet_header = p->next;

		RLINK_ADDR_CPY(&packet->from_addr, &p->from_addr);
		RLINK_ADDR_CPY(&packet->to_addr, &p->to_addr);

		packet->len = p->len;
		memcpy(packet->buf, p->buf, packet->len);

        p->connection->sended_packet++;
		packet->connection = p->connection;

		p->next = link->free_packets;
		link->free_packets = p;
		return packet->len;
	}

    pRCONNECTION connection = link->connections_mgr.connection_header;
    for(; connection != NULL; connection = connection->next)
    {

        // process connection state
		pRPACKET p = link->free_packets;
		if(NULL == p) {
			LQ_DEBUG_CORE("no more packets\r\n");
			packet->len = 0;
			return 0;
		}

		link->free_packets = p->next;

        connection_egress(connection, p);

        if(p->len != 0) {
            RLINK_ADDR_CPY(&p->from_addr, &link->addr);
            p->next = link->sending_packet_header;
            link->sending_packet_header = p;
        } else {
			p->next = link->free_packets;
			link->free_packets = p;
        }
    }

    if(NULL != link->sending_packet_header)
    	goto again;

    return packet->len;
}

/**
 * RLINK纳入PACKET的流程
 * 分析报文的TARGET-CID并交由相应的CONNECTION进一步处理
 * 如果TARGET-CID为空，服务端为其分配新的CONNECTION，并由这个新的CONNECTION处理报文
 **/
/**
 * 考虑对特定的stream进行预先处理，比如 STREAM0，是新建立connect必要的数据，ACK STREAM也是处理packet，connect必要的数据
 * 同时我们应该记录特定的STREAM时候存在，比如ACK STEAM，当只有ACK STREAM的时候，packet的处理是不同的，接收端不能用ACK去回应只有
 * ACK的packet.
 **/
/**
 * 初始化包没有目标ID，区分重复的初始化包需要更加多的检测，否则会形成重复的connections
 */
/*
 * 把这个过程设计成支持防火墙的功能。
 *
 */
int rlink_ingress(pRLINK link, pRPACKET packet) {
	if(NULL == link->free_packets) {
		fprintf(stderr, "No free packets space\r\n");
		packet->len = 0;
		return -ENOMEM;
	}

	pRPACKET p = link->free_packets;
	link->free_packets = p->next;

	RLINK_ADDR_CPY(&p->from_addr, &packet->from_addr);
	RLINK_ADDR_CPY(&p->to_addr, &packet->to_addr);

	p->len = packet->len;
	memcpy(p->buf, packet->buf, p->len);

	log_packet(__FUNCTION__, p);

    cyg_uint8 const *pos = p->buf;
    cyg_uint8 *end = p->buf + p->len;
    cyg_uint8 header_byte;
    dec1(&header_byte, &pos, end);

    RLINK_CID target_cid;
    dec8(&target_cid, &pos, end);

    pRCONNECTION connection = link->connections_mgr.connection_header;

    // 根据packet的DCID (Destination Connection ID)查找link中的匹配项，如果找到，将该packet交予connection进一步处理。

    // TODO: check target_cid == 0
    for(; connection != NULL; connection = connection->next) {
        if(connection->local_cid == target_cid) {
			LQ_DEBUG_PKT("|| [%s] Connection {%s}, SCID: %llu  DCID: %llu\r\n", link->debug_prompt, CSPROMPT(link),
					connection->target_cid, target_cid);
        	goto ingress;
        }
    }

    CHK_FAILED_CORE(!link->isClient, "NOT Server\r\n");

    // 接收到的packet没有相关connection，而且link是服务端，那么这是一个新连接，创建这个链接以进行进一步的处理。
    // server connection
    // TODO: init packet check
    CHK_FAILED_CORE((0 == target_cid), "[%s] Unknow connection with NULL CID\r\n", link->debug_prompt);

    // 特别匹配新进入的packet是不是合法的初始化packet。
    // packet number
    TYPE_PACKET_NUMBER packet_nb;
    decv(&packet_nb, &pos, end);

    // TODO: 如何应对STREAM乱序的情况呢？
    // 如果是合法的初始化包，在STREAM0中包含了Destination CID,如果找不到这个CID，packet protocol violation.
    RLINK_CID remote_cid;
    TYPE_STREAM_ID id;
    TYPE_STREAM_OFFSET offset;
    TYPE_BUFFER_SIZE len;

    while(p->len > (pos - (p->buf)))
    {
    	dec1(&id, &pos, end);

    	CHK_FAILED_CORE((id <= sizeof(STREAM_INGRESS_ATTR)/sizeof(STREAM_INGRESS_ATTR[0])), "[%s] STREAM id overflow\r\n", link->debug_prompt);

		// encode stream offset
		offset = 0;
		if(STREAM_INGRESS_ATTR[id].type & STREAM_HAS_OFFSET)
			decv(&offset, &pos, end);

		// encode stream length
		len = 0;
		if(STREAM_INGRESS_ATTR[id].type & STREAM_HAS_LENGTH) {
			dec2(&len, &pos, end);
		}

		// TODO: use stream parser
	    if(STREAM_ID_ACK1 == id || STREAM_ID_ACK2 == id) {
			LQ_DEBUG_ERROR("[%s] Packet contains ACK STREAM, skip it now\r\n", link->debug_prompt);
			goto failed;
	    }

	    if(STREAM_ID_CRYPTO != id) {
	    	pos += len;
	    	continue;
	    }

	    if(offset != sizeof(CLIENTHELLO)) {
	    	pos += len;
	    	continue;
	    }

	    // check Destination CID length match.
	    if(sizeof(remote_cid) != len) {
			LQ_DEBUG_ERROR("[%s] Stream[000] contains %d bytes datas, but requires: %lu bytes.\r\n", link->debug_prompt, len, sizeof(remote_cid));
			LQ_DEBUG_ERROR("[%s] Packet protocol violation, discard it.\r\n", link->debug_prompt);
			return NO_ERROR;
	    }

    	dec8(&remote_cid, &pos, end);
	    LQ_DEBUG_CORE("[%s] Remote_cid: " FMT_CID "\r\n", link->debug_prompt, remote_cid);

	    // 存在再次接收到初始化包的可能。
		// 根据packet的DCID (Destination Connection ID)查找link中的匹配项，如果找到，将该packet交予connection进一步处理。
		for(connection = link->connections_mgr.connection_header; connection != NULL; connection = connection->next) {
			// TODO: 还应该检测packet的来源地址，因为不同的client也可能存在相同的remote cid.
			if(connection->target_cid == remote_cid) {
				LQ_DEBUG_PKT("|| [%s] {%s} Find initial stage connection, SCID: %llu  DCID: %llu\r\n",
						link->debug_prompt, link->isClient?"Client":"Server", connection->target_cid, remote_cid);
				goto ingress;
			}
		}

		connection = _new_connection(link, &p->from_addr);
		connection->target_cid = remote_cid;
		LQ_DEBUG_PKT("|| [%s] NEW connection for SCID: " FMT_CID "  DCID: " FMT_CID "\r\n",
				link->debug_prompt, connection->local_cid, connection->target_cid);

		// move connection to connection_header
		connection->next = link->connections_mgr.connection_header;
		link->connections_mgr.connection_header = connection;
		goto ingress;
    }
    return NO_ERROR;

ingress:;
	LQ_DEBUG_PKT("||-------- End of Logger --------------------------------------------------------------------------------------------------------------------------\r\n\n");

	p->ref = 0;
	p->slink_size = 0;
	p->connection = connection;
	p->next = connection->received_packet_header;
	connection->received_packet_header = p;
	connection_ingress(connection, p);

    return NO_ERROR;

failed:;
	// return unused packet.
	p->next = link->free_packets;
	link->free_packets = p;

	LQ_DEBUG_PKT("||-------- End of Logger --------------------------------------------------------------------------------------------------------------------------\r\n\n\n");
	return NO_ERROR;
}

int register_application(pRLINK rlink, application_handler *handler, void *ctx) {
	rlink->link_handler = handler;
	return NO_ERROR;
}

void request_write(pRCONNECTION connection, TYPE_STREAM_ID id) {
	connection->egress_streams[id].interesting_event |= CONNECTION_EVENT_WRITEABLE;
}

void request_read(pRCONNECTION connection, TYPE_STREAM_ID id) {
	connection->ingress_streams[id].interesting_event |= CONNECTION_EVENT_READABLE;
}

// 通常情况下，我们等待一定时间，是为了发出新的数据，如果是为了读取数据，只是请求READ就可以了，
// 所以定时事件注册在egress stream上。
// 复杂一点的做法是，先注册定时事件，当这个事件到来的时候，再发起WRITE事件，实现数据发送。
// 之所以复杂处理，是因为当STREAM可写的时候，我们不一定有数据可以发送，因此可以用定时事件来
// 调度下一刻，使得有数据发送时可以发送。
void request_timer(pRCONNECTION connection, TYPE_STREAM_ID id, TYPE_TIMER_US delay_us) {
	connection->egress_streams[id].timer_interesting = connection->rlink->current_time_us + delay_us;
	connection->egress_streams[id].interesting_event |= CONNECTION_EVENT_TIMER;
}

