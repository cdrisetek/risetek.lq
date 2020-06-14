#ifndef __RLINK_BASE_TYPE_
#define __RLINK_BASE_TYPE_
#include <string.h>

typedef unsigned char    cyg_uint8;
typedef unsigned short   cyg_uint16;
typedef unsigned int     cyg_uint32;
typedef unsigned long long   cyg_uint64;


typedef cyg_uint8   uint8_t;
typedef cyg_uint16  uint16_t;
typedef cyg_uint32  uint32_t;
typedef cyg_uint64  uint64_t;
typedef unsigned int uint_t;
typedef int bool;

#define PRIu "du"
#define ensure(x, fmt, ...)

#define TYPE_PACKET_NUMBER          cyg_uint64
#define MIN_PACKET_NUMBER           ((TYPE_PACKET_NUMBER)0)
#define INIT_PACKET_NUMBER           ((TYPE_PACKET_NUMBER)1)

#define TYPE_STREAM_ID              cyg_uint8
#define TYPE_STREAM_LENGTH          cyg_uint16
#define TYPE_STREAM_OFFSET          cyg_uint64

#define TYPE_BUFFER_SIZE            cyg_uint16

#define TYPE_TIMER_US               cyg_uint64

#define NUMBER_OF_STREAMS           0xff       // relationship to TYPE_STREAM_ID

#define BOOL                        int
#define TRUE                        1
#define FALSE                       0

typedef struct rlink_address {
    char addr[64];
} RLINK_ADDR, *pRLINK_ADDR;

#define RLINK_ADDR_CMP(src, dst) memcmp(&(src)->addr, &(dst)->addr, sizeof((src)->addr))
#define RLINK_ADDR_CPY(to, from) memcpy(&(to)->addr, &(from)->addr, sizeof((to)->addr))
#if 0
typedef struct rlink_connect_id {
    char cid[8];
} RLINK_CID, *pRLINK_CID;
#define RLINK_CID_CMP(a, b)     memcmp(&(a)->cid, &(b)->cid, sizeof((a)->cid))
#define RLINK_CID_CPY(to, from) memcpy(&(to)->cid, &(from)->cid, sizeof((to)->cid))

#else
typedef cyg_uint64 RLINK_CID;
#define RLINK_CID_NULL          ((RLINK_CID)0)
#define RLINK_CID_CMP(a, b)     (a == b)
#define RLINK_CID_CPY(to, from) (to = from)
#define RLINK_CID_ENC(bytes, cid) (memcpy(bytes, &cid, sizeof(cid)))
#endif


#define ENOERR          0
#define false           0
#define true            1
#endif // __RLINK_BASE_TYPE_
