#ifndef OPENDEFS_H_INCLUDED
#define OPENDEFS_H_INCLUDED
//general
#include <stdint.h>
#include "toolchain_defs.h"
#include "board_info.h"

//==============================define==============================================

static const uint8_t infoStackName[] = "OpenWSN";
#define OPENWSN_VERSION_MAJOR 1
#define OPENWSN_VERSION_MINOR  25
#define OPENWSN_VERSION_PATCH  0  //补丁

#ifdef TRUE
#define TRUE 1
#endif // TRUE

#ifdef FALSE
#define FALSE 0
#endif // FALSE

#define LENGTH_ADDR16b  2
#define LENGTH_ADDR64b  8
#define LENGTH_ADDR128b 16

#define MAXNUMNEIGHBORS  30 //最大邻居个数

// max number of cell list length
#define CELLLIST_MAX_LEN  5

enum {
    E_SUCCESS        =    0;
    E_FAIL           =    1;
};

//types of address地址类型
enum{
    ADDR_NONE        =     0;
    ADDR_16B         =     1;
    ADDR_64B         =     2;
    ADDR_128B        =     3;
    ADDR_PANID       =     4；
    ADDR_PREFIX      =     5;   //前缀
    ADDR_ANYCAST     =     6;   //选播

};

enum{
    OW_LITTLE_ENDIAN    =  TRUE;
    OW_BIG_ENDIAN       =  FALSE;
};

//协议成员，由IANA定义
enum{
    IANA_IPv6HOPOPT       = 0x00;
    IANA_UDP              = 0x11;
    IANA_IPv6ROUTING      = 0x03;
    IANA_IPv6ROUTE        = 0x2b;//用于源路由
    IANA_ICMPv6           = 0x3a;
    IANA_ICMPv6_ECHO_REQUEST = 128;
    IANA_ICMPv6ECHO_REPLY = 129;
    IANA_ICMPv6_RS        =  133,
    IANA_ICMPv6_RA        =  134,
    IANA_ICMPv6_RA_PREFIX_INFORMATION   =    3,
    IANA_ICMPv6_RPL       =  155,
    IANA_ICMPv6_RPL_DIS   = 0x00,
    IANA_ICMPv6_RPL_DIO   = 0x01,
    IANA_ICMPv6_RPL_DAO   = 0x02,
    IANA_RSVP             =   46,
    IANA_UNDEFINED        =  250, //使用未分配的

};

// well known ports (which we define) 已知端口
// warning: first 4 MSB of 2° octect may coincide with previous protocol number
enum {
    //UDP
    WKP_UDP_COAP          =    5683,
    WKP_UDP_ECHO          =       7,
    WKP_UDP_EXPIRATION    =       5,
    WKP_UDP_MONITOR       =       3,
    WKP_UDP_INJECT        =   61617,// 0xf0b1
    WKP_UDP_RINGMASTER    =   15000,
    WKP_UDP_SERIALBRIDGE  =    2001,
    };


//status elements 状态元素
enum {
    STATUS_ISSYNC                       =  0,
    STATUS_ID                           =  1,
    STATUS_DAGRANK                      =  2,
    STATUS_OUTBUFFERINDEXES             =  3,
    STATUS_ASN                          =  4,
    STATUS_MACSTATS                     =  5,
    STATUS_SCHEDULE                     =  6,
    STATUS_BACKOFF                      =  7,
    STATUS_QUEUE                        =  8,
    STATUS_NEIGHBORS                    =  9,
    STATUS_KAPERIOD                     = 10,
    STATUS_JOINED                       = 11,
    STATUS_MAX                          = 12,
    };

 //component identifiers 组件标识符
 //the order is important because
 enum {
     COMPONENT_NULL                      = 0x00,
     COMPONENT_OPENWSN                   = 0x01,
     //cross-layers
     COMPONENT_IDMANAGER                 = 0x02,
     COMPONENT_OPENQUEUE                 = 0x03,
     COMPONENT_OPENSERIAL                = 0x04,
     COMPONENT_PACKETFUNCTIONS           = 0x05,
     COMPONENT_RANDOM                    = 0x06,
     //PHY
     COMPONENT_RADIO                     = 0x07,
     //MAClow
     COMPONENT_IEEE802154                = 0x08,
     COMPONENT_IEEE802154E               = 0x09,
      // all components with higher component id than COMPONENT_IEEE802154E
      // won't be able to get free packets from the queue
      // when the mote is not synch

       //MAClow<->MAChigh ("virtual components")
       COMPONENT_SIXTOP_TO_IEEE802154E     = 0x0a,
       COMPONENT_IEEE802154E_TO_SIXTOP     = 0x0b,
        //MAChigh
        COMPONENT_SIXTOP                    = 0x0c,
        COMPONENT_NEIGHBORS                 = 0x0d,
        COMPONENT_SCHEDULE                  = 0x0e,
        COMPONENT_SIXTOP_RES                = 0x0f,
        //IPHC
        COMPONENT_OPENBRIDGE                = 0x10,
        COMPONENT_IPHC                      = 0x11,
        //IPv6
        COMPONENT_FORWARDING                = 0x12,
        COMPONENT_ICMPv6                    = 0x13,
        COMPONENT_ICMPv6ECHO                = 0x14,
        COMPONENT_ICMPv6ROUTER              = 0x15,
        COMPONENT_ICMPv6RPL                 = 0x16,
        //TRAN
        COMPONENT_OPENUDP                   = 0x17,
        COMPONENT_OPENCOAP                  = 0x18,
        // secure join
        COMPONENT_CJOIN                     = 0x19,
        COMPONENT_OPENOSCOAP                = 0x1a,
        // applications
         COMPONENT_C6T                       = 0x1b,
         COMPONENT_CEXAMPLE                  = 0x1c,
         COMPONENT_CINFO                     = 0x1d,
         COMPONENT_CLEDS                     = 0x1e,
         COMPONENT_CSENSORS                  = 0x1f,
         COMPONENT_CSTORM                    = 0x20,
         COMPONENT_CWELLKNOWN                = 0x21,
         COMPONENT_UECHO                     = 0x22,
         COMPONENT_UINJECT                   = 0x23,
         COMPONENT_RRT                       = 0x24,
         COMPONENT_SECURITY                  = 0x25,
         COMPONENT_USERIALBRIDGE             = 0x26,
         COMPONENT_UEXPIRATION               = 0x27,
         COMPONENT_UMONITOR                  = 0x28,
         COMPONENT_CINFRARED                 = 0x29,
         };

/** \brief error codes used throughout the OpenWSN stack

\note The comments are used in the Python parsing tool:
 - {0} refers to the value of the first argument,
 - {1} refers to the value of the second argument,
 */

 enum {
   // l7
   ERR_JOINED                          = 0x01, // node joined
   ERR_SEQUENCE_NUMBER_OVERFLOW        = 0x02, // OSCOAP sequence number reached maximum value
   ERR_BUFFER_OVERFLOW                 = 0x03, // OSCOAP buffer overflow detected (code location {0})
   ERR_REPLAY_FAILED                   = 0x04, // OSCOAP replay protection failed
   ERR_DECRYPTION_FAILED               = 0x05, // OSCOAP decryption and tag verification failed
   ERR_ABORT_JOIN_PROCESS              = 0x06, // Aborted join process (code location {0})
   // l4
   ERR_WRONG_TRAN_PROTOCOL             = 0x07, // unknown transport protocol {0} (code location {1})
   ERR_UNSUPPORTED_PORT_NUMBER         = 0x08, // unsupported port number {0} (code location {1})
   // l3
   ERR_RCVD_ECHO_REQUEST               = 0x09, // received an echo request
   ERR_RCVD_ECHO_REPLY                 = 0x0a, // received an echo reply
   ERR_6LORH_DEADLINE_EXPIRED          = 0x0b, // the received packet has expired
   ERR_6LORH_DEADLINE_DROPPED          = 0x0c, // packet expiry time reached, dropped
   ERR_UNEXPECTED_DAO                  = 0x0d, // unexpected DAO (code location {0}). A change maybe happened on dagroot node.
   ERR_UNSUPPORTED_ICMPV6_TYPE         = 0x0e, // unsupported ICMPv6 type {0} (code location {1})
   ERR_6LOWPAN_UNSUPPORTED             = 0x0f, // unsupported 6LoWPAN parameter {1} at location {0}
   ERR_NO_NEXTHOP                      = 0x10, // no next hop for layer 3 destination {0:x}{1:x}
   ERR_INVALID_PARAM                   = 0x11, // invalid parameter
   ERR_INVALID_FWDMODE                 = 0x12, // invalid forward mode
   ERR_LARGE_DAGRANK                   = 0x13, // large DAGrank {0}, set to {1}
   ERR_HOP_LIMIT_REACHED               = 0x14, // packet discarded hop limit reached
   ERR_LOOP_DETECTED                   = 0x15, // loop detected due to previous rank {0} lower than current node rank {1}
   ERR_WRONG_DIRECTION                 = 0x16, // upstream packet set to be downstream, possible loop.
   ERR_FORWARDING_PACKET_DROPPED       = 0x17, // packet to forward is dropped (code location {0})
   // l2b
   ERR_NEIGHBORS_FULL                  = 0x18, // neighbors table is full (max number of neighbor is {0})
   ERR_NO_SENT_PACKET                  = 0x19, // there is no sent packet in queue
   ERR_NO_RECEIVED_PACKET              = 0x1a, // there is no received packet in queue
   ERR_SCHEDULE_OVERFLOWN              = 0x1b, // schedule overflown
   ERR_SIXTOP_RETURNCODE               = 0x1c, // sixtop return code {0} at sixtop state {1}
   ERR_SIXTOP_COUNT                    = 0x1d, // there are {0} cells to request mote
   ERR_SIXTOP_LIST                     = 0x1e, // the cells reserved to request mote contains slot {0} and slot {1}
   // l2a
   ERR_WRONG_CELLTYPE                  = 0x1f, // wrong celltype {0} at slotOffset {1}
   ERR_IEEE154_UNSUPPORTED             = 0x20, // unsupported IEEE802.15.4 parameter {1} at location {0}
   ERR_DESYNCHRONIZED                  = 0x21, // got desynchronized at slotOffset {0}
   ERR_SYNCHRONIZED                    = 0x22, // synchronized at slotOffset {0}
   ERR_LARGE_TIMECORRECTION            = 0x23, // large timeCorr.: {0} ticks (code loc. {1})
   ERR_WRONG_STATE_IN_ENDFRAME_SYNC    = 0x24, // wrong state {0} in end of frame+sync
   ERR_WRONG_STATE_IN_STARTSLOT        = 0x25, // wrong state {0} in startSlot, at slotOffset {1}
   ERR_WRONG_STATE_IN_TIMERFIRES       = 0x26, // wrong state {0} in timer fires, at slotOffset {1}
   ERR_WRONG_STATE_IN_NEWSLOT          = 0x27, // wrong state {0} in start of frame, at slotOffset {1}
   ERR_WRONG_STATE_IN_ENDOFFRAME       = 0x28, // wrong state {0} in end of frame, at slotOffset {1}
   ERR_MAXTXDATAPREPARE_OVERFLOW       = 0x29, // maxTxDataPrepare overflows while at state {0} in slotOffset {1}
   ERR_MAXRXACKPREPARE_OVERFLOWS       = 0x2a, // maxRxAckPrepapare overflows while at state {0} in slotOffset {1}
   ERR_MAXRXDATAPREPARE_OVERFLOWS      = 0x2b, // maxRxDataPrepapre overflows while at state {0} in slotOffset {1}
   ERR_MAXTXACKPREPARE_OVERFLOWS       = 0x2c, // maxTxAckPrepapre overflows while at state {0} in slotOffset {1}
   ERR_WDDATADURATION_OVERFLOWS        = 0x2d, // wdDataDuration overflows while at state {0} in slotOffset {1}
   ERR_WDRADIO_OVERFLOWS               = 0x2e, // wdRadio overflows while at state {0} in slotOffset {1}
   ERR_WDRADIOTX_OVERFLOWS             = 0x2f, // wdRadioTx overflows while at state {0} in slotOffset {1}
   ERR_WDACKDURATION_OVERFLOWS         = 0x30, // wdAckDuration overflows while at state {0} in slotOffset {1}
   ERR_SECURITY                        = 0x31, // security error on frameType {0}, code location {1}
   // cross layer
   ERR_GETDATA_ASKS_TOO_FEW_BYTES      = 0x32, // getData asks for too few bytes, maxNumBytes={0}, fill level={1}
   ERR_INPUT_BUFFER_OVERFLOW           = 0x33, // the input buffer has overflown
   // general
   ERR_BUSY_SENDING                    = 0x34, // busy sending
   ERR_UNEXPECTED_SENDDONE             = 0x35, // sendDone for packet I didn't send
   ERR_NO_FREE_PACKET_BUFFER           = 0x36, // no free packet buffer (code location {0})
   ERR_FREEING_UNUSED                  = 0x37, // freeing unused memory
   ERR_FREEING_ERROR                   = 0x38, // freeing memory unsupported memory
   ERR_UNSUPPORTED_COMMAND             = 0x39, // unsupported command {0}
   ERR_MSG_UNKNOWN_TYPE                = 0x3a, // unknown message type {0}
   ERR_WRONG_ADDR_TYPE                 = 0x3b, // wrong address type {0} (code location {1})
   ERR_BRIDGE_MISMATCH                 = 0x3c, // bridge mismatch (code location {0})
   ERR_HEADER_TOO_LONG                 = 0x3d, // header too long, length {1} (code location {0})
   ERR_INPUTBUFFER_LENGTH              = 0x3e, // input length problem, length={0}
   ERR_BOOTED                          = 0x3f, // booted
   ERR_INVALIDSERIALFRAME              = 0x40, // invalid serial frame
   ERR_INVALIDPACKETFROMRADIO          = 0x41, // invalid packet frome radio, length {1} (code location {0})
   ERR_BUSY_RECEIVING                  = 0x42, // busy receiving when stop of serial activity, buffer input length {1} (code location {0})
   ERR_WRONG_CRC_INPUT                 = 0x43, // wrong CRC in input Buffer
   ERR_PACKET_SYNC                     = 0x44, // synchronized when received a packet
   ERR_SCHEDULE_ADDDUPLICATESLOT       = 0x45, // the slot {0} to be added is already in schedule
   ERR_UNSUPPORTED_FORMAT              = 0x46, // the received packet format is not supported (code location {0})
   ERR_UNSUPPORTED_METADATA            = 0x47, // the metadata type is not suppored
   ERR_MAXRETRIES_REACHED              = 0x48, // maxretries reached (counter: {0})
};

//=========================================typedef======================================================

typedef uint16_t  errorparameter_t;
typedef uint16_t  dagrank_t;
typedef uint8_t   owerror_t;

BEGIN_PACK
typedef struct {
    uint8_t  byte4;
    uint16_t bytes2and3;
    uint16_t bytes0and1;
    } asn_t;
END_PACK

typedef asn_t  macFrameCounter_t;

BEGIN_PACK
// 单元信息{slotoffset,channeloffset}
typedef struct {
    bool      isUsed;
    uint16_t  slotoffset;
    uint16_t  channeloffset;
    } cellInfo_ht;

//地址
typedef struct {
    // always written big endian, i.e. MSB in addr[0]
    uint8_t type;
    union {
        uint8_t addr_16b[2];
        uint8_t addr_64b[8];
        uint8_t addr_128b[16];
        uint8_t panid[2];
        uint8_t prefix[8];
        };
        } open_addr_t;
END_PACK

typedef struct {
   //admin
   uint8_t       creator;                                       // the component which called getFreePacketBuffer()
   uint8_t       owner;                                         // the component which currently owns the entry
   uint8_t*      payload;                                       // pointer to the start of the payload within 'packet'
   uint8_t       length;                                        // length in bytes of the payload
   //l7
   uint16_t      max_delay;                                     // Max delay in milliseconds before which the packet should be delivered to the receiver
   bool          orgination_time_flag;
   bool          drop_flag;
   bool          is_cjoin_response;
   //l4
   uint8_t       l4_protocol;                                   // l4 protocol to be used
   bool          l4_protocol_compressed;                        // is the l4 protocol header compressed?
   uint16_t      l4_sourcePortORicmpv6Type;                     // l4 source port
   uint16_t      l4_destination_port;                           // l4 destination port
   uint8_t*      l4_payload;                                    // pointer to the start of the payload of l4 (used for retransmits)
   uint8_t       l4_length;                                     // length of the payload of l4 (used for retransmits)
   //l3
   open_addr_t   l3_destinationAdd;                             // 128b IPv6 destination (down stack)
   open_addr_t   l3_sourceAdd;                                  // 128b IPv6 source address
   bool          l3_useSourceRouting;                           // TRUE when the packet goes downstream
   //l2
   owerror_t     l2_sendDoneError;                              // outcome of trying to send this packet
   open_addr_t   l2_nextORpreviousHop;                          // 64b IEEE802.15.4 next (down stack) or previous (up) hop address
   uint8_t       l2_frameType;                                  // beacon, data, ack, cmd
   uint8_t       l2_dsn;                                        // sequence number of the received frame
   uint8_t       l2_retriesLeft;                                // number Tx retries left before packet dropped (dropped when hits 0)
   uint8_t       l2_numTxAttempts;                              // number Tx attempts
   asn_t         l2_asn;                                        // at what ASN the packet was Tx'ed or Rx'ed
   uint8_t*      l2_payload;                                    // pointer to the start of the payload of l2 (used for MAC to fill in ASN in ADV)
   cellInfo_ht   l2_sixtop_celllist_add[CELLLIST_MAX_LEN];      // record celllist to be added and will be added when 6P response sendDone
   cellInfo_ht   l2_sixtop_celllist_delete[CELLLIST_MAX_LEN];   // record celllist to be removed and will be removed when 6P response sendDone
   uint16_t      l2_sixtop_frameID;                             // frameID in 6P message
   uint8_t       l2_sixtop_messageType;                         // indicating the sixtop message type
   uint8_t       l2_sixtop_command;                             // command of the received 6p request, recorded in 6p response
   uint8_t       l2_sixtop_cellOptions;                         // celloptions, used when 6p response senddone. (it's the same with cellOptions in 6p request but with TX and RX bits have been flipped)
   uint8_t       l2_sixtop_returnCode;                          // return code in 6P response
   uint8_t*      l2_ASNpayload;                                 // pointer to the ASN in EB
   uint8_t*      l2_nextHop_payload;                            // pointer to the nexthop address in frame
   uint8_t       l2_joinPriority;                               // the join priority received in EB
   bool          l2_IEListPresent;                              // did have IE field?
   bool          l2_payloadIEpresent;                           // did I have payload IE field
   bool          l2_joinPriorityPresent;
   bool          l2_isNegativeACK;                              // is the negative ACK?
   int16_t       l2_timeCorrection;                             // record the timeCorrection and print out at endOfslot
   bool          l2_sendOnTxCell;                               // mark the frame is sent on txCell
   //layer-2 security
   uint8_t       l2_securityLevel;                              // the security level specified for the current frame
   uint8_t       l2_keyIdMode;                                  // the key Identifier mode specified for the current frame
   uint8_t       l2_keyIndex;                                   // the key Index specified for the current frame
   open_addr_t   l2_keySource;                                  // the key Source specified for the current frame
   uint8_t       l2_authenticationLength;                       // the length of the authentication field
   uint8_t       commandFrameIdentifier;                        // used in case of Command Frames
   uint8_t*      l2_FrameCounter;                               // pointer to the FrameCounter in the MAC header
   //l1 (drivers)
   uint8_t       l1_txPower;                                    // power for packet to Tx at
   int8_t        l1_rssi;                                       // RSSI of received packet
   uint8_t       l1_lqi;                                        // LQI of received packet
   bool          l1_crc;                                        // did received packet pass CRC check?
   //the packet
   uint8_t       packet[1+1+125+2+1];                           // 1B spi address, 1B length, 125B data, 2B CRC, 1B LQI
} OpenQueueEntry_t;


BEGIN_PACK
typedef struct {
   bool             used;
   bool             insecure;                                   //不安全
   uint8_t          parentPreference;                           //首选父节点
   bool             stableNeighbor;                            //是否是稳定邻居
   uint8_t          switchStabilityCounter;                    //稳定性计数
   open_addr_t      addr_64b;                                  //地址
   dagrank_t        DAGrank;                                   //DAG等级
   int8_t           rssi;                                      //接收信号强度指示(Received Signal Strength Indication)
   uint8_t          numRx;
   uint8_t          numTx;
   uint8_t          numTxACK;
   uint8_t          numWraps;                                   //number of times the tx counter wraps. can be removed if memory is a restriction. also check openvisualizer then.发送计数器换行的次数。 如果内存有限，可以将其删除。 然后检查openvisualizer。
   asn_t            asn;                                        //绝对时隙数
   uint8_t          joinPrio;
   bool             f6PNORES;
   uint8_t          sequenceNumber;
   uint8_t          backoffExponenton;
   uint8_t          backoff;
} neighborRow_t;
END_PACK

#endif // OPENDEFS_H_INCLUDED
