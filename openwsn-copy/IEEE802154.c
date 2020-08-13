#include "opendefs.h"
#include "IEEE802154.h"
#include "IEEE802154E.h"
#include "packetfunctions.h"
#include "idmanager.h"
#include "openserial.h"
#include "topology.h"
#include "IEEE802154_security.h"

/**
/brief Prepend thee IEEE80215.4 MAC header to a transmit packet
Note that we are writing the field from the end of the header to the beginning.

\param[in,out] msg              The message to append the header to.将要添加头部的消息
\param[in]     frameType        Type of IEEE802.15.4 frame.         IEEE802.15.4帧类型
\param[in]     payloadIEPresent Is the IE list present?             IE List
\param[in]     sequenceNumber   Sequence number of this frame.      帧序列号
\param[in]     nextHop          Address of the next hop             下一跳地址
*/

void ieee802154_prependHeader(OpenQueueEntry_t* msg,
                              uint8_t           frameType,
                              bool              payloadIEPresent,
                              uint8_t           sequenceNumber,
                              open_addr_t*      nextHop)
{
   uint8_t      temp_8b;
   uint8_t      ielistpresent = IEEE154_IELIST_NO;
   bool         securityEnabled;
   int16_t      timeCorrection;
   uint16_t     timeSyncInfo;
   uint16_t     length_elementid_type;
   bool         headerIEPresent = FALSE;
   uint8_t      destAddrMode = -1;
   securityEnabled = msg->l2_securityLevel == IEEE154_ASH_SLF_TYPE_NOSEC ? 0 : 1;
   msg->l2_payload = msg->packet;      //保存启用安全性后开始加密的位置
//---->|Header IE |Header Termination 1(0x7e)|Payloaad IE|Frame Payload
//     |Header IE |Header Termination 2(0x7f)|Frame Payload
//                                           |->MAC Payload

   //通用IE（所有的数据包均包含这些）
   //相应地添加Termination IE
   if(payloadIEPresent == TRUE){//若payloadIE存在则添加Header Termination IE(0x7e)实现与payloadIE分隔
    ielistpresent = IEEE154_IELIST_YES;
    //添加 header termination IE(id = 0x7e)
    packetfunctions_reserveHeaderSize(msg,TERMINATIONIE_LEN);    //预留头部空间
    msg->payload[0] = HEADER_TERMINATION_1_IE         & 0xFF;    //HEADER_TERMINATION_1_IE   = 0x3f00
    msg->payload[1] = (HEADER_TERMINATION_1_IE  >> 8) & 0xFF;


   }else{//payload IE 不存在
   //判断是否存在payload，若有，添加header termination IE2(0x7F),用于分隔Payload IE与Frame Payload
   //或者省略termination IE，例如，keep alive 帧不携带payload，不用添加termination IE
        if(msg->length!=0){
            //若header IE list存在，添加 header termination IE (id = 0x7f)；否则不添加
            if(headerIEPresent == TRUE){
            ielistpresent = IEEE802154E_IELIST_YES;
            packetfunctions_reserveHeaderSize(msg,TERMINATIONIE_LEN);
            msg->packet[0] = HEADER_TERMINATION_2_IE  & 0xFF;//低8位
            msg->packet[1] = (HEADER_TERMINATION_2_IE>>8)  & 0xFF;//糕8位
            }else{
        //headerIEPresent = FALSE, 无payload IE， 无termination IE
            }

        }else{
            // no payload,termination IE 被省略，检验是否存在 timeCorrection IE
            if(frameType!=IEEE154_TYPE_ACK){
                // no operation
            }else {//frameType == IEEE154_TYPE_ACK
                //之后将会存在timeCorrection IE
                ielistpresent = IEEE154_IELIST_YES;
            }
        }
   }
    if (frameType == IEEE154_TYPE_ACK) {//确认帧---payload的内容只有ime correction
       timeCorrection = (int16_t)(ieee154e_getTimeCorrection());
       // add the payload to the ACK (i.e. the timeCorrection)
       packetfunctions_reserveHeaderSize(msg,sizeof(uint16_t));
       timeCorrection *= US_PER_TICK;
       timeSyncInfo  = ((uint16_t)timeCorrection) & 0x0fff;
       if (msg->l2_isNegativeACK){
          timeSyncInfo |= 0x8000;
       }
       msg->payload[0] = (uint8_t)(((timeSyncInfo)   ) & 0xff);
       msg->payload[1] = (uint8_t)(((timeSyncInfo)>>8) & 0xff);

       // add header IE header -- xv poipoi -- pkt is filled in reverse order..
       packetfunctions_reserveHeaderSize(msg,sizeof(uint16_t));
       //create the header for ack IE
       length_elementid_type=sizeof(uint16_t)|
                             (IEEE802154E_ACK_NACK_TIMECORRECTION_ELEMENTID << IEEE802154E_DESC_ELEMENTID_HEADER_IE_SHIFT)|
                             (IEEE802154E_DESC_TYPE_SHORT << IEEE802154E_DESC_TYPE_IE_SHIFT);
       msg->payload[0] = (length_elementid_type)        & 0xFF;
       msg->payload[1] = ((length_elementid_type) >> 8) & 0xFF;
   }
   //------->|Auxiliary Security Header|header IE | Payload IE | Frame Payload | FCS <-------------------

   //if security enable, the Axuiliary Security Header need to be added to the IEEE808.15.4 header添加辅助安全头
    if(securityEnabled){
        IEEE802154E_security_prependAuxiliarySecurityHeader(msg);
    }

   //Dest PAN ID |DEST ADDR|SOUR PAN ID|SOUR ADDR|Auxiliary Security Header|header IE | Payload IE | Frame Payload | FCS <-------------------
   //|->addressing fields                      <-|                         |->Information Elements<|->MAC Payload
    //previouHop address(always 64-bit)
    packetfunctions_writeAddress(msg,idmanager_getMy(ADDR_128B),OW_LITTLE_ENDIAN);
    //next hop address
    if(packetfunctions_isBroadcastMulticast(nextHop)){
        //broadcast address is always 16-bit(0xffff)
        packetfunctions_reserveHeaderSize(msg,sizeof(uint8_t));
        *((uint8_t)(msg->payload)) = 0XFF;
        packetfunctions_reserveHeaderSize(msg,sizeof(uint8_t));
        *((uint8_t)(msg->payload)) = 0xFF;
    }else{
        //unicast单播
        switch(nextHop->type){
        case ADDR_16B:
        case ADDR_64B:
            packetfunctions_writeAddress(msg,nextHop,OW_LITTLE_ENDIAN);
            break;
        default:
            openserial_printCritical(COMPONENT_IEEE802154,
                                     ERR_WRONG_ADDR_TYPE,
                                     (errorparameter_t)nextHop->type,
                                     (errorparameter_t)1);//error location
        }
    }
    msg->l2_nextHop_payload = msg->payload;
    //destination PAN only set as it is equal to SRC PAN ID
    packetfunctions_writeAddress(msg,idmanager_getMyID(ADDR_PANID),OW_LITTLE_ENDIAN);
    //Seq num|Dest PAN ID |DEST ADDR|SOUR PAN ID|SOUR ADDR|Auxiliary Security Header|header IE | Payload IE | Frame Payload | FCS <------------------
    //       |->addressing fields                      <-|                         |->Information Elements<|->MAC Payload
    //data sequence number
    packetfunctions_reserveHeaderSize(msg,sizeof(uint8_t));
    *((uint8_t)(msg->payload)) = sequenceNumber;

    //Frame Control Filed|Seq Num|Dest PAN ID |DEST ADDR|SOUR PAN ID|SOUR ADDR|Auxiliary Security Header|header IE | Payload IE | Frame Payload | FCS <------------------
    //                           |->addressing fields                      <-|                         |->Information Elements<|->MAC Payload
    //Frame Control Filed second byte
    packetfunctions_reserveHeaderSize(msg,sizeof(uint8_t));
    temp_8b = 0;
    if(packetfunctions_isBroadcastMulticast(nextHop)){
        temp_8b             |= IEEE154_ADDR_SHORT  << IEEE154_FCF_DEST_ADDR_MODE;
        destAddrMode         = IEEE154_ADDR_SHORT；
    }else{
        switch(nextHop->type){
            case ADDR_16B:
                temp_8b     |= IEEE154_ADDR_SHORT  << IEEE154_FCF_DEST_ADDR_MODE;
                destAddrMode = IEEE154_ADDR_SHORT；
                break;
            case ADDR_64B:
                temp_8b     |= IEEE154_ADDR_EXT  << IEEE154_FCF_DEST_ADDR_MODE;
                destAddrMode = IEEE154_ADDR_EXT；
                break;
          // no need for a default, since it would have been caught above.
        }

    }
    temp_8b             |= IEEE154_ADDR_EXT                << IEEE154_FCF_SRC_ADDR_MODE;
    //poipoi xv IE list present
    temp_8b             |= ielistpresent                   << IEEE154_FCF_IELIST_PRESENT;
    temp_8b             |= IEEE154_FRAMEVERSION_2012       << IEEE154_FCF_FRAME_VERSION;
    temp_8b             |= IEEE154_DSN_SUPPRESSION_NO      << IEEE154_FCF_DSN_SUPPRESSION;
    *((uint8_t*)(msg->payload)) = temp_8b;

    //Frame Control Field  (1st byte)
    packetfunctions_reserveHeaderSize(msg,sizeof(uint8_t));
    temp_8b              = 0;
    temp_8b             |= frameType                       << IEEE154_FCF_FRAME_TYPE;
    temp_8b             |= securityEnabled                 << IEEE154_FCF_SECURITY_ENABLED;
    temp_8b             |= IEEE154_PENDING_NO_FRAMEPENDING << IEEE154_FCF_FRAME_PENDING;
    if (frameType==IEEE154_TYPE_ACK || packetfunctions_isBroadcastMulticast(nextHop)) {
            temp_8b          |= IEEE154_ACK_NO_ACK_REQ          << IEEE154_FCF_ACK_REQ;
    } else {       temp_8b          |= IEEE154_ACK_YES_ACK_REQ         << IEEE154_FCF_ACK_REQ;
        }
    if (destAddrMode == IEEE154_ADDR_SHORT) {
            temp_8b         |= IEEE154_PANID_COMPRESSED        << IEEE154_FCF_INTRAPAN;
    } else {
        if (destAddrMode == IEEE154_ADDR_EXT) {
                temp_8b     |= IEEE154_PANID_UNCOMPRESSED      << IEEE154_FCF_INTRAPAN;
        } else {
            // never happens
            }
        }
    *((uint8_t*)(msg->payload)) = temp_8b;
}

/**
\brief 从（刚收到的）数据包中检索(retrieve)IEEE802.15.4 MAC报头
Note 从header的开头到结尾编写字段
\param[in,out]:msg        刚收到的数据包
\param[out]   :ieee802154_header
*/
void ieee802154_retrieveHeader(OpenQueueEntry_t msg,
                               ieee802154_header_iht* ieee802154_header){
        uint8_t  temp_8b;
        uint16_t temp_16b;
        uint16_t len;
        uint8_t  gr_elem_id;
        uint8_t  byte0;
        uint8_t  byte1;
        int16_t  timecorrection;
        uint16_t timeSyncInfo;
       //默认情况下，假设报头无效(valid)，以防由于数据包最终比报头短而离开此函数。
        ieee802154_header->valid = FALSE;
        ieee802154_header->headerLength = 0;

        // FCF  byte 1
        if(ieee802154_header->headerLength > msg->length){ return ;}
        temp_8b = *((uint8_t)msg->payload + ieee802154_header->headerLength);
        ieee802154_header->frameType        = (temp_8b >> IEEE154_FCF_FRAME_TYPE)      &0x07;//3b 0x07=0000 0111
        ieee802154_header->securityEnabled  = (temp_8b >> IEEE154_FCF_SECURITY_ENABLED)&0x01;//1b
        ieee802154_header->framePending     = (temp_8b >> IEEE154_FCF_FRAME_PENDING)   &0x01;//1b
        ieee802154_header->ackRequested     = (temp_8b >> IEEE154_FCF_ACK_REQ)         &0x01;//1b
        ieee802154_header->panIDCompression = (temp_8b >> IEEE154_FCF_INTRAPAN)        &0x01;//1b
        ieee802154_header->headerLength    += 1;

        //fcf byte 2，取出相应的值

        if(ieee802154_header->headerLength > msg->length) {return ;}
        temp_8b = *((uint8_t)(msg->payload) + ieee802154_header->headerLength);
        ieee802154_header->ieListPresent    = (temp_8b >> IEEE154_FCF_IELIST_PRESENT  )&0x01;//1b
        ieee802154_header->frameVersion     = (temp_8b >> IEEE154_FCF_FRAME_VERSION   )&0x03;//2b 0x03=0000 0011
        ieee802154_header->dsn_suppressed   = (temp_8b >> IEEE154_FCF_DSN_SUPPRESSION))&0x01;//1b
        if(ieee802154_header->ieListPresent == TRUE && ieee802154_header->frameVersion != IEEE154_FRAMEVERSION_2012){
            return ;
        }
        //判断目的地址类型
        switch((temp_8b >> IEEE154_FCF_DEST_ADDR_MODE ) 0x03){
        case IEEE154_ADDR_NONE:
            ieee802154_header->dest.type = ADDR_NONE;
            break;
        case IEEE154_ADDR_SHORT:
            ieee802154_header->dest.type = ADDR_16B;
            break;
        case IEEE154_ADDR_EXT:
            ieee802154_header->dest.type = ADDR_16B;
            break;
        default:
            openserial_printError(COMPONENT_IEEE802154,ERR_IEEE154_UNSUPPORTED,
                                  (errorparameter_t)1,
                                  (errorparameter_t)(temp_8b >> IEEE154_FCF_DEST_ADDR_MODE) & 0x03
                                  );
            return ;//无效数据包
        }
}









