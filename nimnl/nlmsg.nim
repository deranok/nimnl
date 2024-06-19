# Helpers for converting netlink messages to/from nim
import defs/netlink_hdr
import attr
import bitparsers

type
  NlMsgType* = enum
    nlMsgError,
    nlMsgNoOp,
    nlMsgRegular
  
  # nlMsg combination of the nlmsghdr with the value
  NlMsg* = object
    header*: NlMsgHeader
    payload*: seq[byte]
  
  NlErrorMsg* = object
    error_code*: int
    error_header*: NlMsgHeader
  
proc isErrorMsg*(hdr: NlMsgHeader): bool =
  return hdr.nlmsg_type == NLMSG_ERROR

proc isErrorMsg*(msg: NlMsg): bool = 
  return isErrorMsg(msg.header)

proc writeLen*(msg: var seq[byte]) =
  var msg_len = uint32 msg.len
  copyMem(addr msg[0], addr msg_len, sizeof msg_len)

proc nlAlign*(buf: var seq[byte]) =
  var new_buf = newSeq[byte](NLMSG_ALIGN(buf.len))
  copyMem(addr new_buf[0], addr buf[0], buf.len)
  buf = new_buf

# iterate over nlmsg inside a message buffer
iterator nlMsgsIn*(buf: openArray[byte or char]): NlMsg =
  var cur_idx: uint = 0
  while cur_idx <= uint high(buf):
    if (cur_idx + uint sizeof(NlMsgHeader)) > uint high(buf):
      break # Current message does not contain a complete header
    var cur_msg_len = parseUint32(buf[cur_idx..(cur_idx+3)])
    if (cur_msg_len == 0): break # the message is empty
    if ((cur_idx + cur_msg_len) > ((uint high(buf))) + 1):
      break # the message was truncated
    var cur_msg_type = parseUint16(buf[(cur_idx+4)..(cur_idx+5)])
    if (cur_msg_type == NLMSG_NOOP):
      cur_idx += NLMSG_ALIGN(sizeof(NlMsgHeader))
      continue
    var cur_msg_flags = parseUint16(buf[(cur_idx+6)..(cur_idx+7)])
    var cur_msg_seq = parseUint32(buf[(cur_idx+8)..(cur_idx+11)])
    var cur_msg_pid = parseUint32(buf[(cur_idx+12)..(cur_idx+15)])
    var cur_msg_payload = buf[(cur_idx+16)..(cur_idx + cur_msg_len - 1)]
    cur_idx = cur_idx + cur_msg_len
    var cur_msg = NlMsg(
      header: NlMsgHeader(
        nlmsg_len: cur_msg_len,
        nlmsg_type: cur_msg_type,
        nlmsg_flags: cur_msg_flags,
        nlmsg_seq: cur_msg_seq,
        nlmsg_pid: cur_msg_pid),
      payload: cur_msg_payload)
    
    yield cur_msg

iterator errorMsgsIn*(buf: openArray[byte]): NlErrorMsg =
  var cur_msg: NlErrorMsg
  if(buf.len < (sizeof cur_msg)):
    yield NlErrorMsg()# this message is probably truncated
  var error_code = parseInt32(buf)
  var error_hdr: NlMsgHeader
  for nl_msg in nlMsgsIn(buf[4..high(buf)]):
    error_hdr = nl_msg.header
  yield NlErrorMsg(
    error_code: error_code,
    error_header: error_hdr)

#Warning: this function only works for "flat" objects
proc toByteArray*[T: object](ob: T, endian: Endianness = cpuEndian): seq[byte] =
  result = newSeq[byte](sizeof ob)
  var cur_idx = 0
  for v in fields(ob):
    copyMem(addr result[cur_idx], addr v, sizeof v)
    if endian != cpuEndian:
      var num_rvrs = sizeof v
      var loop_count = 0
      var temp = result[(cur_idx) .. (cur_idx + (sizeof v) - 1)]
      while num_rvrs > 0:
        result[cur_idx + loop_count] = temp[high(temp) - loop_count]
        dec(num_rvrs) 
        inc(loop_count)
    cur_idx += sizeof v
