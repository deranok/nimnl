# Helpers for creating netlink sockets
import posix
import defs/netlink_hdr
import bitparsers

let AF_NETLINK {.importc, header: "<linux/socket.h>".}: cint 
let SOL_NETLINK {.importc, header: "<linux/socket.h>".}: cint

proc `$`*(s: SocketHandle): string = 
  return $ int(s)

proc nl_socket*(netlink_family: int): SocketHandle =
  result = socket(AF_NETLINK, SOCK_RAW, cint netlink_family)

proc nl_bind*(s: SocketHandle, nl_groups: uint32 = 0): cint =
  var sockAddr =  Sockaddr_nl(
    nl_family: TSa_Family AF_NETLINK,
    nl_pad: cushort 0,
    nl_pid: uint32 0,
    nl_groups: uint32 nl_groups)
    
  return bindSocket(s, cast[ptr SockAddr](addr sockAddr), SockLen sizeof(sockAddr))

proc nl_send*(s: SocketHandle, buf: pointer, buf_len: int): int =
  var snl = Sockaddr_nl(nl_family: TSa_Family AF_NETLINK)
  result = posix.sendto(
    s, 
    buf, 
    buf_len, 
    0, 
    cast[ptr SockAddr](addr snl), 
    SockLen sizeof(snl))

proc nl_send*(s: SocketHandle, buf: openArray[char]): int =
  result = nl_send(s, addr buf, buf.len)

proc nl_send*(s: SocketHandle, buf: openArray[byte]): int =
  result = nl_send(s, addr buf, buf.len)

proc nl_recv*(s: SocketHandle, buf: pointer, buf_len: int): int =
  result = recv(
    s,
    buf,
    buf_len,
    0)

proc nl_recv*(s: SocketHandle, buf: openArray[char]): int =
  result = nl_recv(s, addr buf, buf.len)

proc nl_recv*(s: SocketHandle, buf: openArray[byte]): int =
  result = nl_recv(s, addr buf, buf.len)

proc nl_recv_all*(s: SocketHandle, buf: openArray[byte]): int =
  var bytesRead = nl_recv(s, addr buf, buf.len)
  
  if(bytesRead < 16):
    return bytesRead # message is probably incorrect
  
  var messageFlags = buf[6 .. 7]
  var isMultipartMessage = (parseUInt16(messageFlags) and (uint16 NLM_F_MULTI)) > 0

  if isMultipartMessage:
    var readDone = false
    var tempBufSize = 8192
    if buf.len < tempBufSize: tempBufSize = buf.len
    while(not readDone):
      var tempBuf = newSeq[byte](tempBufSize)
      var curBytesRead = nl_recv(s, tempBuf)
      if(curBytesRead >= 16):
        if (curBytesRead + bytesRead) > buf.len:
          echo "socket.nim: buffer too small"
          return bytesRead
        copyMem(addr buf[bytesRead], addr tempBuf[0], curBytesRead)
        var messageType = tempBuf[4 .. 5]
        readDone = (parseUInt16(messageType) and (uint16 NLMSG_DONE)) > 0
        bytesRead = bytesRead + curBytesRead
      else:
        return curBytesRead # recv failed
  else:
    return bytesRead

proc attachGroup*(s: SocketHandle, groupId: uint32): cint =
  result = setsockopt(
    s, 
    SOL_NETLINK, 
    NETLINK_ADD_MEMBERSHIP, 
    cast[ptr cint](addr groupId), 
    SockLen sizeof(groupId))
