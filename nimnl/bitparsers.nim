#BitParsers
# Low level parsers that convert byte buffers from netlink into basic nim types
# used as the building block for the higher level parsers 

proc parseInt*[T: byte or char](buf: openArray[T], endian: Endianness = cpuEndian): int =
  if endian == cpuEndian:
    copyMem(addr result, addr buf[0], sizeof result)
  else:
    echo "parseInt not implement for this endianness"

proc parseInt32*[T: byte or char](buf: openArray[T], big_endian: bool = false): int32 =
  if big_endian:
    echo "not implemented"
    return 0
  else: # little_endian
    var ret_len: int32
    for i in 0..<4:
      var rvs_idx = 3 - i
      var ret_tmp = (int32 buf[rvs_idx]) shl (sizeof(T) * 8 * rvs_idx)
      ret_len = ret_len or ret_tmp
    return ret_len

proc reverseBytes*[T](buf: openArray[T]): seq[T] =
  var buf_len = buf.len
  for i in 0..high(buf):
    var reverse_idx = buf_len - i - 1
    result.add(buf[reverse_idx])

proc parseUint64*[T: byte or char](buf: openArray[T], big_endian: bool = false): uint64 =
  if big_endian:
    echo "not implemented"
    return 0
  else: # little_endian
    var ret_len: uint64
    for i in 0..<8:
      var rvs_idx = 7 - i
      var ret_tmp = (uint64 buf[rvs_idx]) shl (sizeof(char) * 8 * rvs_idx)
      ret_len = ret_len or ret_tmp
    return ret_len

proc parseUint32*[T: byte or char](buf: openArray[T], big_endian: bool = false): uint32 =
  if big_endian:
    echo "not implemented"
    return 0
  else: # little_endian
    var ret_len: uint32
    for i in 0..<4:
      var rvs_idx = 3 - i
      var ret_tmp = (uint32 buf[rvs_idx]) shl (sizeof(T) * 8 * rvs_idx)
      ret_len = ret_len or ret_tmp
    return ret_len

proc parseUint16*[T: byte or char](buf: openArray[T], big_endian: bool = false): uint16 =
  if big_endian:
    echo "not implemented"
    return 0
  else: # little_endian
    var ret_len: uint16
    for i in 0..<2:
      var rvs_idx = 1 - i
      var ret_tmp = (uint16 buf[rvs_idx]) shl (sizeof(T) * 8 * rvs_idx)
      ret_len = ret_len or ret_tmp
    return ret_len

proc parseUint8*[T: byte or char](buf: openArray[T], big_endian: bool = false): uint8 =
  if big_endian:
    echo "not implemented"
    return 0
  else: # little_endian
    return uint8 buf[0]

proc parseString*[T: byte or char](buf: openArray[T], big_endian: bool = false): string =
  if big_endian:
    echo "not implemented"
  else:
    for v in items(buf):
      if (byte v) == (byte 0): break # skip the padding
      result.add(char v)

proc sum*(seqs: varargs[seq[byte]]): seq[byte] =
  var res_len = 0
  for s in items(seqs):
    res_len += s.len
  result = newSeq[byte](res_len)
  var cur_idx = 0
  for s in items(seqs):
    if s.len > 0:
      copyMem(addr result[cur_idx], addr s[0], s.len)
    cur_idx += s.len
  return result
