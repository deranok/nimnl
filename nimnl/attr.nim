# Helpers for netlink attributes
import defs/netlink_hdr
import std/strutils
import bitparsers

type
  # These are the basic types that this libary has implemented.
  # You must create a mapping from any attribute type to one of these types
  MnlAttributeType* = enum 
    MnlAttributeU8, MnlAttributeU16, MnlAttributeU32, MnlAttributeU64,
    MnlAttributeS8, MnlAttributeS16, MnlAttributeS32, MnlAttributeS64,
    MnlAttributeBinary, # raw binary array
    MnlAttributeString, # a string
    MnlAttributeNested, # an array
    MnlAttributeNestedArray, # an array of arrays
    MnlAttributeZeroLength, # zero length attribute

  AttributePolicyElement* = object 
    nlAttributeType*: uint16 
    isBitmask*: bool = false
    case kind*: MnlAttributeType
    of MnlAttributeNested, MnlAttributeNestedArray:
      policy*: AttributePolicy
    else: discard
  
  AttributePolicy* = seq[AttributePolicyElement]
  
  NlAttribute* = object
    length*: uint16
    attrType*: uint16
    case kind*: MnlAttributeType
    of MnlAttributeU8:u8Val: uint8
    of MnlAttributeU16:u16Val*: uint16
    of MnlAttributeU32:u32Val*: uint32
    of MnlAttributeU64:u64Val*: uint64
    of MnlAttributeS8:s8Val: int8
    of MnlAttributeS16:s16Val: int16
    of MnlAttributeS32:s32Val: int32
    of MnlAttributeS64:s64Val*: int64
    of MnlAttributeBinary: binaryVal*: seq[byte] # if in doubt stick the raw bytes here
    of MnlAttributeString: stringVal*: string
    of MnlAttributeNested: nestedVal*: seq[NlAttribute]
    of MnlAttributeNestedArray: nestedArrayVal*: seq[seq[NlAttribute]]
    of MnlAttributeZeroLength: discard

proc toString*(at: NlAttribute, printPolicy: proc(at: NlAttribute): string): string =
  return printPolicy(at)

proc toString*(at: NlAttribute, nestingLevel: Natural = 0): string =
  result = "Type: " & `$`(at.attrType) & ", Value: "
  case at.kind
  of MnlAttributeU8:
    result = result & `$`at.u8Val
  of MnlAttributeU16:
    result = result & `$`at.u16Val
  of MnlAttributeU32:
    result = result & `$`at.u32Val
  of MnlAttributeU64:
    result = result & `$`at.u64Val
  of MnlAttributeS8:
    result = result & `$`at.s8Val
  of MnlAttributeS16:
    result = result & `$`at.s16Val
  of MnlAttributeS32:
    result = result & `$`at.s32Val
  of MnlAttributeS64:
    result = result & `$`at.s64Val
  of MnlAttributeBinary:
    result = result & `$`at.binaryVal
  of MnlAttributeString:
    result = result & `$`at.stringVal
  of MnlAttributeNested:
    result = result & "\n"
    for (idx, someAt) in pairs(at.nestedVal):
      if (idx == 0):
        result = result & "\t".repeat(nestingLevel) & toString(someAt, nestingLevel + 1)
      else:
        result = result & "\n" & "\t".repeat(nestingLevel) & toString(someAt, nestingLevel + 1)
  of MnlattributeNestedArray:
    for someAtSeq in items(at.nestedArrayVal):
      for (idx, someAt) in pairs(someAtSeq):
        result = result & "\n" & "\t".repeat(nestingLevel + 1) & toString(someAt, nestingLevel + 2)
  of MnlAttributeZeroLength:
    result = result & `$`(at.attrType)

# TODO: Possible optimisation could be achieved by converting the policy into a 
#       Key: Value mapping of uint16 and MnlAttributes. Possibly elimininating the 
#       need for this function altogether.
proc getAttributePolicy(policy: AttributePolicy, nlAt: uint16): AttributePolicyElement =
  result = AttributePolicyElement(
    nlAttributeType: nlAt,
    kind: MnlAttributeBinary)
  for policyElement in items(policy):
    if (policyElement.isBitmask):
      if (NLA_TYPE_MASK and (policyElement.nlAttributeType and nlAt)) > 0:
        return policyElement
      continue
    if (policyElement.nlAttributeType == nlAt):
      return policyElement
  echo "no parser found, using fallback: cur_attr_nl_type: ", nlAt

template flatAttribute(attrVal: untyped, attrParser: untyped): NlAttribute =
  NlAttribute(
    length: cur_attr_len,
    attrType: cur_attr_nl_type,
    kind: cur_attr_mnl_type,
    attrVal: attrParser(payload[(cur_idx+4) .. (cur_idx + cur_attr_len - 1)]))

# Convert a raw seq of bytes obtained from netlink (or elsewhere) to a seq of NLAttributes
proc nlAttributesIn*(payload: seq[byte], policy: AttributePolicy): seq[NlAttribute] =
  var cur_idx: uint16 = 0
  
  while cur_idx < uint16 high(payload):
    if(high(payload)) < 0: break
    var cur_attr_len = uint16 parseUint16(payload[cur_idx .. (cur_idx + 1)])
    if (NLMSG_ALIGN(cur_attr_len) + cur_idx - 1) > uint16 high(payload):
      echo "current attribute is truncated"
      echo "cur_attr_len: ", cur_attr_len
      echo "cur_idx: ", cur_idx
      echo "high(payload): ", high(payload)
      break
    var cur_attr_nl_type = parseUint16(payload[(cur_idx + 2) .. (cur_idx + 3)])
    var cur_attr_is_nested = (cur_attr_nl_type and uint16 0x8000) > 0
    var cur_attr_is_bigEndian = (cur_attr_nl_type and uint16 0x6400) > 0
    if cur_attr_is_bigEndian: echo "cur_attr_is_bigEndian"
    if cur_attr_is_nested: echo "cur attr is nested, raw attr: ", cur_attr_nl_type, " stripped val: ", cur_attr_nl_type and uint16(0x63FF)
    #~ cur_attr_nl_type = cur_attr_nl_type and uint16(0x63FF)
    let cur_attr_mnl_policy = policy.getAttributePolicy(cur_attr_nl_type)
    let cur_attr_mnl_type = cur_attr_mnl_policy.kind
    case cur_attr_mnl_type
    of MnlAttributeU8:
      result.add(flatAttribute(u8Val, parseUint8))
    of MnlAttributeU16:
      result.add(flatAttribute(u16Val, parseUint16))
    of MnlAttributeU32:
      result.add(flatAttribute(u32Val, parseUint32))
    of MnlAttributeU64:
      result.add(flatAttribute(u64Val, parseUint64))
    of MnlAttributeString: 
      result.add(flatAttribute(stringVal, parseString))
    of MnlAttributeNested:
      var nestedElements: seq[NlAttribute]
      nestedElements = nlAttributesIn(payload[(cur_idx+4) .. (cur_idx + cur_attr_len - 1)], cur_attr_mnl_policy.policy)
      result.add(NlAttribute(
        length: cur_attr_len,
        attrType: cur_attr_nl_type and (uint16 0x3FFF),
        kind: MnlAttributeNested,
        nestedVal: nestedElements))
    of MnlAttributeNestedArray:
      var nestedElements = 
        nlAttributesIn(payload[(cur_idx+4) .. (cur_idx + cur_attr_len - 1)], cur_attr_mnl_policy.policy)
      result.add(NlAttribute(
        length: cur_attr_len,
        attrType: cur_attr_nl_type and (uint16 0x3FFF),
        kind: MnlAttributeNestedArray,
        nestedArrayVal: @[nestedElements]
      ))
    of MnlAttributeZeroLength:
      result.add(NlAttribute(
        length: 0,
        attrType: cur_attr_nl_type,
        kind: cur_attr_mnl_type))
    of MnlAttributeBinary:
      result.add(NlAttribute(
        length: cur_attr_len,
        attrType: cur_attr_nl_type,
        kind: MnlAttributeBinary,
        binaryVal: payload[(cur_idx + 4) .. (cur_idx + cur_attr_len - 1)]))
    else:
      echo "Unimplemented mnl_attribute: ", cur_attr_mnl_type
      result.add(NlAttribute(
        length: cur_attr_len,
        attrType: cur_attr_nl_type,
        kind: MnlAttributeBinary,
        binaryVal: payload[(cur_idx + 4) .. (cur_idx + cur_attr_len - 1)]))
    cur_idx = cur_idx + uint16 NLMSG_ALIGN(cur_attr_len)

# Low level converter of NlAttributes into seq [byte]
template toByteArray(attr: NlAttribute, attrValField: untyped): seq[byte] =
  var result = newSeq[byte](NLMSG_ALIGN((sizeof attr.length) + (sizeof attr.attrType) + (sizeof attr.attrValField)))
  var resLen = uint16 result.len
  copyMem(addr result[0], addr resLen, sizeof attr.length)
  copyMem(addr result[(sizeof attr.length)], addr attr.attrType, sizeof attr.attrType)
  copyMem(addr result[(sizeof attr.length) + (sizeof attr.attrType)], addr attr.attrValField, sizeof attr.attrValField)
  result

# Convert an NlAttribute to a seq[byte]  
proc toByteArray*(attr: NlAttribute): seq[byte] =
  case attr.kind
  of MnlAttributeU8:
    result = toByteArray(attr, u8Val)
  of MnlAttributeU16:
    result = toByteArray(attr, u16Val)
  of MnlAttributeU32:
    result = toByteArray(attr, u32Val)
  of MnlAttributeU64:
    result = toByteArray(attr, u64Val) 
  of MnlAttributeS8:
    result = toByteArray(attr, s8Val) 
  of MnlAttributeS16:
    result = toByteArray(attr, s16Val) 
  of MnlAttributeS32:
    result = toByteArray(attr, s32Val) 
  of MnlAttributeS64:
    result = toByteArray(attr, s64Val)
  of MnlAttributeBinary:
    result = newSeq[byte](NLMSG_ALIGN((sizeof attr.length) + (sizeof attr.attrType) + (len(attr.binaryVal))))
    var resLen = uint16 result.len
    copyMem(addr result[0], addr resLen, sizeof attr.length)
    copyMem(addr result[(sizeof attr.length)], addr attr.attrType, sizeof attr.attrType)
    copyMem(addr result[(sizeof attr.length) + (sizeof attr.attrType)], addr attr.binaryVal[0], len(attr.binaryVal))
  of MnlAttributeString: 
    result = newSeq[byte](NLMSG_ALIGN((sizeof attr.length) + (sizeof attr.attrType) + (len(attr.stringVal)) + 1))
    var resLen = uint16 result.len
    copyMem(addr result[0], addr resLen, sizeof attr.length)
    copyMem(addr result[(sizeof attr.length)], addr attr.attrType, sizeof attr.attrType)
    copyMem(addr result[(sizeof attr.length) + (sizeof attr.attrType)], addr attr.stringVal[0], len(attr.stringVal))
  of MnlAttributeNested:
    var resElems: seq[seq[byte]]
    for elem in items(attr.nestedVal):
      resElems.add(toByteArray(elem))
    result = toByteArray(
      NlAttribute(
        length: 0, 
        attrType: uint16 NL_ATTR_TYPE_NESTED, 
        kind: MnlAttributeBinary, binaryVal: sum(resElems)))
  of MnlAttributeNestedArray:
    var resElems: seq[seq[byte]]
    for elem in items(attr.nestedArrayVal):
      var elemAsAttribute = 
        NlAttribute(
          length: 0, 
          attrType: uint16 NL_ATTR_TYPE_NESTED, 
          kind: MnlAttributeNested,
          nestedVal: elem)
      resElems.add(toByteArray(elemAsAttribute))
    result = toByteArray(
      NlAttribute(
        length: 0, 
        attrType: uint16 NL_ATTR_TYPE_NESTED_ARRAY, 
        kind: MnlAttributeBinary, binaryVal: sum(resElems)))  
  of MnlAttributeZeroLength:
    result = newSeq[byte](NLMSG_ALIGN((sizeof attr.length) + (sizeof attr.attrType)))
    var resLen = uint16 result.len
    copyMem(addr result[0], addr resLen, sizeof attr.length)
    copyMem(addr result[(sizeof attr.length)], addr attr.attrType, sizeof attr.attrType)

when isMainModule:
  var some_var = NlAttribute(kind: MnlAttributeString, stringVal: "some string")
  var some_a = NlAttribute(kind: MnlAttributeU8, u8Val: 1)
  var some_b = NlAttribute(kind: MnlAttributeU16, u16Val: 2)
  var some_nested = 
    NlAttribute(
      kind: MnlAttributeNested, 
      nestedVal: @[NlAttribute(kind: MnlAttributeNested, nestedVal: @[some_a]), some_b, some_var])
  var some_nested_array = 
    NlAttribute(
      kind: MnlAttributeNestedArray, 
      nestedArrayVal: @[@[some_a], @[some_b], @[some_var]])

  #~ echo some_var.toByteArray
  #~ echo some_a.toByteArray
  #~ echo some_b.toByteArray
  #~ echo some_nested.toByteArray
  #~ echo some_nested_array.toByteArray
  #~ echo typeof MnlAttributeNested
  
  var int_a: uint32
  var int_b: uint32
  var int_a_seq: seq[byte] = @[0, 0, 0, 1]
  var int_b_seq: seq[byte] = @[1, 0, 0, 0]
  copyMem(addr int_a, addr int_a_seq[0], 4)
  copyMem(addr int_b, addr int_b_seq[0], 4)
  echo int_a
  echo int_b
