##  A wrapper for netlink.h
import posix
const
  NETLINK_ROUTE* = 0
  NETLINK_UNUSED* = 1
  NETLINK_USERSOCK* = 2
  NETLINK_FIREWALL* = 3
  NETLINK_SOCK_DIAG* = 4
  NETLINK_NFLOG* = 5
  NETLINK_XFRM* = 6
  NETLINK_SELINUX* = 7
  NETLINK_ISCSI* = 8
  NETLINK_AUDIT* = 9
  NETLINK_FIB_LOOKUP* = 10
  NETLINK_CONNECTOR* = 11
  NETLINK_NETFILTER* = 12
  NETLINK_IP6_FW* = 13
  NETLINK_DNRTMSG* = 14
  NETLINK_KOBJECT_UEVENT* = 15
  NETLINK_GENERIC* = 16

##  leave room for NETLINK_DM (DM Events)

const
  NETLINK_SCSITRANSPORT* = 18
  NETLINK_ECRYPTFS* = 19
  NETLINK_RDMA* = 20
  NETLINK_CRYPTO* = 21
  NETLINK_SMC* = 22
  NETLINK_INET_DIAG* = NETLINK_SOCK_DIAG
  MAX_LINKS* = 32

type
  sockaddr_nl* {.bycopy.} = object
    nl_family*: TSa_Family
    ##  AF_NETLINK
    nl_pad*: cushort
    ##  zero
    nl_pid*: uint32
    ##  port ID
    nl_groups*: uint32
    ##  multicast groups mask
  
  Sockaddr_nl* {.bycopy.} = object
    nl_family*: TSa_Family
    ##  AF_NETLINK
    nl_pad*: cushort
    ##  zero
    nl_pid*: uint32
    ##  port ID
    nl_groups*: uint32
    ##  multicast groups mask

  nlmsghdr {.bycopy.} = object
    ## total length: 16 bytes
    nlmsg_len*: uint32
    ##  Length of message including header
    nlmsg_type*: uint16
    ##  Message content
    nlmsg_flags*: uint16
    ##  Additional flags
    nlmsg_seq*: uint32
    ##  Sequence number
    nlmsg_pid*: uint32
    ##  Sending process port ID
  
  NlMsgHeader* {.bycopy.} = object
    ## total length: 16 bytes
    nlmsg_len*: uint32   ## 4 bytes: Length of message including header
    nlmsg_type*: uint16  ## 2 bytes: Message content
    nlmsg_flags*: uint16 ## 2 bytes: Additional flags
    nlmsg_seq*: uint32 ## 4 bytes: Sequence number
    nlmsg_pid*: uint32 ## 4 bytes Sending process port ID

##  Flags values

const
  NLM_F_REQUEST* = uint16 0x01
  NLM_F_MULTI* = uint16 0x02
  NLM_F_ACK* = uint16 0x04
  NLM_F_ECHO* = uint16 0x08
  NLM_F_DUMP_INTR* = uint16 0x10
  NLM_F_DUMP_FILTERED* = uint16 0x20

##  Modifiers to GET request

const
  NLM_F_ROOT* = uint16 0x100
  NLM_F_MATCH* = uint16 0x200
  NLM_F_ATOMIC* = uint16 0x400
  NLM_F_DUMP* = uint16 (NLM_F_ROOT or NLM_F_MATCH)

##  Modifiers to NEW request

const
  NLM_F_REPLACE* = uint16 0x100
  NLM_F_EXCL* = uint16 0x200
  NLM_F_CREATE* = uint16 0x400
  NLM_F_APPEND* = uint16 0x800

##  Modifiers to DELETE request

const
  NLM_F_NONREC* = uint16 0x100

##  Flags for ACK message

const
  NLM_F_CAPPED* = uint16 0x100
  NLM_F_ACK_TLVS* = uint16 0x200

##
##    4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
##    4.4BSD CHANGE	NLM_F_REPLACE
##
##    True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
##    Append		NLM_F_CREATE
##    Check		NLM_F_EXCL
##

const
  NLMSG_ALIGNTO* = 4'u

template NLMSG_ALIGN*(len: untyped): untyped =
  (((uint(len)) + NLMSG_ALIGNTO - 1) and not (NLMSG_ALIGNTO - 1))

const
  NLMSG_HDRLEN* = (cast[cint](NLMSG_ALIGN(sizeof(nlmsghdr))))

template NLMSG_LENGTH*(len: untyped): untyped =
  ((len) + NLMSG_HDRLEN)

template NLMSG_SPACE*(len: untyped): untyped =
  NLMSG_ALIGN(NLMSG_LENGTH(len))

template NLMSG_DATA*(nlh: untyped): untyped =
  (cast[pointer](((cast[cstring](nlh)) + NLMSG_LENGTH(0))))

template NLMSG_OK*(nlh, len: untyped): untyped =
  ((len) >= cast[cint](sizeof(nlmsghdr)) and (nlh).nlmsg_len >= sizeof(nlmsghdr) and
      (nlh).nlmsg_len <= (len))

template NLMSG_PAYLOAD*(nlh, len: untyped): untyped =
  ((nlh).nlmsg_len - NLMSG_SPACE((len)))

const
  NLMSG_NOOP* = uint16 0x1
  NLMSG_ERROR* = uint16 0x2
  NLMSG_DONE* = uint16 0x3
  NLMSG_OVERRUN* = uint16 0x4
  NLMSG_MIN_TYPE* = uint16 0x10

type
  nlmsgerr* {.bycopy.} = object
    error*: cint
    msg*: nlmsghdr
    ##
    ##  followed by the message contents unless NETLINK_CAP_ACK was set
    ##  or the ACK indicates success (error == 0)
    ##  message length is aligned with NLMSG_ALIGN()
    ##
    ##
    ##  followed by TLVs defined in enum nlmsgerr_attrs
    ##  if NETLINK_EXT_ACK was set
    ##

##
##  enum nlmsgerr_attrs - nlmsgerr attributes
##  @NLMSGERR_ATTR_UNUSED: unused
##  @NLMSGERR_ATTR_MSG: error message string (string)
##  @NLMSGERR_ATTR_OFFS: offset of the invalid attribute in the original
## 	 message, counting from the beginning of the header (u32)
##  @NLMSGERR_ATTR_COOKIE: arbitrary subsystem specific cookie to
## 	be used - in the success case - to identify a created
## 	object or operation or similar (binary)
##  @NLMSGERR_ATTR_POLICY: policy for a rejected attribute
##  @__NLMSGERR_ATTR_MAX: number of attributes
##  @NLMSGERR_ATTR_MAX: highest attribute number
##

type
  nlmsgerr_attrs* = enum
    NLMSGERR_ATTR_UNUSED, NLMSGERR_ATTR_MSG, NLMSGERR_ATTR_OFFS,
    NLMSGERR_ATTR_COOKIE, NLMSGERR_ATTR_POLICY, NNLMSGERR_ATTR_MAX


let NLMSGERR_ATTR_MAX = NNLMSGERR_ATTR_MAX.int - 1
const
  NETLINK_ADD_MEMBERSHIP* = 1
  NETLINK_DROP_MEMBERSHIP* = 2
  NETLINK_PKTINFO* = 3
  NETLINK_BROADCAST_ERROR* = 4
  NETLINK_NO_ENOBUFS* = 5
  NETLINK_RX_RING* = 6
  NETLINK_TX_RING* = 7
  NETLINK_LISTEN_ALL_NSID* = 8
  NETLINK_LIST_MEMBERSHIPS* = 9
  NETLINK_CAP_ACK* = 10
  NETLINK_EXT_ACK* = 11
  NETLINK_GET_STRICT_CHK* = 12

type
  nl_pktinfo* {.bycopy.} = object
    group*: uint32

  nl_mmap_req* {.bycopy.} = object
    nm_block_size*: cuint
    nm_block_nr*: cuint
    nm_frame_size*: cuint
    nm_frame_nr*: cuint

  nl_mmap_hdr* {.bycopy.} = object
    nm_status*: cuint
    nm_len*: cuint
    nm_group*: uint32
    ##  credentials
    nm_pid*: uint32
    nm_uid*: uint32
    nm_gid*: uint32

  nl_mmap_status* = enum
    NL_MMAP_STATUS_UNUSED, NL_MMAP_STATUS_RESERVED, NL_MMAP_STATUS_VALID,
    NL_MMAP_STATUS_COPY, NL_MMAP_STATUS_SKIP


const
  NL_MMAP_MSG_ALIGNMENT* = NLMSG_ALIGNTO

template ALIGN_KERNEL_MASK*(x, mask: untyped): untyped =
  (((x) + (mask)) and not (mask))

const
  NL_MMAP_HDRLEN* = ALIGN_KERNEL_MASK(sizeof(nl_mmap_hdr), (
      typeof(sizeof(nl_mmap_hdr)))(NL_MMAP_MSG_ALIGNMENT) - 1)
  NET_MAJOR* = 36

const
  NETLINK_UNCONNECTED* = 0
  NETLINK_CONNECTED* = 1

##
##   <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
##  +---------------------+- - -+- - - - - - - - - -+- - -+
##  |        Header       | Pad |     Payload       | Pad |
##  |   (struct nlattr)   | ing |                   | ing |
##  +---------------------+- - -+- - - - - - - - - -+- - -+
##   <-------------- nlattr->nla_len -------------->
##

type
  nlattr* {.bycopy.} = object
    nla_len*: uint16
    nla_type*: uint16


##
##  nla_type (16 bits)
##  +---+---+-------------------------------+
##  | N | O | Attribute Type                |
##  +---+---+-------------------------------+
##  N := Carries nested attributes
##  O := Payload stored in network byte order
##
##  Note: The N and O flag are mutually exclusive.
##

const
  NLA_F_NESTED* = uint16 0x8000 #(1 shl 15)
  NLA_F_NET_BYTEORDER* = uint16 0x4000 #(1 shl 14)
  NLA_TYPE_MASK* = not (NLA_F_NESTED or NLA_F_NET_BYTEORDER)
  NLA_ALIGNTO* = 4

template NLA_ALIGN*(len: untyped): untyped =
  (((len) + NLA_ALIGNTO - 1) and not (NLA_ALIGNTO - 1))

const
  NLA_HDRLEN* = (cast[cint](NLA_ALIGN(sizeof(nlattr))))

##  Generic 32 bitflags attribute content sent to the kernel.
##
##  The value is a bitmap that defines the values being set
##  The selector is a bitmask that defines which value is legit
##
##  Examples:
##   value = 0x0, and selector = 0x1
##   implies we are selecting bit 1 and we want to set its value to 0.
##
##   value = 0x2, and selector = 0x2
##   implies we are selecting bit 2 and we want to set its value to 1.
##
##

type
  nla_bitfield32* {.bycopy.} = object
    value*: uint32
    selector*: uint32


##
##  policy descriptions - it's specific to each family how this is used
##  Normally, it should be retrieved via a dump inside another attribute
##  specifying where it applies.
##
##
##  enum netlink_attribute_type - type of an attribute
##  @NL_ATTR_TYPE_INVALID: unused
##  @NL_ATTR_TYPE_FLAG: flag attribute (present/not present)
##  @NL_ATTR_TYPE_U8: 8-bit unsigned attribute
##  @NL_ATTR_TYPE_U16: 16-bit unsigned attribute
##  @NL_ATTR_TYPE_U32: 32-bit unsigned attribute
##  @NL_ATTR_TYPE_U64: 64-bit unsigned attribute
##  @NL_ATTR_TYPE_S8: 8-bit signed attribute
##  @NL_ATTR_TYPE_S16: 16-bit signed attribute
##  @NL_ATTR_TYPE_S32: 32-bit signed attribute
##  @NL_ATTR_TYPE_S64: 64-bit signed attribute
##  @NL_ATTR_TYPE_BINARY: binary data, min/max length may be specified
##  @NL_ATTR_TYPE_STRING: string, min/max length may be specified
##  @NL_ATTR_TYPE_NUL_STRING: NUL-terminated string,
## 	min/max length may be specified
##  @NL_ATTR_TYPE_NESTED: nested, i.e. the content of this attribute
## 	consists of sub-attributes. The nested policy and maxtype
## 	inside may be specified.
##  @NL_ATTR_TYPE_NESTED_ARRAY: nested array, i.e. the content of this
## 	attribute contains sub-attributes whose type is irrelevant
## 	(just used to separate the array entries) and each such array
## 	entry has attributes again, the policy for those inner ones
## 	and the corresponding maxtype may be specified.
##  @NL_ATTR_TYPE_BITFIELD32: &struct nla_bitfield32 attribute
##

type
  netlink_attribute_type* = enum
    NL_ATTR_TYPE_INVALID, NL_ATTR_TYPE_FLAG, NL_ATTR_TYPE_U8, NL_ATTR_TYPE_U16,
    NL_ATTR_TYPE_U32, NL_ATTR_TYPE_U64, NL_ATTR_TYPE_S8, NL_ATTR_TYPE_S16,
    NL_ATTR_TYPE_S32, NL_ATTR_TYPE_S64, NL_ATTR_TYPE_BINARY, NL_ATTR_TYPE_STRING,
    NL_ATTR_TYPE_NUL_STRING, NL_ATTR_TYPE_NESTED, NL_ATTR_TYPE_NESTED_ARRAY,
    NL_ATTR_TYPE_BITFIELD32


##
##  enum netlink_policy_type_attr - policy type attributes
##  @NL_POLICY_TYPE_ATTR_UNSPEC: unused
##  @NL_POLICY_TYPE_ATTR_TYPE: type of the attribute,
## 	&enum netlink_attribute_type (U32)
##  @NL_POLICY_TYPE_ATTR_MIN_VALUE_S: minimum value for signed
## 	integers (S64)
##  @NL_POLICY_TYPE_ATTR_MAX_VALUE_S: maximum value for signed
## 	integers (S64)
##  @NL_POLICY_TYPE_ATTR_MIN_VALUE_U: minimum value for unsigned
## 	integers (U64)
##  @NL_POLICY_TYPE_ATTR_MAX_VALUE_U: maximum value for unsigned
## 	integers (U64)
##  @NL_POLICY_TYPE_ATTR_MIN_LENGTH: minimum length for binary
## 	attributes, no minimum if not given (U32)
##  @NL_POLICY_TYPE_ATTR_MAX_LENGTH: maximum length for binary
## 	attributes, no maximum if not given (U32)
##  @NL_POLICY_TYPE_ATTR_POLICY_IDX: sub policy for nested and
## 	nested array types (U32)
##  @NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE: maximum sub policy
## 	attribute for nested and nested array types, this can
## 	in theory be < the size of the policy pointed to by
## 	the index, if limited inside the nesting (U32)
##  @NL_POLICY_TYPE_ATTR_BITFIELD32_MASK: valid mask for the
## 	bitfield32 type (U32)
##  @NL_POLICY_TYPE_ATTR_MASK: mask of valid bits for unsigned integers (U64)
##  @NL_POLICY_TYPE_ATTR_PAD: pad attribute for 64-bit alignment
##

type
  netlink_policy_type_attr* = enum
    NL_POLICY_TYPE_ATTR_UNSPEC, NL_POLICY_TYPE_ATTR_TYPE,
    NL_POLICY_TYPE_ATTR_MIN_VALUE_S, NL_POLICY_TYPE_ATTR_MAX_VALUE_S,
    NL_POLICY_TYPE_ATTR_MIN_VALUE_U, NL_POLICY_TYPE_ATTR_MAX_VALUE_U,
    NL_POLICY_TYPE_ATTR_MIN_LENGTH, NL_POLICY_TYPE_ATTR_MAX_LENGTH,
    NL_POLICY_TYPE_ATTR_POLICY_IDX, NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE,
    NL_POLICY_TYPE_ATTR_BITFIELD32_MASK, NL_POLICY_TYPE_ATTR_PAD, NL_POLICY_TYPE_ATTR_MASK, ##  keep last
    NNL_POLICY_TYPE_ATTR_MAX


let NL_POLICY_TYPE_ATTR_MAX = int(NNL_POLICY_TYPE_ATTR_MAX) - 1
