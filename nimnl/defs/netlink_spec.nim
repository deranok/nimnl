# Mappings from netlink attributes to Nim
import netlink_hdr
import ../attr.nim

let nl_policy_type_attr_unspec_spec* =
  AttributePolicyElement(
      nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_UNSPEC, 
      kind: MnlAttributeBinary)

let nl_policy_type_attr_type_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_TYPE,
    kind: MnlAttributeU32)

let nl_policy_type_attr_min_value_s_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_MIN_VALUE_S,
    kind: MnlAttributeS64)

let nl_policy_type_attr_max_value_s_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_MAX_VALUE_S,
    kind: MnlAttributeS64)

let nl_policy_type_attr_min_value_u_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_MIN_VALUE_U, 
    kind: MnlAttributeU64)

let nl_policy_type_attr_max_value_u_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_MAX_VALUE_U,
    kind: MnlAttributeU64)

let nl_policy_type_attr_min_length_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_MIN_LENGTH, 
    kind: MnlAttributeU32)

let nl_policy_type_attr_max_length_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_MAX_LENGTH,
    kind: MnlAttributeU32)

let nl_policy_type_attr_policy_idx_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_POLICY_IDX, 
    kind: MnlAttributeU32)

let nl_policy_type_attr_policy_maxtype_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE,
    kind: MnlAttributeU32)

let nl_policy_type_attr_bitfield32_mask_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_BITFIELD32_MASK, 
    kind: MnlAttributeU32)

let nl_policy_type_attr_pad_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_PAD,
    kind: MnlAttributeBinary)

let nl_policy_type_attr_mask_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NL_POLICY_TYPE_ATTR_MASK,
    kind: MnlAttributeU64)

let nnl_policy_type_attr_max_spec* =
  AttributePolicyElement(
    nlAttributeType: uint16 NNL_POLICY_TYPE_ATTR_MAX,
    kind: MnlAttributeBinary)

let netlink_policy_type_attr_spec* =
  @[nl_policy_type_attr_unspec_spec,
    nl_policy_type_attr_type_spec,
    nl_policy_type_attr_min_value_s_spec,
    nl_policy_type_attr_max_value_s_spec,
    nl_policy_type_attr_min_value_u_spec,
    nl_policy_type_attr_max_value_u_spec,
    nl_policy_type_attr_min_length_spec,
    nl_policy_type_attr_max_length_spec,
    nl_policy_type_attr_policy_idx_spec,
    nl_policy_type_attr_policy_maxtype_spec,
    nl_policy_type_attr_bitfield32_mask_spec,
    nl_policy_type_attr_pad_spec,
    nl_policy_type_attr_mask_spec,
    nnl_policy_type_attr_max_spec]

proc  netlink_attribute_type_print_spec*(at: NlAttribute): string = 
  let atVal = netlink_attribute_type at.u32Val
  case atVal
  of NL_ATTR_TYPE_INVALID: return "NL_ATTR_TYPE_INVALID"
  of NL_ATTR_TYPE_FLAG: return "NL_ATTR_TYPE_FLAG" 
  of NL_ATTR_TYPE_U8: return "NL_ATTR_TYPE_U8"
  of NL_ATTR_TYPE_U16: return "NL_ATTR_TYPE_U16"
  of NL_ATTR_TYPE_U32: return "NL_ATTR_TYPE_U32" 
  of NL_ATTR_TYPE_U64: return  "NL_ATTR_TYPE_U64"
  of NL_ATTR_TYPE_S8: return "NL_ATTR_TYPE_S8"
  of NL_ATTR_TYPE_S16: return "NL_ATTR_TYPE_S16"
  of NL_ATTR_TYPE_S32: return "NL_ATTR_TYPE_S32"
  of NL_ATTR_TYPE_S64: return "NL_ATTR_TYPE_S64"
  of NL_ATTR_TYPE_BINARY: return "NL_ATTR_TYPE_BINARY"
  of NL_ATTR_TYPE_STRING: return "NL_ATTR_TYPE_STRING"
  of NL_ATTR_TYPE_NUL_STRING: return "NL_ATTR_TYPE_NUL_STRING"
  of NL_ATTR_TYPE_NESTED: return "NL_ATTR_TYPE_NESTED"
  of NL_ATTR_TYPE_NESTED_ARRAY: return "NL_ATTR_TYPE_NESTED_ARRAY"
  of NL_ATTR_TYPE_BITFIELD32: return "NL_ATTR_TYPE_BITFIELD32"

proc netlink_policy_type_print_spec*(at: NlAttribute): string =
  let atVal = netlink_policy_type_attr at.attrType
  case atVal
  of NL_POLICY_TYPE_ATTR_UNSPEC: return "ATTR_UNSPEC" 
  of NL_POLICY_TYPE_ATTR_TYPE: return "ATTR_TYPE: " & netlink_attribute_type_print_spec(at)
  of NL_POLICY_TYPE_ATTR_MIN_VALUE_S: return "ATTR_MIN_VALUE_S: " & `$`(at.s64Val)
  of NL_POLICY_TYPE_ATTR_MAX_VALUE_S: return "ATTR_MAX_VALUE_S: " & `$`(at.s64Val)
  of NL_POLICY_TYPE_ATTR_MIN_VALUE_U: return "ATTR_MIN_VALUE_U: " & `$`(at.u64Val)
  of NL_POLICY_TYPE_ATTR_MAX_VALUE_U: return "ATTR_MAX_VALUE_U: " & `$`(at.u64Val)
  of NL_POLICY_TYPE_ATTR_MIN_LENGTH: return "ATTR_MIN_LENGTH: " & `$`(at.u32Val)
  of NL_POLICY_TYPE_ATTR_MAX_LENGTH: return "ATTR_MAX_LENGTH: " & `$`(at.u32Val)
  of NL_POLICY_TYPE_ATTR_POLICY_IDX: return "ATTR_POLICY_IDX: " & `$`(at.u32Val)
  of NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE: return "ATTR_POLICY_MAXTYPE: " & `$`(at.u32Val)
  of NL_POLICY_TYPE_ATTR_BITFIELD32_MASK: return "ATTR_BITFIELD32_MASK: " & `$`(at.u32Val)
  of NL_POLICY_TYPE_ATTR_PAD: return "ATTR_PAD: " & "ATTR_PAD"
  of NL_POLICY_TYPE_ATTR_MASK: return "ATTR_MASK: " & `$`(at.u64Val)
  of NNL_POLICY_TYPE_ATTR_MAX: return "You should never see this"
