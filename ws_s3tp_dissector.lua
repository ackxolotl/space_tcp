s3tp_protocol = Proto("S3TP",  "S3TP Protocol")

set_not_set = {
    [0] = "Not set",
    [1] = "Set"
}

msg_types = {
    [0] = "Invalid message type",
    [1] = "Standard"
}

flag_syn = ProtoField.uint8("s3tp.flags.syn", "SYN",           base.HEX, set_not_set, 0x01)
flag_ack = ProtoField.uint8("s3tp.flags.ack", "ACK",           base.HEX, set_not_set, 0x02)
flag_rst = ProtoField.uint8("s3tp.flags.rst", "RESET",         base.HEX, set_not_set, 0x04)
flag_fin = ProtoField.uint8("s3tp.flags.fin", "FIN",           base.HEX, set_not_set, 0x08)
flag_rsv = ProtoField.uint8("s3tp.flags.rsv", "Reserved bits", base.HEX, nil, 0xf0)

version  = ProtoField.uint8( "s3tp.version",  "Version",                base.DEC, nil, 0xf0)
msg_type = ProtoField.uint8( "s3tp.msg_type", "Message Type",           base.DEC, msg_types, 0x0f)
flags    = ProtoField.uint8( "s3tp.flags",    "Flags",                  base.HEX)
src_port = ProtoField.uint16("s3tp.src_port", "Source Port",            base.DEC)
dst_port = ProtoField.uint16("s3tp.dst_port", "Destination Port",       base.DEC)
seq_num  = ProtoField.uint16("s3tp.seq_num",  "Sequence Number",        base.DEC)
ack_num  = ProtoField.uint16("s3tp.ack_num",  "Acknowledgment Number",  base.DEC)
size     = ProtoField.uint16("s3tp.size",     "Size",                   base.DEC)
hmac     = ProtoField.none(  "s3tp.hmac",     "HMAC")
payload  = ProtoField.none(  "s3tp.payload",  "Payload")

s3tp_protocol.fields = { version, msg_type, flags, flag_syn, flag_ack, flag_rst,
                         flag_fin, flag_rsv, src_port, dst_port,
                         seq_num, ack_num, size, hmac, payload }

function s3tp_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()

  if length == 0 then return end

  pinfo.cols.protocol = s3tp_protocol.name

  local subtree = tree:add(s3tp_protocol, buffer(),
                           "S3TP Protocol Version 1, Src Port: " ..
                           buffer(2, 2):uint() .. ", Dst Port: " ..
                           buffer(4, 2):uint())

  local payload_size = buffer(10, 2):uint()

  subtree:add(version,  buffer(0,  1))
  subtree:add(msg_type, buffer(0,  1))
  local flag_tree = subtree:add(flags, buffer(1, 1))
  subtree:add(src_port, buffer(2,  2))
  subtree:add(dst_port, buffer(4,  2))
  subtree:add(seq_num,  buffer(6,  2))
  subtree:add(ack_num,  buffer(8,  2))
  subtree:add(size,     buffer(10, 2))
  subtree:add(hmac,     buffer(12, 32))
  subtree:add(payload,  buffer(44, payload_size))

  flag_tree:add(flag_syn,      buffer(1, 1))
  flag_tree:add(flag_ack,      buffer(1, 1))
  flag_tree:add(flag_rst,      buffer(1, 1))
  flag_tree:add(flag_fin,      buffer(1, 1))
  flag_tree:add(flag_rsv,      buffer(1, 1))

  -- pinfo.cols.info:append(" " .. tostring(pinfo.src_port).." -> "..tostring(pinfo.dst_port))
end

local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(0x99, s3tp_protocol)
