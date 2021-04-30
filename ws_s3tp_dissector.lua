s3tp_protocol = Proto("S3TP",  "S3TP Protocol")

set_not_set = {
    [0] = "Not set",
    [1] = "Set"
}

msg_types = {
    [0] = "A",
    [1] = "B",
    [2] = "C",
    [3] = "D",
    [4] = "E",
    [5] = "F",
    [6] = "G"
}

flag_ack            = ProtoField.uint8("s3tp.flags.ack",      "ACK",           base.HEX, set_not_set, 0x01)
flag_init           = ProtoField.uint8("s3tp.flags.init",     "INIT",          base.HEX, set_not_set, 0x02)
flag_retran         = ProtoField.uint8("s3tp.flags.retran",   "RETRAN",        base.HEX, set_not_set, 0x04)
flag_reserved       = ProtoField.uint8("s3tp.flags.reserved", "Reserved bits", base.HEX, nil, 0xe0)

version  = ProtoField.uint8( "s3tp.version",  "Version",          base.DEC, nil, 0xf0)
msg_type = ProtoField.uint8( "s3tp.msg_type", "Message Type",     base.DEC, msg_types, 0x0f)
flags    = ProtoField.uint8( "s3tp.flags",    "Flags",            base.HEX)
src_port = ProtoField.uint16("s3tp.src_port", "Source Port",      base.DEC)
dst_port = ProtoField.uint16("s3tp.dst_port", "Destination Port", base.DEC)
seq_num  = ProtoField.uint16("s3tp.seq_num",  "Sequence Number",  base.DEC)
size     = ProtoField.uint16("s3tp.size",     "Size",             base.DEC)
hmac     = ProtoField.none(  "s3tp.hmac",     "HMAC")
payload  = ProtoField.none(  "s3tp.payload",  "Payload")

s3tp_protocol.fields = { version, msg_type, flags, flag_ack, flag_init,
                         flag_retran, flag_reserved, src_port, dst_port,
                         seq_num, size, hmac, payload }

function s3tp_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()

  if length == 0 then return end

  pinfo.cols.protocol = s3tp_protocol.name

  local subtree = tree:add(s3tp_protocol, buffer(),
                           "S3TP Protocol Version 1, Src Port: " ..
                           buffer(2, 2):uint() .. ", Dst Port: " ..
                           buffer(4, 2):uint())

  local payload_size = buffer(8, 2):uint()

  subtree:add(version,  buffer(0,  1))
  subtree:add(msg_type, buffer(0,  1))
  local flag_tree = subtree:add(flags, buffer(1, 1))
  subtree:add(src_port, buffer(2,  2))
  subtree:add(dst_port, buffer(4,  2))
  subtree:add(seq_num,  buffer(6,  2))
  subtree:add(size,     buffer(8,  2))
  subtree:add(hmac,     buffer(10, 32))
  subtree:add(payload,  buffer(42, payload_size))

  flag_tree:add(flag_ack,      buffer(1, 1))
  flag_tree:add(flag_init,     buffer(1, 1))
  flag_tree:add(flag_retran,   buffer(1, 1))
  flag_tree:add(flag_reserved, buffer(1, 1))

  -- pinfo.cols.info:append(" " .. tostring(pinfo.src_port).." -> "..tostring(pinfo.dst_port))
end

local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(0x99, s3tp_protocol)
