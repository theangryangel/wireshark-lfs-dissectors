local proto_name = "LFS InSim Protocol"

-- Known LFS InSim packets
local proto_insim_packets = {
	-- invalid packet type
	0 = function(buffer, offset, tree)
	end,
	-- ISI
	1 = function(buffer, offset, tree)
	end,
}

local proto_insim = Proto("proto_insim", proto_name)
proto_insim.fields = {
	ProtoField.uint8("proto_insim.size", "Packet Size", base.DEC),
	ProtoField.uint8("proto_insim.id", "Packet ID", base.DEC),
	ProtoField.bytes("proto_insim.unhandled","Unhandled Packet Data"),
}

function proto_insim.dissector(buffer, pinfo, tree)

	local available = buffer:len()
	local used = 0

	pinfo.desegment_len = 0

	local subtree = tree:add(proto_insim, buffer(), proto_name)

	while used < available do
		local size = buffer(used, 1):uint()
		local id = buffer(used + 1, 1):uint()

		if (size + used) > available then
			pinfo.desegment_len = (size + used) - available
			return
		end

		treepkt = subtree:add(proto_insim, buffer(used), "InSim Packet")
		-- packet size
		treepkt:add(proto_insim.fields[1], buffer(used, 1))
		-- packet id
		treepkt:add(proto_insim.fields[2], buffer(used + 1, 1))

		if proto_insim_packets[id] then
			-- known packet
			proto_insim_packets[id](buffer, used, treepkt)
		else
			-- unhandled packet data
			treepkt:add(proto_insim.fields[3], buffer(used + 2, size - 2))
		end

		-- next packet
		used += size
	end 

end

-- register the dissector
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(29999, proto_insim)

udp_table = DissectorTable.get("udp.port")
udp_table:add(29999, proto_insim)
