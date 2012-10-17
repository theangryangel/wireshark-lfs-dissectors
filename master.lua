packetnum = -1

local proto_name = "LFS Master Protocol"
local proto_lfs = Proto("proto_lfs", proto_name)
proto_lfs.fields = {
	ProtoField.ipv4("server.ipv4", "Server IPv4 Addr"),
	ProtoField.uint8("server.port", "Server IPv4 Port", base.DEC),
	ProtoField.uint8("packet.size", "Packet Size", base.DEC),
	ProtoField.string("packet.type", "Packet Type"),
	ProtoField.string("packet.header", "Packet Header"),
	ProtoField.string("license.username", "Licensed Username"),
	ProtoField.string("license.password", "Licensed Password (?)"),
	ProtoField.string("misc.string", "Unknown (String?)"),
}

function tree_add_client(buffer, pinfo, tree, offset, len)
	tree:add(proto_lfs.fields[5], buffer(offset + 1, 4))
	tree:add(proto_lfs.fields[8], buffer(offset + 5, 36))
	tree:add(proto_lfs.fields[6], buffer(offset + 41, 24))
	tree:add(proto_lfs.fields[7], buffer(offset + 65, 12))
end

function tree_add_server(buffer, pinfo, tree, offset, len)
	if (len == 8) then
		-- Initial response - success
		tree:add(buffer(offset + 5, 1), "Number of Servers (works for small values only?): " .. buffer(offset + 5, 1):le_uint())
	elseif (len == 32) then
		-- Initial response - error
		tree:add(buffer(offset + 1, 32), "Error message")
	else
		-- Otherwise, it's servers baby
		local ptr = offset + 1
		tree:add(proto_lfs.fields[4], "Server List")

		while (ptr + 8 < len) do

			local subtree = tree:add(proto_lfs, buffer(ptr, 6), "Server")
			subtree:add(proto_lfs.fields[1], buffer(ptr, 4))
			subtree:add(proto_lfs.fields[2], buffer(ptr + 4, 2), buffer(ptr + 4, 2):le_uint())

			ptr = ptr + 8
		end
	end
end

-- dissector function
function proto_lfs.dissector(buffer, pinfo, tree)
	local server = (pinfo.match ~= pinfo.dst_port)
	local direction = (server and "Server -> Client" or "Client -> Server")

	-- Add an proto_lfs Protocol subtree in the decoded pane
	local subtree = tree:add(proto_lfs, buffer(), proto_name .. " " .. direction)
	
	-- pktlen stores the actual buffer size
	local pktlen = buffer:len()
	local offset = 0
	
	-- main dissection loop
	while offset < pktlen do
		-- if offset is less than pktlen, then we have stacked messages
		local lfs_pktlen = buffer(offset, 1):uint()

		lfs_pkttree = subtree:add(proto_lfs, buffer(offset), "Packet")
		lfs_pkttree:add(proto_lfs.fields[3], buffer(offset, 1), lfs_pktlen)

		if (server) then
			tree_add_server(buffer, pinfo, lfs_pkttree, offset, lfs_pktlen)
		else 
			tree_add_client(buffer, pinfo, lfs_pkttree, offset, lfs_pktlen)
		end

		if lfs_pktlen < pktlen then
			offset = offset + lfs_pktlen + 1
		end
	end

	-- TODO
	-- Deal with LFS packets split across TCP packets
end

-- register the dissector
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add (29339, proto_lfs)
