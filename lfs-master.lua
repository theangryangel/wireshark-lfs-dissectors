packetnum = -1

local proto_name = "LFS Master Protocol"
local proto_lfs = Proto("proto_lfs", proto_name)
proto_lfs.fields = {
	ProtoField.ipv4("server.ipv4", "Server IPv4 Addr"),
	ProtoField.uint8("server.port", "Server IPv4 Port", base.DEC),
	ProtoField.uint8("packet.size", "Packet Size", base.DEC),
	ProtoField.string("packet.type", "Packet Type")
}

function tree_add_client(buffer, pinfo, tree, offset, len)
	tree:add(buffer(offset + 1, 4), "Header: " .. buffer(offset + 1, 4):string())
	tree:add(buffer(offset + 5, 24), "24 Char Str(?): " .. buffer(offset + 5, 24):string())
	tree:add(buffer(offset + 41, 24), "Username: " .. buffer(offset + 41, 24):string())
	tree:add(buffer(offset + 65, 12), "Password(?): " .. buffer(offset + 65, 12):string())
end

function tree_add_server(buffer, pinfo, tree, offset, len)
	if (len == 8) then
		tree:add(buffer(offset + 5, 1), "Number of Servers: " .. buffer(offset + 5, 1):le_uint())
	else
		local ptr = offset + 1
		lfs_pkttree:add(proto_lfs.fields[4], "Server List")

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
