do
	-- port
	local PORT = 63391

	-- UDP
	
	local lfs_mp_udp_name = "LFS Multiplayer Protocol (UDP)"
	local lfs_mp_udp = Proto("lfs_mp_udp", lfs_mp_udp_name)
	
	function lfs_mp_udp.dissector(buffer, pinfo, tree)
	
		-- Add an proto_lfs Protocol subtree in the decoded pane
		local subtree = tree:add(lfs_mp_udp, buffer(), lfs_mp_udp_name .. " Packet")
		subtree:add(buffer(0, 1), "Packet Size " .. buffer(0, 1):le_uint())
	end
	
	--udp_table = DissectorTable.get("udp.port")
	--udp_table:add(58996, lfs_mp_udp)
	
	-- TCP

	local lfs_mp_tcp_packets = {
		-- general
		["unknown"] = function(buffer, length, tree)
			tree:add(buffer, "Unknown Packet")
		end,

		-- client to server
		[2] = function (buffer, length, tree)
			tree:add(buffer(0, length), "Packet Debug")
		end,

		-- server to client
		[3] = function (buffer, length, tree)
			tree:add(buffer(8, 4), "Track ID (?) " .. buffer(8, 4):le_uint())
			tree:add(buffer(12, 32), "Track Name")
			tree:add(buffer(44, 200), "Welcome Message")
		end

	}

	local lfs_mp_tcp_name = "LFS Multiplayer Protocol (TCP) Stream"
	local lfs_mp_tcp = Proto("lfs_mp_tcp", lfs_mp_tcp_name)
	
	function lfs_mp_tcp.dissector(buffer, pinfo, tree)

		if pinfo.dstport == PORT then
			return
		end

		local size = buffer:len()
		local offset = 0
		
		-- main dissection loop
		while offset < size do
			local pktlen = buffer(offset, 1):le_uint()
	
			-- not enough data to decode the whole packet
			if pktlen + offset > buffer:len() then
				pinfo.desegment_len = pktlen + offset - buffer:len()
				return
			end
	
			local id = buffer(offset + 1, 1):le_uint()
	
			local subtree = tree:add(lfs_mp_tcp, buffer(offset + 1, pktlen), lfs_mp_tcp_name .. " Packet")
			subtree:add(buffer(offset, 1), "Packet Size: " .. buffer(0, 1):le_uint())
			subtree:add(buffer(offset + 1, 1), "Packet ID: " .. id)

			local func = 'unknown'

			if lfs_mp_tcp_packets[id] ~= nil then
				func = id
			end

			lfs_mp_tcp_packets[func](buffer(offset + 1, pktlen), pktlen, subtree)
	
			if pktlen < size then
				offset = offset + pktlen + 1
			end
		end
	end
	
	tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(PORT, lfs_mp_tcp)
	
end
