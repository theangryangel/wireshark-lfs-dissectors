do
	-- port
	local PORT = 63391

	-- UDP

	local lfs_mp_udp_name = "LFS Multiplayer Protocol (UDP)"
	local lfs_mp_udp = Proto("lfs_mp_udp", lfs_mp_udp_name)

	function lfs_mp_udp.dissector(buffer, pinfo, tree)

		local server = (pinfo.match ~= pinfo.dst_port)

		local direction = (server and "Server -> Client" or "Client -> Server")
		local subtree = tree:add(lfs_mp_udp, buffer, lfs_mp_udp_name .. " Packet (" .. direction .. ")")

		local length = buffer:len()

		subtree:add("Packet Size: " .. length)

		-- Hello/NAT busting
		if (buffer(0, 1):string() == 'L') then
			subtree:add(buffer(0, length), 'Hello/NAT Bust Message')
			return
		end

		-- otherwise we're a position packet, i think

		-- when sent from server first 2 bytes possibly used as an autoincrement id
		if (server) then
			subtree:add(buffer(0, 2), "Packet Order Number (?): " .. buffer(0, 2):le_uint())
		end
	end

	udp_table = DissectorTable.get("udp.port")
	udp_table:add(PORT, lfs_mp_udp)

	-- TCP

	local lfs_mp_tcp_packets = {
		-- general
		["unknown"] = function(buffer, tree)
			tree:add(buffer, "Unknown TCP Packet")
		end,

		-- multi-purpose
		[1] = function (buffer, tree)
			-- XXX:  probably bitwise flags rather than a number
			local subt = buffer(1, 1):le_uint()

			tree:add(buffer(1, 1), "SubType: " .. subt)
			
			-- return the next function the dissector should call
			-- prevents us from cluttering up this function when there are large
			-- numbers of subtypes
			return "1:" .. tostring(subt)
		end,

		-- packet 1, subtype 1
		-- chat message
		["1:1"] = function(buffer, tree)
			tree:add(buffer(3, 1), "Connection ID: " .. buffer(3, 1):le_uint())

			if (buffer:len() > 4) then
				tree:add(buffer(5), "Chat Message")
			end
		end,

		-- welcome message/track information
		[3] = function (buffer, tree)
			tree:add(buffer(8, 4), "Track ID (?)" .. buffer(8, 4):le_uint())
			tree:add(buffer(12, 32), "Track Name")

			if (buffer():len() > 44) then
				tree:add(buffer(44), "Welcome Message")
			end
		end,

		-- always preceeds packet id 5
		-- possible hashing/encryption for packet id 5?
		-- possibly a variation on http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm??
		[4] = function(buffer, tree)
			tree:add(buffer(0), "Pre-Setup data(?)")
		end,

		-- setup(?)
		-- seems to be encrypted by data from packet id 4
		[5] = function(buffer, tree)
			tree:add(buffer(0), "Setup - Seems to be encrypted by Packet ID 4 (previous packet)")
			tree:add(buffer(12, 32), "Car")
			tree:add(buffer(44, 16), "Skin Name")
		end,

		-- New connection(?)
		[7] = function(buffer, tree)
			tree:add(buffer(1, 1), "Connection ID: " .. buffer(1, 1):le_uint())
			tree:add(buffer(4, 24), "Player Name: " .. buffer(4, 24):string())
			tree:add(buffer(36, 24), "License Name: " .. buffer(36, 24):string())
		end,

		-- New player(?)
		[49] = function(buffer, tree)
			tree:add(buffer(4, 24), "Player Name: " .. buffer(4, 24):string())
			tree:add(buffer(36, 4), "Vehicle (Short): " .. buffer(36, 4):string())
			tree:add(buffer(64, 24), "License Name: " .. buffer(64, 24):string())
		end,
	}

	local lfs_mp_tcp_name = "LFS Multiplayer Protocol (TCP)"
	local lfs_mp_tcp = Proto("lfs_mp_tcp", lfs_mp_tcp_name)

	local lfs_mp_tcp_count_client
	local lfs_mp_tcp_count_server

	function lfs_mp_tcp.init()
		lfs_mp_tcp_count_client = 0
		lfs_mp_tcp_count_server = 0
	end

	function lfs_mp_tcp.dissector(buffer, pinfo, tree)

		local direction = ((pinfo.match ~= pinfo.dst_port) and "Server -> Client" or "Client -> Server")

		local offset = 0

		while (offset < buffer:len()) do

			local rest = buffer(offset)

			local length = rest(0,1):le_uint()

			assert((length ~= 0), "Invalid packet size!")

			local stream_length = length + 1

			if (rest:len() < stream_length) then
				-- packet is not complete
				pinfo.desegment_offset = offset
				pinfo.desegment_len = stream_length - rest:len()
				return nil
			end

			local func = 'unknown'
			local id = rest(1, 1):le_uint()

			if (lfs_mp_tcp_packets[id] ~= nil) then
				func = id
			end

			local subtree = tree:add(lfs_mp_tcp, rest(0, stream_length), lfs_mp_tcp_name .. " Packet (" .. direction .. ")")
			subtree:add(rest(0, 1), "Packet Size: " .. length)
			subtree:add(rest(1, 1), "Packet ID: " .. id)

			-- If we get a result from calling lfs_mp_tcp_packets[func]
			-- we need go again. This is useful for packets with multiple
			-- subtypes
			while ((func ~= nil) and (lfs_mp_tcp_packets[func] ~= nil)) do
				local res = lfs_mp_tcp_packets[func](rest(1, length), subtree)
				func = res
			end

			offset = offset + stream_length
		end
	end

	-- register
	tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(PORT, lfs_mp_tcp)

end
