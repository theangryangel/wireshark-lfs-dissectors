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
		["unknown"] = function(buffer, tree)
			tree:add(buffer, "Unknown Packet")
		end,

		-- new player/racer(?)
		[0] = function(buffer, tree)
			tree:add(buffer(0), "New Racer(?)")
		end,

		-- chat message
		[1] = function (buffer, tree)
			tree:add(buffer(5), "Chat Message")
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
		end

	}

	local lfs_mp_tcp_name = "LFS Multiplayer Protocol (TCP) Stream"
	local lfs_mp_tcp = Proto("lfs_mp_tcp", lfs_mp_tcp_name)

	local lfs_mp_tcp_count_client
	local lfs_mp_tcp_count_server

	function lfs_mp_tcp.init()
		lfs_mp_tcp_count_client = 0
		lfs_mp_tcp_count_server = 0
	end

	function lfs_mp_tcp.dissector(buffer, pinfo, tree)
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

			if lfs_mp_tcp_packets[id] ~= nil then
				func = id
			end

			local subtree = tree:add(lfs_mp_tcp, rest(0, stream_length), lfs_mp_tcp_name .. " Packet")
			subtree:add(rest(0, 1), "Packet Size: " .. length)
			subtree:add(rest(1, 1), "Packet ID: " .. id)

			lfs_mp_tcp_packets[func](rest(1, length), subtree)

			offset = offset + stream_length
		end
	end

	tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(PORT, lfs_mp_tcp)

end
