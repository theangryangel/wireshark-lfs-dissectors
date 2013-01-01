do

	local lfs_insim_name = "LFS InSim Protocol"
	local lfs_insim = Proto("lfs_insim", lfs_insim_name)	

	-- known InSim packets
	local lfs_insim_packets = {
		-- unknown
		['unknown'] = function(buffer, tree)
		end,

		-- ISI
		[1] = function(buffer, tree)
		end,
	}
	
	function lfs_insim.dissector(buffer, pinfo, tree)
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

			if (lfs_insim_packets[id] ~= nil) then
				func = id
			end

			local subtree = tree:add(lfs_insim, rest(0, stream_length), lfs_insim_name .. " Packet")
			subtree:add(rest(0, 1), "Packet Size: " .. length)
			subtree:add(rest(1, 1), "Packet ID: " .. id)

			-- If we get a result from calling lfs_insim_packets[func]
			-- we need go again. This is useful for packets with multiple
			-- subtypes
			while ((func ~= nil) and (lfs_insim_packets[func] ~= nil)) do
				local res = lfs_insim_packets[func](rest(1, length), subtree)
				func = res
			end

			offset = offset + stream_length
		end
	
	end
	
	-- register the dissector
	tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(29999, lfs_insim)
	
	udp_table = DissectorTable.get("udp.port")
	udp_table:add(29999, lfs_insim)

end
