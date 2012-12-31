local lfs_mp_udp_name = "LFS Multiplayer Protocol (UDP)"
local lfs_mp_udp = Proto("lfs_mp_udp", lfs_mp_udp_name)

function lfs_mp_udp.dissector(buffer, pinfo, tree)

	-- Add an proto_lfs Protocol subtree in the decoded pane
	local subtree = tree:add(lfs_mp_udp, buffer(), lfs_mp_udp_name .. " Packet")
	subtree:add(buffer(0, 1), "Packet Size " .. buffer(0, 1):le_uint())
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(58996, lfs_mp_udp)
