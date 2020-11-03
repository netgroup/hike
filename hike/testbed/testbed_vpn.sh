#!/bin/bash

# Network topology
#
# +--------------+                                           +--------------+
# |      h1      |                                           |      h2      |
# |              |                                           |              |
# |  cafe::1/64  |                                           |  cafe::2/64  |
# |              |                                           |              |
# |   veth-h1r1  |                                           |   veth-h2r2  |
# |              |                                           |              |
# +------+-------+                                           +-------+------+
#        |                                                           |
#        |                                                           |
#        |                                                           |
#  +-----+--------------------------+      +-------------------------+------+
#  |              r1                |      |              r2                |
#  | veth-r1h1            veth-r1r2 +------+ veth-r2r1            veth-r2h2 |
#  |                                |      |                                |
#  | cafe::100/64     fd00:12::1/64 |      | fd00:12::2/64     cafe::100/64 |
#  |  (hike)                        |      |   (hike)                       |
#  |                                |      |                                |
#  +--------------------------------+      +--------------------------------+
#

TMUX=hike

# Kill tmux previous session
tmux kill-session -t $TMUX 2>/dev/null

ip -all netns del

ip netns add h1
ip netns add h2

ip netns add r1
ip netns add r2

ip -netns h1 link add veth-h1r1 type veth peer name veth-r1h1 netns r1
ip -netns h2 link add veth-h2r2 type veth peer name veth-r2h2 netns r2

ip -netns r1 link add veth-r1r2 type veth peer name veth-r2r1 netns r2

###################
#### Node: h1 #####
###################
echo -e "\nNode: h1"

ip -netns h1 link set dev lo up
ip -netns h1 link set dev veth-h1r1 up

ip -netns h1 -6 neigh add cafe::2 lladdr 00:00:00:00:01:00 dev veth-h1r1
ip -netns h1 addr add cafe::1/64 dev veth-h1r1


###################
#### Node: r1 #####
###################
echo -e "\nNode: r1"

ip netns exec r1 sysctl -w net.ipv6.conf.all.forwarding=1

ip -netns r1 link set dev lo up
ip -netns r1 link set dev veth-r1h1 up
ip -netns r1 link set dev veth-r1r2 up

ip -netns r1 link set dev veth-r1h1 address 00:00:00:00:01:00

ip -netns r1 addr add cafe::100/64 dev veth-r1h1
ip -netns r1 addr add fd00:12::1/64 dev veth-r1r2

ip -netns r1 -6 route add fc00::1 \
	encap seg6local action End.DT6 table 254 dev veth-r1r2

# XXX: Note that fc00::/64 are used for encoding the SIDs.
ip -netns r1 -6 route add fc00::2 via fd00:12::2 dev veth-r1r2

read -r -d '' r1_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).

	mount -t bpf bpf /sys/fs/bpf/
	mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	ip link set dev veth-r1h1 xdp obj prog_kern.o sec xdp_dispatcher

	# Load the dummy xdp_pass prog on the ingress interface
	# NOTE: both the veth endpoints need to be set with a xdp/eBPF program
	# otherwise packets are discarded.
	# ip link set dev veth-r1r2 xdp obj prog_kern.o sec xdp_pass

	# Consider the ENDIANESS (the experiment is run on top of a
	# little-endian machine)

	# uprogram written through bpftool (in hex):
	# 00 00 <opcode(1byte) operand(1byte)>{8} <00>{14}


	######################### IPv6 uprograms ##############################

	# The prog chain (uprogs) are store in the map value corresponding
	# to the key cafe::2
	# 
	# The prog chian is made, in this case, of 3 uprogs:
	# 
	#  1) 00 00 -> program loader, always set to 00 00;
	# 
	#  2) 01(a) 01(b) (a and b are used for referring the 1-st and 2-nd bytes):
	#      a) 01 is the encap program;
	#      b) 01 is the number of sids carried by the SIDlist.
	# 
	#  3) ff ff -> (end of program chain; pass the packet to the Linux
	#		networking stack).

	# eBPF IPv6 uprogram for DA cafe::2
	bpftool map update							\
		pinned /sys/fs/bpf/ebpfgen/ipv6_ingress_table			\
		key   hex ca fe 00 00 00 00 00 00 00 00 00 00 00 00 00 02 	\
		value hex 00 00 01 01 03 02 ff ff 00 00 00 00 00 00 00 00	\
			  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


	######################## SRH encap mode encap #########################

	# eBPF IPv6 SRH encap (encap) tables
	bpftool map update							\
		pinned /sys/fs/bpf/ebpfgen/srh_encap_sidlist_table_1	  	\
		key   hex ca fe 00 00 00 00 00 00 00 00 00 00 00 00 00 02	\
		value hex fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02	\


	############################## Monitoring #############################

	# +--------+
	# | Egress |
	# +--------+

	# eBPF monitoring set active color
	bpftool map update 							\
		pinned /sys/fs/bpf/ebpfgen/map_color				\
		key   hex 00 00 00 00						\
		value hex 01 00 00 00

	# eBPF monitoring set flow to be monitored (egress)
	bpftool map update							\
		pinned /sys/fs/bpf/ebpfgen/egress_mon_map_sidlist_1		\
		key   hex fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02	\
		value hex 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00	\
			  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


 	########## Device map for Routing and Forwarding programs  ############
 
 	# eBPF routing and forwarding using kernel helper functions;
 	# device table
 	bpftool map update							\
 		pinned /sys/fs/bpf/ebpfgen/rtfwd_tx_port_table			\
 		key   hex 03 00 00 00 						\
 		value hex 03 00 00 00

 	bpftool map update							\
 		pinned /sys/fs/bpf/ebpfgen/rtfwd_tx_port_table			\
 		key   hex 02 00 00 00 						\
 		value hex 02 00 00 00

	/bin/bash
EOF

###################
#### Node: r2 #####
###################
echo -e "\nNode: r2"

ip netns exec r2 sysctl -w net.ipv6.conf.all.forwarding=1

ip -netns r2 link set dev lo up
ip -netns r2 link set dev veth-r2h2 up
ip -netns r2 link set dev veth-r2r1 up

ip -netns r2 link set dev veth-r2h2 address 00:00:00:00:02:00

ip -netns r2 addr add cafe::100/64 dev veth-r2h2
ip -netns r2 addr add fd00:12::2/64 dev veth-r2r1

ip -netns r2 -6 route add fc00::2 \
	encap seg6local action End.DT6 table 254 dev veth-r2r1

ip -netns r2 -6 route add cafe::1 \
	encap seg6 mode encap segs fc00::1 dev veth-r2r1

ip -netns r2 -6 route add fc00::1 via fd00:12::1 dev veth-r2r1


read -r -d '' r2_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).

	mount -t bpf bpf /sys/fs/bpf/
	mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	ip link set dev veth-r2h2 xdp obj prog_kern.o sec xdp_pass

	# Load the dummy xdp_pass prog on the ingress interface
	# NOTE: both the veth endpoints need to be set with a xdp/eBPF program
	# otherwise packets are discarded.

	ip link set dev veth-r2r1 xdp obj prog_kern.o sec xdp_dispatcher

	# Consider the ENDIANESS (the experiment is run on top of a
	# little-endian machine)

	######################### IPv6 uprograms ##############################
 
 	# eBPF fallback IPv6 uprogram (::)
 	bpftool map update							\
 		pinned /sys/fs/bpf/ebpfgen/ipv6_ingress_table			\
 		key   hex 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 	\
 		value hex 00 00 03 01 ff ff 00 00 00 00 00 00 00 00 00 00 	\
 			  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

	############################## Monitoring #############################

	# +---------+
	# | Ingress |
	# +---------+

	# eBPF monitoring set flow to be monitored (egress)
	bpftool map update							\
		pinned /sys/fs/bpf/ebpfgen/ingress_mon_map_sidlist_1		\
		key   hex fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02	\
		value hex 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00	\
			  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


	/bin/bash
EOF

###################
#### Node: h2 #####
###################
echo -e "\nNode: h2"

ip -netns h2 link set dev lo up
ip -netns h2 link set dev veth-h2r2 up

ip -netns h2 -6 neigh add cafe::1 lladdr 00:00:00:00:02:00 dev veth-h2r2

ip -netns h2 addr add cafe::2/64 dev veth-h2r2


## Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n h1 ip netns exec h1 bash
tmux new-window -t $TMUX -n r1 ip netns exec r1 bash -c "${r1_env}"
tmux new-window -t $TMUX -n r2 ip netns exec r2 bash -c "${r2_env}"
tmux new-window -t $TMUX -n h2 ip netns exec h2 bash

tmux select-window -t :0
tmux set-option -g mouse on
tmux attach -t $TMUX
