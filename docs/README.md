Segment Routing with IPv6 (SRv6) is a leading Hybrid SDN (HSDN) architecture, as it fully exploits standard IP routing and forwarding both in the control plane and in the data plane. We designed and evaluated an efficient Linux software router in an HSDN/SRv6 architecture based on a programmable data plane architecture called HybrId Kernel/eBPF forwarding (HIKE). The HIKE architecture integrates the packet forwarding and processing based on the standard Linux kernel networking with the ones based on custom designed eBPF programs in order to speed up performance of SRv6 software routers.

More details about the overall HIKE architecture can be found [here](#scientific-papers). In the paper ["Performance Monitoring with H^2: Hybrid Kernel/eBPF data plane for SRv6 based Hybrid SDN"](http://netgroup.uniroma2.it/Stefano_Salsano/papers/20-srv6-hybrid-sdn-hike.pdf) we leveraged HIke for supporting SRv6 Networking and Performance Monitoring with significant increase in performance with respect to conventional Linux networking stack based solutions.

[We](#hike-linux-implementation-team) have designed and implemented HIKE in the context of the [ROSE](https://netgroup.github.io/rose/) project.

### HIKE Linux implementation source code

- HIKE framework: [https://github.com/netgroup/hike](https://github.com/netgroup/hike)

- The structure of the HIKE implementation is pretty straightforward. The `hike` folder hosts the code for the HIKE eBPF/XDP implementation, the only one that is actually implemented so far. The `ipv6_gen_prog.h` contains definitions, common structures and helper functions which can be used in HIKE eBPF/XDP programs. The `ipv6_gen_prog_kern.c` represents the core of the HIKE eBPF/XPD implementation: it contains HIKE programs (SRv6 encap, Performance Monitoring, etc), the logic for chaining such programs together and for interacting with the traditional Linux kernel networking stack.
The `ipv6_gen_prog_kern.c` is compiled in an object file which contains all the executable eBPF programs that can be used by the HIKE framework. Such programs are loaded using the ip command as described in the [testbed](#ipv6-l3-vpn-with-performance-monitoring-testbed) example.

- In order to interact with the HIKE programs, custom userspace application can be written leveraging the support of the `libbpf` library which is also provided in this repository. At the moment, HIKE programs are configured using the `bpftool` which allows us to inject any configuration in a binary format right within the command line or from a file.

- The `hike/testbed` folder contains a simple testbed used for getting familiar with the HIKE and to test first hand how the HIKE eBPF/XDP and the traditional Linux kernel networking stack can cooperate with each other for obtaining an hybrid packet processing and forwarding solution.

  NOTE: only the HIKE eBPF/XDP is implemented in the HIKE framework at the moment. We are working on the HIKE eBPF/TC implementation to complete the HIKE framework and to give you a full HIKE experience.

### HIKE Dependecies
Please follow the [link](https://github.com/netgroup/hike/blob/master/docs/setup_dependencies.org) to check out and resolve all the dependecies needed for compiling the HIKE framework and running testbeds.

### IPv6 L3 VPN with Performance Monitoring Testbed

Network topology
```text
+--------------+                                        +--------------+
|      h1      |                                        |      h2      |
|              |                                        |              |
|  cafe::1/64  |                                        |  cafe::2/64  |
|              |                                        |              |
|   veth-h1r1  |                                        |   veth-h2r2  |
|              |                                        |              |
+------+-------+                                        +-------+------+
       |                                                        |
       |                                                        |
       |                                                        |
+------+-------------------------+    +-------------------------+------+
|              r1                |    |              r2                |
| veth-r1h1            veth-r1r2 +----+ veth-r2r1            veth-r2h2 |
|                                |    |                                |
| cafe::100/64     fd00:12::1/64 |    | fd00:12::2/64     cafe::100/64 |
|  (hike)                        |    |   (hike)                       |
|                                |    |                                |
+--------------------------------+    +--------------------------------+
```

In this example, the HIKE framework is used for implementing an IPv6 L3 VPN service based on Segment Routing for IPv6 networks. Moreover, such VPN also provides Performance Monitoring capabilities within the domain of a tenant.

The example is made of 2 hosts (`h1` and `h2`) and 2 routers (`r1` and `r2`). Hosts `h1` and `h2` are respectively connected to router `r1` and router `r2`. The purpose of IPv6 L3 VPN is to connect `h1` and `h2` together and make it possible to exchange data between them. Without the VPN service, the communication between the two hosts is not possible due the presence of a public network (the one between `r1` and `r2`).

The IPv6 L3 VPN based on SRv6 networks leverages unidirectional tunnels. Therefore, to connect host `h1` with host `h2`, we need to create a i) SRv6 tunnel which starts from the `r1` and terminates on `r2` (for short `r1->r2`) and ii) a SRv6 tunnel which starts from `r2` and terminates on `r1` (for short `r2->r1`).  

To show the great flexibility of the HIKE framework, we choose to realize such tunnels following two different approaches. The SRv6 tunnel `r1->r2` is realized using the HIKE programs and the Linux kernel routing capabilities, while the `r2->r1` tunnel is made only using the SRv6 Linux kernel networking infrastructure.

Considering the tunnel `r1->r2`, in node `r1` we use the HIKE framework to apply the SRv6 policy relying on the HIKE SRv6 encap program and the HIKE SRv6 Performance Monitoring program (for monitoring the packet loss).
In node `r2`, we leverage the HIKE framework only for the performance monitoring activities and we use the SRv6 End.DT6 of the SRv6 Linux kernel networking stack for decapsulating the VPN packets.

On the contrary,for the reverse tunnel `r2->r1` we do not use any HIKE facilities. On the `r2` side, we rely only on the SRv6 Linux kernel networking stack which encapsulates the plain IPv6 packets coming from `h2` using the traditional SRv6 Linux kernel encap. On the `r1` node we decapsulate packet using the SRv6 End.DT6 made available, also in this case, by the Linux kernel networking stack.

To test first hand how this VPN service works, you can launch the `./testbed_vpn.sh` script in the terminal. Therefore, it will present you with 4 different tabs: `h1`, `r1`, `r2`, `h2`. To facilitate the interaction with those nodes, we use tmux along with the mouse support. In this way you can jump over any node and, using a packet sniffer, you can see the traffic.

To generate VPN traffic, please go into node `h1` and ping the `h2` node. Private addresses of `h1` and `h2` are `cafe::1` and `cafe::2` respectively.

```text
  ping -n cafe::2
  PING cafe::2(cafe::2) 56 data bytes
  64 bytes from cafe::2: icmp_seq=1 ttl=63 time=0.585 ms
```

### Scientific papers

- A. Mayer, P. Loreti, L. Bracciale, P. Lungaroni, S. Salsano, C. Filsfils,<br>
["Performance Monitoring with H^2: Hybrid Kernel/eBPF data plane for SRv6 based Hybrid SDN"](https://doi.org/10.1016/j.comnet.2020.107705),<br>
Elsevier Computer Networks, Volume 185, 11 February 2021 ([pdf-preprint](http://netgroup.uniroma2.it/Stefano_Salsano/papers/20-srv6-hybrid-sdn-hike.pdf))

### HIKE Linux implementation Team

- Andrea Mayer
- Pierpaolo Loreti
- Paolo Lungaroni
- Lorenzo Bracciale
- Stefano Salsano
