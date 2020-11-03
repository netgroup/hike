
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#include "ipv6_gen_prog.h"

struct bpf_elf_map SEC("maps") gen_jmp_table = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= GEN_PROG_MAP_ID,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GEN_NS,
	.max_elem	= GEN_PROG_TABLE_SIZE,
};

struct bpf_elf_map SEC("maps") pcpu_uprog_ctx_table = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct uprogram),
	.max_elem	= 1,
};

static __always_inline struct uprogram *pcpu_uprog_ctx(void)
{
	const __u32 off = 0;

	return  bpf_map_lookup_elem(&pcpu_uprog_ctx_table, &off);
}

static __always_inline int
uprog_fetch_current_instr(struct uprogram *up, __u8 *opcode, __u8 *operand)
{
	__u8 uip = up->uip;
	struct uinstr *uins;

	if (uip >= UIP_MAX)
		return -EINVAL;

	uins = &up->uins[uip & UIP_MASK];
	if (!uins)
		return -EINVAL;

	if (opcode)
		*opcode = uins->opcode;
	if (operand)
		*operand = uins->operand;

	return 0;
}

static __always_inline __u8 uprog_uip_inc(struct uprogram *up)
{
	return ++up->uip;
}

static __always_inline int
bpf_tail_call_next_uprog(struct xdp_md *ctx, struct uprogram *up)
{
	__u8 operand;
	__u8 opcode;
	int rc;

	/* points to the next instruction */
	uprog_uip_inc(up);

	rc = uprog_fetch_current_instr(up, &opcode, &operand);
	if (rc < 0)
		return rc;

	/* End instruciton is reached, tail call stops here */
	if (opcode == UINSTR_OPCODE_END && operand == UINSTR_OPERAND_END)
		return -ENOENT;

	bpf_tail_call(ctx, &gen_jmp_table, opcode);

	/* fallback
	 * No programs are registered with the given opcode: notify it to
	 * the caller.
	 */
	return -EBADRQC;
}

static __always_inline int uprog_retcode_is_error(int rc)
{
	if (!rc)
		return 0;

	if (rc == -ENOENT)
		/* it means we reached the last instruction */
		return 0;

	/* bpf_tail_call and other errors are considered as *ERROR* */
	return 1;
}

#define PCPU_SCRATCH_BUFSIZE	128
struct bpf_elf_map SEC("maps") pcpu_scratch = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= PCPU_SCRATCH_BUFSIZE,
	.max_elem	= 1,
};

static __always_inline void *get_scratch_ptr(void)
{
	const __u32 off = 0;

	return  bpf_map_lookup_elem(&pcpu_scratch, &off);
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/* The total number of IPv6 DA addresses that can be associated with a prog */
#define IPv6_INGRESS_TABLE_SIZE	64
struct bpf_elf_map SEC("maps") ipv6_ingress_table = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct in6_addr),
	.size_value	= sizeof(struct uprogram),
	.pinning	= PIN_GEN_NS,
	.max_elem	= IPv6_INGRESS_TABLE_SIZE,
};

static __always_inline int parse_ethhdr(struct hdr_cursor *cur,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = cur_data(cur);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (!cur_may_pull(cur, sizeof(*eth)))
		return -ENOBUFS;

	if (ethhdr)
		*ethhdr = eth;

	vlh = cur_pull(cur, sizeof(*eth));
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (!cur_may_pull(cur, sizeof(*vlh)))
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		cur_pull(cur, sizeof(*vlh));
	}

	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *cur,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = cur_data(cur);

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (!cur_may_pull(cur, sizeof(*ip6h)))
		return -ENOBUFS;

	if (ip6hdr)
		*ip6hdr = ip6h;

	cur_pull(cur, sizeof(*ip6h));

	return ip6h->nexthdr;
}

static __always_inline int parse_srv6hdr(struct hdr_cursor *cur,
					 struct ipv6_sr_hdr **sr6h)
{
	struct ipv6_sr_hdr *srh;
	int hdrsize;

	if (!cur_may_pull(cur, sizeof(*srh)))
		return -ENOBUFS;

	srh = cur_data(cur);
	if (!srh)
		return -ENOBUFS;

	if (srh->type != IPV6_SRCRT_TYPE_4)
		return -EINVAL;

	/* check boundaries again, the real size of the srh is known now */
	hdrsize = ipv6_optlen(srh);
	if (!cur_may_pull(cur, hdrsize))
		return -ENOBUFS;

	cur_pull(cur, hdrsize);
	if (sr6h)
		*sr6h = srh;

	/* next-header protocol number */
	return srh->nexthdr;
}

static __always_inline int
copy_uprog(struct uprogram *dst, struct uprogram *src)
{
#ifdef __OPTIMIZED_CODE
	/* this workaround makes the copy between dst and src efficient */
	struct __tmp  {
		union {
			/* 32 bytes */
			struct uprogram *up;
			__u64 p[4];
		} a;
	};
	struct __tmp *v0 = (struct __tmp *)dst;
	struct __tmp *v1 = (struct __tmp *)src;
	int i;

	if (!v0 || !v1)
		return -EINVAL;

	/* shallow copy of the two programs */
	#pragma unroll
	for(i = 0; i < 4; ++i)
		v0->a.p[i] = v1->a.p[i];
#else
	if (!dst || !src)
		return -EINVAL;

	*dst = *src;
#endif

	return 0;
}

static __always_inline struct uprogram *
ipv6_lookup_uprog_by_addr(struct in6_addr *addr)
{
	struct uprogram *uprog;

#define __ipv6_lookup_uprog_by_addr(__addr)		\
	bpf_map_lookup_elem(&ipv6_ingress_table, (__addr));

	if (!addr) {
		struct in6_addr zaddr;

		memset((void *)&zaddr, 0, sizeof(zaddr));

		/* the IPv6 addr :: is reserved for the fallback IPv6 fallback
		 * program (if any).
		 */
		uprog = __ipv6_lookup_uprog_by_addr(&zaddr);
	} else {
		uprog = __ipv6_lookup_uprog_by_addr(addr);
	}

	return uprog;

#undef __ipv6_lookup_uprog_by_addr
}

static __always_inline int
ipv6_lookup_uprog_with_fallback(struct ipv6hdr *ip6h, struct uprogram **uprog)
{
	struct uprogram *ipv6_uprog;
	struct in6_addr *daddr;

	daddr = &ip6h->daddr;
	if (!daddr)
		return -EINVAL;

	ipv6_uprog = ipv6_lookup_uprog_by_addr(daddr);
	if (ipv6_uprog)
		goto found;

	/* there is no program for the given daddr, let's try to see if there
	 * is a generic program for any address ::
	 *
	 * note: we represent at this level the :: program with the NULL
	 * argument.
	 */
	ipv6_uprog = ipv6_lookup_uprog_by_addr(NULL);
	if (!ipv6_uprog)
		return -ENOENT;

found:
	*uprog = ipv6_uprog;

	return 0;
}

static __always_inline int
xdp_ipv6_bpf_tail_call_uprog(struct xdp_md *ctx, struct ipv6hdr *ip6h)
{
	struct uprogram *uprog, *ipv6_uprog;
	int rc;

	uprog = pcpu_uprog_ctx();
	if (!uprog)
		/* but no uprogram infrastructure found for IPv6; go ahead. */
		goto pass;

	rc = ipv6_lookup_uprog_with_fallback(ip6h, &ipv6_uprog);
	if (rc < 0) {
		if (rc == -ENOENT)
			/* no uprogram found for IPv6, go ahead  */
			goto pass;

		/* notify to the caller any other kind of error */
		return rc;
	}

	if (!ipv6_uprog)
		return -EINVAL;

	/* the IPv6 uprogram has been found and it's time to copy it in the
	 * pcpu uprogram area. In this way the program will be available
	 * to any uprogram in the entire tail call chain.
	 */
	copy_uprog(uprog, ipv6_uprog);

	/* time to carry out the bpf_tail_call using the first uprogram in the
	 * chain.
	 */
	rc = bpf_tail_call_next_uprog(ctx, uprog);

	/* fallback */
	return rc;

pass:
	return 0;
}

__section("xdp_dispatcher")
int xdp_ipv6_gen_prog(struct xdp_md *ctx)
{
	struct hdr_cursor *cur;
	int action = XDP_PASS;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;
	__be16 eth_type;
	int nexthdr;
	int rc;

	cur = get_scratch_ptr();
	if (!cur)
		goto out;

	/* initialize the cursor */
	cur_init(cur, ctx);

	eth_type = parse_ethhdr(cur, &eth);
	if (!eth || eth_type < 0)
		goto out;

	/* set the network header */
	cur_reset_network_header(cur);

	/* for the moment we handle only IPv6 traffic */
	if (eth_type != bpf_htons(ETH_P_IPV6))
		goto out;

	nexthdr = parse_ip6hdr(cur, &ip6h);
	if (nexthdr < 0 || !ip6h)
		goto out;

	cur_reset_transport_header(cur);

	rc = xdp_ipv6_bpf_tail_call_uprog(ctx, ip6h);
	if (uprog_retcode_is_error(rc))
		return XDP_ABORTED;
out:
	return action;
}

__section("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

/* ~~~~~~~~~~~~~~~~~~~ IPv6 Segment Routing Encap (encap) ~~~~~~~~~~~~~~~~~~~ */

#if 0
static int __always_inline
ipv6_srh_encap_inline(struct xdp_md *ctx, struct hdr_cursor *cur, int nsids)
{
	const int hdrlen = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	struct ipv6hdr *old_ip6h, *ip6h;
	struct ethhdr *old_eth, *eth;
	void *data_end, *data;

	if (bpf_xdp_adjust_head(ctx, 0 - hdrlen) < 0)
		goto error;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	/* context is changed, we have to update all the pointers */
	if (cur_update_pointers_after_head_expand(cur, data, hdrlen,
						  data_end) < 0)
		goto error;

	/* IPv6 copy */

	old_ip6h = cur_header_pointer(cur, cur->nhoff, sizeof(*old_ip6h));
	if (!old_ip6h)
		goto error;

	/* set the data offset where we have to push the new header */
	if (cur_set_data(cur, cur->mhoff) < 0)
		goto error;

	ip6h = cur_push(cur, sizeof(*ip6h));
	if (!ip6h)
		goto error;

	cur_reset_network_header(cur);
	memcpy((void *)ip6h, (void *)old_ip6h, sizeof(*ip6h));

	/* Copy Ethernet */

	/* XXX: Register spilling seems to not work perfectly, we have to
	 * remind the verifier which are the cur->head and cur->tail ... :(
	 */
	__cur_update(cur, data, data_end);
	old_eth = cur_header_pointer(cur, cur->mhoff, sizeof(*old_eth));
	if (!old_eth)
		goto error;

	eth = cur_push(cur, sizeof(*eth));
	if (!eth)
		goto error;

	cur_reset_mac_header(cur);
	memcpy((void *)eth, (void *)old_eth, sizeof(*eth));

	return 0;

error:
	return -EINVAL;
}
#endif

#define SRH_ENCAP_SIDLIST_NAME(__len) srh_encap_sidlist_##__len

#define DEFINE_SRH_ENCAP_SIDLIST(__len)					\
	struct SRH_ENCAP_SIDLIST_NAME(__len) {				\
		struct in6_addr sids[(__len)];				\
	}

#define SRH_ENCAP_SIDLIST_TABLE_NAME(__nsids)				\
	srh_encap_sidlist_table_##__nsids

#define SRH_ENCAP_SID_TABLE(__nsids)					\
DEFINE_SRH_ENCAP_SIDLIST(__nsids);					\
									\
struct bpf_elf_map SEC("maps")						\
SRH_ENCAP_SIDLIST_TABLE_NAME(__nsids) = {				\
	.type		= BPF_MAP_TYPE_HASH,				\
	.size_key	= sizeof(struct in6_addr),			\
	.size_value	= sizeof(struct SRH_ENCAP_SIDLIST_NAME(__nsids)), \
	.pinning	= PIN_GEN_NS,					\
	.max_elem	= SRH_ENCAP_SIDLIST_TABLE_SIZE,			\
}									\


/* IPv6 SRH Encap encap programs
 *
 * NOTE: if you declare a new ENCAP please keep updated the
 * srh_encap_sidlist_select(...) function. This declarative approach
 * is needed to overcome some eBPF limitations.
 */
SRH_ENCAP_SID_TABLE(1);
SRH_ENCAP_SID_TABLE(2);
SRH_ENCAP_SID_TABLE(3);
SRH_ENCAP_SID_TABLE(4);
SRH_ENCAP_SID_TABLE(5);
SRH_ENCAP_SID_TABLE(6);
SRH_ENCAP_SID_TABLE(7);
SRH_ENCAP_SID_TABLE(8);

static __always_inline void *srh_encap_sidlist_select(__u8 nsids)
{
#define __begin	switch (nsids) {

#define __cast(__v)						\
	case (__v):						\
		return &(SRH_ENCAP_SIDLIST_TABLE_NAME(__v));	\
	break

#define __end(nsids)						\
	default:						\
		return NULL;					\
	}

	__begin(nsids);
	__cast(1);
	__cast(2);
	__cast(3);
	__cast(4);
	__cast(5);
	__cast(6);
	__cast(7);
	__cast(IPv6_SRH_ENCAP_SIDLIST_MAX);
	__end(nsids);

#undef __begin
#undef __cast
#undef __end
	return NULL;
}

static __always_inline int
srh_check_encap_address(struct xdp_md *ctx, __u8 nsids)
{
	struct hdr_cursor *cur;
	struct in6_addr *daddr;
	struct ipv6hdr *ip6h;
	void *map_sidlist;
	void *sidlist;

	cur = get_scratch_ptr();
	if (!cur)
		goto error;

	if (cur_update_pointers(cur, ctx) < 0)
		goto error;

	ip6h = cur_header_pointer(cur, cur->nhoff, sizeof(*ip6h));
	if (!ip6h)
		goto error;

	daddr = &ip6h->daddr;
	if (!daddr)
		goto error;

	map_sidlist = srh_encap_sidlist_select(nsids);
	if (!map_sidlist)
		goto error;

	sidlist = bpf_map_lookup_elem(map_sidlist, daddr);
	if (!sidlist)
		/* no srh encap for the current IPv6 DA address */
		return -ENOENT;

	return 0;

error:
	return -EINVAL;
}

static __always_inline int srh_encap_check_sidlist_len(__u8 nsids)
{
	if (nsids == 0 || nsids > IPv6_SRH_ENCAP_SIDLIST_MAX)
		return -EINVAL;

	return 0;
}

static __always_inline int
__srh_encap_prepare_headers(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	const __u16 bytes_to_move = sizeof(struct ethhdr) +
				    sizeof(struct ipv6hdr);
#ifdef __OPTIMIZED_CODE
	struct __tmp {
		union {
			struct __h {
				/* same size of bytes_to_move */
				struct ethhdr eth;
				struct ipv6hdr ip6h;
			} h;
			struct __g {
				__be64 a[6];
				__be32 b[1];
				__be16 c[1];
			} g;
		} u;
		__u8 pad[2];
	};
	struct __tmp *v0, *v1;
	int i;
#endif
	const void *src_ptr;
	void *dst_ptr;

	src_ptr = cur_header_pointer(cur, cur->mhoff, bytes_to_move);
	if (!src_ptr)
		goto error;

	/* data starts from head */
	cur->dataoff = 0;
	dst_ptr = cur_header_pointer(cur, cur->dataoff, bytes_to_move);
	if (!dst_ptr)
		goto error;

#ifdef __OPTIMIZED_CODE
	v0 = (struct __tmp *)dst_ptr;
	v1 = (struct __tmp *)src_ptr;

	#pragma unroll
	for (i = 0; i < 6; ++i)
		v0->u.g.a[i] = 	v1->u.g.a[i];

	v0->u.g.b[0] = v1->u.g.b[0];
	v0->u.g.c[0] = v1->u.g.c[0];
#else
	/* we copy the mac header and the IPv6 header to the packet head */
	memmove(dst_ptr, src_ptr, bytes_to_move);
#endif

	cur_reset_mac_header(cur);
	__pull(cur, sizeof(struct ethhdr));

	/* data points to the outer ipv6 which has to be changed (it's a copy
	 * of the inner ipv6 header!).
	 */
	cur_reset_network_header(cur);

	cur_touch(cur, ctx);

	return 0;

error:
	return -EINVAL;
}

static __always_inline void
srh_encap_init_srh(struct ipv6_sr_hdr *srh, __u16 srhlen)
{
	__u8 nsids = (srhlen - 8) >> 4;

	srh->nexthdr = IPPROTO_IPV6;
	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	srh->segments_left = nsids - 1;
	srh->first_segment = nsids - 1;
	srh->flags = 0;
	srh->tag = 0;
}

static __always_inline void
__in6_addr_cpy(struct in6_addr *dst, struct in6_addr *src)
{
#ifdef __OPTIMIZED_CODE
	struct __tmp {
		union {
			struct in6_addr *addr;
			__be64 a[2];
		} u;
	};
	struct __tmp *v0 = (struct __tmp *)dst;
	struct __tmp *v1 = (struct __tmp *)src;

	v0->u.a[0] = v1->u.a[0];
	v0->u.a[1] = v1->u.a[1];
#else
	*dst = *src;
#endif
}

static __always_inline int
__memcpy_sidlist(struct xdp_md *ctx, struct hdr_cursor *cur,  __u8 nsids)
{
	struct in6_addr *segments;
	struct in6_addr *lastsid;
	struct in6_addr *daddr;
	struct ipv6hdr *ip6h;

	ip6h = cur_header_pointer(cur, cur->nhoff, sizeof(*ip6h));
	if (!ip6h)
		return -ENOBUFS;

	daddr = &ip6h->daddr;
	if (!daddr)
		return -EINVAL;

#define __cpy(__v) 							\
	case (__v): {							\
		struct SRH_ENCAP_SIDLIST_NAME(__v) *srh_sidlist;	\
		__u8 i;							\
									\
	        srh_sidlist = bpf_map_lookup_elem(			\
				&(SRH_ENCAP_SIDLIST_TABLE_NAME(__v)),	\
				daddr);					\
		if (!srh_sidlist)					\
			return -ENOENT;					\
									\
		cur_touch(cur, ctx);					\
		segments = cur_header_pointer(cur, cur->dataoff,	\
					      (__v) *			\
					      sizeof(*segments));	\
		if (!segments)						\
			return -ENOBUFS;				\
									\
		for (i = 0; i < (__v); ++i)				\
			__in6_addr_cpy(&segments[i],			\
				       &srh_sidlist->sids[i]);		\
		} break

#define __cpy_default return -EINVAL

	switch (nsids) {
		__cpy(1);
		__cpy(2);
		__cpy(3);
		__cpy(4);
		__cpy(5);
		__cpy(6);
		__cpy(7);
		__cpy(IPv6_SRH_ENCAP_SIDLIST_MAX);
		__cpy_default;
	};

#undef __cpy
#undef __cpy_default

	__pull(cur, (nsids - 1) * sizeof(*segments));

	cur_touch(cur, ctx);

	/* copy the last sid int the IPv6 DA */
	lastsid = cur_header_pointer(cur, cur->dataoff, sizeof(*lastsid));
	if (!lastsid)
		return -EINVAL;

	__in6_addr_cpy(&ip6h->daddr, lastsid);

	__pull(cur, sizeof(*lastsid));

	return 0;
}

static __always_inline  int
ipv6_srh_encap_encap(struct xdp_md *ctx, __u8 nsids)
{
	struct ipv6hdr *outer_ip6h;
	struct ipv6_sr_hdr *srh;
	struct hdr_cursor *cur;
	void *data, *data_end;
	__u16 ip6len;
	__u16 tothdr;
	__u16 srhlen;
	int rc;

	if (srh_encap_check_sidlist_len(nsids) < 0)
		goto error;

	srhlen = sizeof(struct ipv6_sr_hdr) + nsids * sizeof(struct in6_addr);
	tothdr = sizeof(struct ipv6hdr) + srhlen;

	if (bpf_xdp_adjust_head(ctx, 0 - tothdr) < 0)
		goto error;

	/* after extension of header, reload all the pointers */
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	cur = get_scratch_ptr();
	if (!cur)
		goto error;

	/* context is changed, we have to update all the pointers */
	if (cur_update_pointers_after_head_expand(cur, ctx, tothdr) < 0)
		goto error;

	/* it makes a copy of the inner IPv6 header for creating the outer
	 * IPv6 header. The funcitons also move the ethernet header to the
	 * top of the new packet head.
	 */
	if (__srh_encap_prepare_headers(ctx, cur) < 0)
		goto error;

	if (!cur_may_pull(cur, sizeof(*outer_ip6h)))
		goto error;

	outer_ip6h = cur_data(cur);
	if (!outer_ip6h)
		goto error;

	outer_ip6h->nexthdr = IPPROTO_ROUTING;

	/* we copied the inner IPv6 header so the payload_len was already set
	 * with the original size of the payload... but we need to update such
	 * field consdiering the inner IPv6 + SRH.
	 */
	ip6len = bpf_ntohs(outer_ip6h->payload_len) + tothdr;
	outer_ip6h->payload_len = bpf_htons(ip6len);

	/* just to make a bit different the two IPv6 headers ... */
	outer_ip6h->hop_limit = SRH_ENCAP_HOP_LIMIT;

	/* Transport header (SRH header) */
	__pull(cur, sizeof(struct ipv6hdr));
	cur_reset_transport_header(cur);

	if (!cur_may_pull(cur, sizeof(*srh)))
		goto error;

	srh = cur_data(cur);
	if (!srh)
		goto error;

	srh_encap_init_srh(srh, srhlen);
	__pull(cur, sizeof(*srh));

	/* dataoff points to the first segment in the sidlist */
	rc = __memcpy_sidlist(ctx, cur, nsids);
	if (rc < 0)
		return rc;

	return 0;

error:
	return -EINVAL;
}

__section_tail(GEN_PROG_MAP_ID, UINSTR_OPCODE_SRH_ENCAP_ENCAP)
int xdp_ipv6_srh_encap_prog(struct xdp_md *ctx)
{
	struct uprogram *uprog;
	__u8 nsids = 0;
	int rc;

	/* get the uprogram */
	uprog = pcpu_uprog_ctx();
	if (!uprog)
		goto error;

	/* the number of sids for the encap is stored in the operand of the
	 * current micro instruction.
	 */
	rc = uprog_fetch_current_instr(uprog, NULL, &nsids);
	if (rc < 0)
		goto error;

	if (srh_encap_check_sidlist_len(nsids) < 0)
		goto error;

	rc = srh_check_encap_address(ctx, nsids);
	if (rc < 0) {
		if (rc == -ENOENT)
			/* no encap for this IPv6 DA */
			goto out;

		goto error;
	}

	if (ipv6_srh_encap_encap(ctx, nsids) < 0)
		goto error;

out:
	/* we execute the bpf_tail_call to the next program */
	rc = bpf_tail_call_next_uprog(ctx, uprog);
	if (uprog_retcode_is_error(rc))
		goto error;

	return XDP_PASS;

error:
	return XDP_ABORTED;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~ ROUTING AND FORWARDING ~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define RTFWD_TX_PORT_TABLE_SIZE	64
struct bpf_elf_map SEC("maps") rtfwd_tx_port_table = {
	.type		= BPF_MAP_TYPE_DEVMAP,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GEN_NS,
	.max_elem	= RTFWD_TX_PORT_TABLE_SIZE,
};

static __always_inline int xdp_ipv6_rtfwd_kernel(struct xdp_md *ctx, __u8 flags)
{
	struct bpf_fib_lookup fib_params;
	struct in6_addr *saddr, *daddr;
	__u32 fib_lookup_flags = 0;
	struct hdr_cursor *cur;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;
	int action;
	int rc;

	memset((void *)&fib_params, 0, sizeof(fib_params));

	cur = get_scratch_ptr();
	if (!cur)
		goto error;

	if (cur_update_pointers(cur, ctx) < 0)
		goto error;

	ip6h = cur_header_pointer(cur, cur->nhoff, sizeof(*ip6h));
	if (!ip6h)
		goto error;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

	fib_lookup_flags = flags & UINSTR_OPERAND_IPv6_FWD_OPERAND_MASK;

	saddr = (struct in6_addr *)fib_params.ipv6_src;
	daddr = (struct in6_addr *)fib_params.ipv6_dst;

	*saddr			= ip6h->saddr;
	*daddr			= ip6h->daddr;
	fib_params.family	= AF_INET6;
	fib_params.flowinfo	= *((__be32 *)ip6h) & IPv6_FLOWINFO_MASK;
	fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
	fib_params.l4_protocol	= ip6h->nexthdr;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.ifindex	= ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),
			    fib_lookup_flags);

	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		/* decrease the hop-limit and prepare the ethernet layer
		 * for submitting the frame.
		 */
		ip6h->hop_limit--;

		cur_touch(cur, ctx);

		eth = cur_header_pointer(cur, cur->mhoff, sizeof(*eth));
		if (!eth)
			goto error;

		/* TODO: to optimize ? */
		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

		action = bpf_redirect_map(&rtfwd_tx_port_table,
					  fib_params.ifindex, 0);

		break;

	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;

	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		action = XDP_PASS;
		break;
	}

	return action;

error:
	return XDP_ABORTED;
}

/* Routing and forwarding program for IPv6 using eBPF kernel helper functions.
 * If the packet is routed/forwarded successfully, the program chain is
 * interrupted.
 * If the packet is not forwarded and there are no errors, then it
 * is possible to call the next uprogram in the chain.
 * If an error occurred during the routing and fortwarding function, the
 * program returns the error code and the call to the next program (if any) is
 * avoided.
 *
 * Routing and Forwarding program (with kernel tables support)
 */
__section_tail(GEN_PROG_MAP_ID, UINSTR_OPCODE_IPv6_FWD_KERNEL)
int xdp_ipv6_rtfwd_kernel_prog(struct xdp_md *ctx)
{
	struct uprogram *uprog;
	__u8 opcode;
	__u8 flags;
	int rc;

	/* get the uprogram */
	uprog = pcpu_uprog_ctx();
	if (!uprog)
		goto error;

	rc = uprog_fetch_current_instr(uprog, &opcode, &flags);
	if (rc < 0)
		goto error;

	/* paranoid: check if the current opcode matches with this program */
	if (opcode != UINSTR_OPCODE_IPv6_FWD_KERNEL)
		goto error;

	if (flags & UINSTR_OPERAND_IPv6_FWD_KERNEL)
		/* pass the packet directly to the kernel */
		return XDP_PASS;

	rc = xdp_ipv6_rtfwd_kernel(ctx, flags);
	switch (rc) {
	case XDP_TX:
	case XDP_REDIRECT:
		/* if we have to redirect the packet, we stop the program
		 * chain here (for this implementation).
		 */
		return rc;

	case XDP_PASS:
		goto out;

	default:
	case XDP_DROP:
	case XDP_ABORTED:
		return rc;
	}

out:
	rc = bpf_tail_call_next_uprog(ctx, uprog);
	if (uprog_retcode_is_error(rc))
		goto error;

	return XDP_PASS;

error:
	return XDP_ABORTED;
}

struct bpf_elf_map SEC("maps") fib6_info_table_0 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct in6_addr),
	.size_value	= sizeof(struct fib6_info),
	.pinning	= PIN_GEN_NS,
	.max_elem	= FIB6_INFO_TABLE_SIZE,
};

/* copy the fib6_info dst,src in the ethernet header dst,src. Read the
 * fib6_info comments for more details about alignement of the structures.
 */
static __always_inline void
__ethhdr_addresses_cpy(struct ethhdr *eth, struct fib6_info *fib)
{
#ifdef __OPTIMIZED_CODE
	struct __tmp {
		union {
			struct __e {
				struct ethhdr *d;
				struct ethhdr *s;
			} e;
			struct __f {
				__u64 a[1];
				__u16 b[1];
			} f;
		} u;
	};
	struct __tmp *v0 = (struct __tmp *)eth;
	struct __tmp *v1 = (struct __tmp *)fib;

	v0->u.f.a[0] = v1->u.f.a[0];
	v0->u.f.b[0] = v1->u.f.b[0];
#else
	memcpy((void *)eth->h_dest, (const void *)fib->dst, ETH_ALEN);
	memcpy((void *)eth->h_source, (const void *)fib->src, ETH_ALEN);
#endif
}

static __always_inline int xdp_ipv6_rtfwd_raw(struct xdp_md *ctx, __u8 flags)
{
	struct in6_addr *daddr;
	struct hdr_cursor *cur;
	struct fib6_info *fib;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;

	cur = get_scratch_ptr();
	if (!cur)
		goto error;

	if (cur_update_pointers(cur, ctx) < 0)
		goto error;

	ip6h = cur_header_pointer(cur, cur->nhoff, sizeof(*ip6h));
	if (!ip6h)
		goto error;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

	daddr = &ip6h->daddr;
	if (!daddr)
		goto error;

	flags = flags & UINSTR_OPERAND_IPv6_RT_RAW_MASK;

	fib = bpf_map_lookup_elem(&fib6_info_table_0, daddr);
	if (!fib) {
		/* no fib found, let's see if we can pass the packet to
		 * the kernel; otherwise we drop it.
		 */
		if (flags & UINSTR_OPERAND_IPv6_RT_RAW_STRICT)
			return XDP_DROP;

		/* pass the packet to the kernel */
		return XDP_PASS;
	}

	--ip6h->hop_limit;

	cur_touch(cur, ctx);

	eth = cur_header_pointer(cur, cur->mhoff, sizeof(*eth));
	if (!eth)
		goto error;

	/* rebuild the mac header addresses.  */

	__ethhdr_addresses_cpy(eth, fib);

	return bpf_redirect_map(&rtfwd_tx_port_table, fib->ifindex, 0);

error:
	return XDP_ABORTED;
}

/* Routing and Forwarding RAW program (no kernel support) */
__section_tail(GEN_PROG_MAP_ID, UINSTR_OPCODE_IPv6_RT_RAW)
int xdp_ipv6_rtfwd_raw_prog(struct xdp_md *ctx)
{
	struct uprogram *uprog;
	__u8 opcode;
	__u8 flags;
	int rc;

	/* get the uprogram */
	uprog = pcpu_uprog_ctx();
	if (!uprog)
		goto error;

	rc = uprog_fetch_current_instr(uprog, &opcode, &flags);
	if (rc < 0)
		goto error;

	/* paranoid: check if the current opcode matches with this program */
	if (opcode != UINSTR_OPCODE_IPv6_RT_RAW)
		goto error;

	if (flags & UINSTR_OPERAND_IPv6_RT_RAW_KERN_PASS)
		/* pass the packet directly to the kernel */
		return XDP_PASS;

	rc = xdp_ipv6_rtfwd_raw(ctx, flags);
	switch (rc) {
	case XDP_TX:
	case XDP_REDIRECT:
		/* if we have to redirect the packet, we stop the program
		 * chain here (for this implementation).
		 */
		return rc;

	case XDP_PASS:
		goto out;

	default:
	case XDP_DROP:
	case XDP_ABORTED:
		return rc;
	}

out:
	rc = bpf_tail_call_next_uprog(ctx, uprog);
	if (uprog_retcode_is_error(rc))
		goto error;

	return XDP_PASS;

error:
	return XDP_ABORTED;
}



/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Dummy program ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

__section_tail(GEN_PROG_MAP_ID, UINSTR_OPCODE_NOP)
int xdp_nop_uprog(struct xdp_md *ctx)
{
	struct uprogram *uprog;
	__u8 opcode;
	int rc;

	bpf_printk(">>> eBPF: nop program called\n");

	uprog = pcpu_uprog_ctx();
	if (!uprog)
		goto error;

	rc = uprog_fetch_current_instr(uprog, &opcode, NULL);
	if (rc < 0)
		goto error;

	if (opcode != UINSTR_OPCODE_NOP) {
		bpf_printk(">>> eBPF: nop program wrong OPCODE\n");
		goto error;
	}

	rc = bpf_tail_call_next_uprog(ctx, uprog);
	if (uprog_retcode_is_error(rc))
		goto error;

	return XDP_PASS;

error:
	bpf_printk(">>> eBPF: nop program aborted\n");

	return XDP_ABORTED;
}

/* ~~~~~~~~~~~~~~~~~~~~~ Packet Loss Monitoring Program ~~~~~~~~~~~~~~~~~~~~~ */

/* declare a new map which is meant for holding keys of (16 * __len) bytes.
 * In other words, the key represents a sid_list of __len sids.
 */
#define MON_KEY_SIDLIST_NAME(__len) mon_key_sidlist_##__len

#define DEFINE_MON_KEY_SIDLIST(__len)					\
	struct MON_KEY_SIDLIST_NAME(__len) {				\
		struct in6_addr sids[(__len)];				\
	}

#define MON_DIR_MAP_SIDLIST_NAME(__dir, __len)				\
	__dir##_mon_map_sidlist_##__len

#define DECLARE_MON_MAP_SIDLIST(__dir, __len)				\
	struct bpf_elf_map SEC("maps")					\
		MON_DIR_MAP_SIDLIST_NAME(__dir,__len) = {		\
		.type = BPF_MAP_TYPE_PERCPU_HASH,			\
		.size_key = sizeof(struct MON_KEY_SIDLIST_NAME(__len)),	\
		.size_value = sizeof(struct color_stats),		\
		.pinning = PIN_GEN_NS,					\
		.max_elem = NUM_OF_FLOWS_PER_MAP_MAX,			\
	}

#define DECLARE_MON_MAPS_SIDLIST(__len)					\
	DEFINE_MON_KEY_SIDLIST(__len);					\
	DECLARE_MON_MAP_SIDLIST(ingress, __len);			\
	DECLARE_MON_MAP_SIDLIST(egress, __len)

DECLARE_MON_MAPS_SIDLIST(1);
DECLARE_MON_MAPS_SIDLIST(2);
DECLARE_MON_MAPS_SIDLIST(3);
DECLARE_MON_MAPS_SIDLIST(4);
DECLARE_MON_MAPS_SIDLIST(5);
DECLARE_MON_MAPS_SIDLIST(6);
DECLARE_MON_MAPS_SIDLIST(7);
DECLARE_MON_MAPS_SIDLIST(8);

static __always_inline void *
mon_map_sid_list_select(enum flow_dir fld, __u32 nsids)
{
#define __begin	switch (nsids) {

#define __cast(__dir, __v)						\
	case (__v):							\
		switch (__dir) {					\
		case FLOW_DIR_INGRESS:					\
			return &(MON_DIR_MAP_SIDLIST_NAME(ingress,	\
							  __v));	\
		case FLOW_DIR_EGRESS:					\
			return &(MON_DIR_MAP_SIDLIST_NAME(egress,	\
							  __v));	\
		default: return NULL;					\
		};							\
	break

#define __end(nsids) 							\
	default: return NULL;						\
	}

	__begin(nsids);
	__cast(fld, 1);
	__cast(fld, 2);
	__cast(fld, 3);
	__cast(fld, 4);
	__cast(fld, 5);
	__cast(fld, 6);
	__cast(fld, 7);
	__cast(fld, 8);
	__end(nsids);

#undef __begin
#undef __cast
#undef __end
	return NULL;
}

/* FIXME: changes are not atomic? SWITCH TO TYPE_HASH instead of TYPE_ARRAY */
/* map_color is used for setting the current color from the userspace */
struct bpf_elf_map SEC("maps") map_color = {
	.type = BPF_MAP_TYPE_ARRAY,
	.size_key = sizeof(__u32),
	.size_value = sizeof(__u32),
	.pinning = PIN_GEN_NS,
	.max_elem = 1,
};

static __always_inline __u8 ipv6_get_dsfield(const struct ipv6hdr *ip6h)
{
	return bpf_ntohs(*(const __be16 *)ip6h) >> 4;
}

static __always_inline
void ipv6_set_dsfield(struct ipv6hdr *const ip6h, __u8 mask, __u8 value)
{
	__be16 *p = (__be16 *)ip6h;

	/* A bit of explaination here, first 32 bits of an IPv6 packet:
	 * --------------------------------------------------------------------
	 * | Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits) |
	 * --------------------------------------------------------------------
	 *
	 * we need to write in the Traffic Class, so we have to shift (left)
	 * both mask and value of 4 bits. Then, we need to keep the 4 bits of
	 * version field and the first 4 bits of the Flow Label field. So, here
	 * we have the mask 0xf00f.
	 * At this point it is just a matter of doing the bit-bit AND between
	 * the previous value of *p (the overall first 16 bits of the packet)
	 * with the adjusted mask value. Therefore, we proceed to consider the
	 * dscp value (doing the bit-bit OR).
	 */
	*p = (*p & bpf_htons((((__u16)mask << 4) | 0xf00f))) |
	      bpf_htons((__u16)value << 4);
}

static __always_inline int get_active_color(__u32 *active_color)
{
	const __u32 index = 0;
	__u32 *cc;

	cc = bpf_map_lookup_elem(&map_color, &index);
	if (!cc)
		/* should never happen! */
		return -ENOENT;

	/* bpf_map_lookup_elem should read the *cc value atomically... */
	*active_color = *cc;

	return 0;
}

static __always_inline
int update_pcpu_color_stats(struct color_stats *pcpu_cstats, __u32 color)
{
	if (color >= NUM_OF_COLOR_MAX)
		return -EDOM;

	++pcpu_cstats->packets[color];

	return 0;
}

static __always_inline
int get_pcpu_color_stats(struct xdp_md *ctx, struct hdr_cursor *cur,
			 enum flow_dir fld, struct color_stats **cstats)
{
	struct color_stats *pcpu_cstats;
	struct ipv6_sr_hdr *sr6h;
	void *map_sid_list;
	void *key_sid_list;
	__u32 nsids;

	cur_touch(cur, ctx);

	sr6h = cur_header_pointer(cur, cur->thoff, sizeof(*sr6h));
	if (!sr6h)
		return -ENOBUFS;

	nsids = sr6h->first_segment + 1;

	map_sid_list = mon_map_sid_list_select(fld, nsids);
	if (!map_sid_list)
		return -ENOENT;

	sr6h = cur_header_pointer(cur, cur->thoff, sizeof(*sr6h) +
				  nsids * sizeof(struct in6_addr));
	if (!sr6h)
		return -ENOBUFS;

#define get_sid_list_ptr(__srh) (&((__srh)->segments[0]))
	key_sid_list = get_sid_list_ptr(sr6h);
#undef get_sid_list_ptr

	/* we retrieve the color_stats for the given sid_list */
	pcpu_cstats = bpf_map_lookup_elem(map_sid_list, key_sid_list);
	if (!pcpu_cstats)
		return -ENOENT;

	*cstats = pcpu_cstats;

	return 0;
}

static __always_inline
int update_srv6_pfplm_stats_on_ingress(struct xdp_md *ctx,
				       struct hdr_cursor *cur)
{
	struct color_stats *pcpu_stats;
	struct ipv6hdr *ip6h;
	__u32 color;
	int res;

	ip6h = cur_header_pointer(cur, cur->nhoff, sizeof(*ip6h));
	if (!ip6h)
		return -ENOBUFS;

	color = (__u32)((ipv6_get_dsfield(ip6h) &
				 DSCP_BITMASK_COLOR));

	res = get_pcpu_color_stats(ctx, cur, FLOW_DIR_INGRESS,
				   &pcpu_stats);
	if (res)
		return res;

	return update_pcpu_color_stats(pcpu_stats, color);
}

static __always_inline
int update_ipv6_and_srv6_pfplm_stats_on_egress(struct xdp_md *ctx,
					       struct hdr_cursor *cur)
{
	__u8 dscp_mask = 0xff & (~DSCP_BITMASK_COLOR);
	struct color_stats *pcpu_stats;
	struct ipv6hdr *ip6h;
	__u32 active_color;
	int res;

	if (get_active_color(&active_color))
		return -ENOENT;

	res = get_pcpu_color_stats(ctx, cur, FLOW_DIR_EGRESS, &pcpu_stats);
	if (res)
		return res;

	cur_touch(cur, ctx);

	ip6h = cur_header_pointer(cur, cur->nhoff, sizeof(*ip6h));
	if (!ip6h)
		return -ENOBUFS;

	/* at this point we have successfully retrieved the counters related to
	 * the sid list in the SRH. We can go on: 1) by setting the color in the
	 * dscp field of the ipv6 packet; 2) by updating the counters for the
	 * flow considering the active color.
	 */
	ipv6_set_dsfield((struct ipv6hdr *)ip6h, dscp_mask,
			 (__u8) active_color);

	return update_pcpu_color_stats(pcpu_stats, active_color);
}

static __always_inline int xdp_srv6_pfplm(struct xdp_md *ctx, enum flow_dir fld)
{
	struct ipv6_sr_hdr *sr6h;
	struct hdr_cursor *cur;
	struct ipv6hdr *ip6h;
	int proto = 0;

	cur = get_scratch_ptr();
	if (!cur)
		return -EINVAL;

	/* reset data to the network header */
	cur->dataoff = cur->nhoff;
	if (cur_update_pointers(cur, ctx) < 0)
		return -EINVAL;

	ip6h = cur_header_pointer(cur, cur->dataoff, sizeof(*ip6h));
	if (!ip6h)
		return -ENOBUFS;

	cur_pull(cur, sizeof(*ip6h));
	cur_reset_transport_header(cur);

	if (ip6h->nexthdr != IPPROTO_ROUTING)
		/* no Segment Routing Header as next protocol */
		return 0;

	/* parse the srv6 header */
	proto = parse_srv6hdr(cur, &sr6h);
	if (proto < 0)
		return proto;

	switch (fld) {
	case FLOW_DIR_INGRESS:
		update_srv6_pfplm_stats_on_ingress(ctx, cur);
		break;
	case FLOW_DIR_EGRESS:
		update_ipv6_and_srv6_pfplm_stats_on_egress(ctx, cur);
		break;
	default:
		goto out;
	};

out:
	/* for the moment we do not want to notify the outcome of the the
	 * coloring operation to the caller.
	 */
	return 0;
}

__section_tail(GEN_PROG_MAP_ID, UINSTR_OPCODE_PFPLM)
int xdp_srv6_pfplm_ingress_prog(struct xdp_md *ctx)
{
	enum flow_dir flow_dir = FLOW_DIR_UNSPEC;
	struct uprogram *uprog;
	__u8 opcode, flags;
	int rc;

	uprog = pcpu_uprog_ctx();
	if (!uprog)
		goto error;

	rc = uprog_fetch_current_instr(uprog, &opcode, &flags);
	if (rc < 0)
		goto error;

	flags = flags & UINSTR_OPERAND_PFPLM_MASK;

	if (flags & UINSTR_OPERAND_PFPLM_INGRESS)
		flow_dir = FLOW_DIR_INGRESS;
	else if (flags & UINSTR_OPERAND_PFPLM_EGRESS)
		flow_dir = FLOW_DIR_EGRESS;

	rc = xdp_srv6_pfplm(ctx, flow_dir);
	if (rc < 0)
		goto error;

	rc = bpf_tail_call_next_uprog(ctx, uprog);
	if (uprog_retcode_is_error(rc))
		goto error;

	return XDP_PASS;

error:
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
