
#ifndef _IPV6_GEN_PROG_H
#define _IPV6_GEN_PROG_H

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#define bpf_printk(fmt, ...)						\
({				 					\
	char ____fmt[] = fmt;						\
	bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);	\
})

#ifndef __stringify
#define __stringify(X)		#X
#endif

#ifndef __section
#define __section(NAME)					\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
#define __section_tail(ID, KEY)				\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

/* header cursor to keep track of current parsing position within the packet */
struct hdr_cursor {
	struct xdp_md *ctx;

	int dataoff;
	int mhoff;
	int nhoff;
	int thoff;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

#ifndef ipv6_optlen
#define ipv6_optlen(__srh)	(((__srh)->hdrlen + 1) << 3)
#endif

#define AF_INET			2
#define AF_INET6		10
#define IPv6_FLOWINFO_MASK	bpf_htonl(0x0FFFFFFF)

/* the maximum offset at which a generic protocol is considered to be valid
 * from the beginning (head) of the hdr_cursor.
 */
#define PROTO_OFF_MAX 0x7ff

static __always_inline void cur_reset_mac_header(struct hdr_cursor *cur)
{
	cur->mhoff = cur->dataoff;
}

static __always_inline void cur_reset_network_header(struct hdr_cursor *cur)
{
	cur->nhoff = cur->dataoff;
}

static __always_inline void cur_reset_transport_header(struct hdr_cursor *cur)
{
	cur->thoff = cur->dataoff;
}

static __always_inline void *cur_head(struct hdr_cursor *cur)
{
	return (void *)((long)cur->ctx->data);
}

static __always_inline void *cur_data(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->dataoff;
}

static __always_inline int cur_set_data(struct hdr_cursor *cur, int off)
{
	if (off < 0 || off > PROTO_OFF_MAX)
		return -EINVAL;

	cur->dataoff = off & PROTO_OFF_MAX;

	return 0;
}

static __always_inline void *cur_tail(struct hdr_cursor *cur)
{
	return (void *)((long)cur->ctx->data_end);
}

static __always_inline void *cur_mac_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->mhoff;
}

static __always_inline void *cur_network_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->nhoff;
}

static __always_inline void *cur_transport_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->thoff;
}

static __always_inline int
__cur_update(struct hdr_cursor *cur, struct xdp_md *ctx)
{
	cur->ctx = ctx;

	return 0;
}

#define cur_touch	__cur_update

static __always_inline void
cur_init(struct hdr_cursor *cur, struct xdp_md *ctx)
{
	__cur_update(cur, ctx);
	cur->dataoff = 0;
	cur_reset_mac_header(cur);
	cur_reset_network_header(cur);
	cur_reset_transport_header(cur);
}

static __always_inline int
__check_proto_offsets(struct hdr_cursor *cur)
{
	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		goto error;

	if (cur->mhoff < 0 || cur->mhoff > PROTO_OFF_MAX)
		goto error;

	if (cur->nhoff < 0 || cur->nhoff > PROTO_OFF_MAX)
		goto error;

	if (cur->thoff < 0 || cur->thoff > PROTO_OFF_MAX)
		goto error;

	return 0;

error:
	return -EINVAL;

}

static __always_inline int
cur_update_pointers(struct hdr_cursor *cur, struct xdp_md *ctx)
{
	int rc;

	rc =__cur_update(cur, ctx);
	if (rc < 0)
		return rc;

	return __check_proto_offsets(cur);
}

static __always_inline int
cur_adjust_proto_offsets(struct hdr_cursor *cur, int off)
{
	cur->dataoff += off;
	cur->mhoff += off;
	cur->nhoff += off;
	cur->thoff += off;

	return __check_proto_offsets(cur);
}

static __always_inline int
cur_update_pointers_after_head_expand(struct hdr_cursor *cur,
				      struct xdp_md *ctx, int head_off)
{
	int rc;

	rc = __cur_update(cur, ctx);
	if (rc < 0)
		return rc;

	return cur_adjust_proto_offsets(cur, head_off);
}

#define		__may_pull(__ptr, __len, __data_end)			\
			(((void *)(__ptr)) + (__len) <= (__data_end))

#define 	__may_pull_hdr(__hdr, __data_end)			\
			((__hdr) + 1 <= (__data_end))

#define 	__pull(__cur, __len)					\
			((__cur)->dataoff += (__len))

static __always_inline int cur_may_pull(struct hdr_cursor *cur, int len)
{
	void *tail;
	void *data;

	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		return 0;

	cur->dataoff &= PROTO_OFF_MAX;
	data = cur_data(cur);
	tail = cur_tail(cur);

	return __may_pull(data, len, tail);
}

static __always_inline void *cur_pull(struct hdr_cursor *cur, int len)
{
	if (!cur_may_pull(cur, len))
		return NULL;

	__pull(cur, len);

	return cur_data(cur);
}

static __always_inline void *
cur_header_pointer(struct hdr_cursor *cur, int off, int len)
{
	void *head = cur_head(cur);
	void *tail = cur_tail(cur);
	int __off = off + len;

	if (__off < 0 || __off > PROTO_OFF_MAX)
		goto error;

	/* to make the verifier happy... */
	len &= PROTO_OFF_MAX;
	off &= PROTO_OFF_MAX;

	/* overflow for the packet */
	if (!__may_pull(head + off, len, tail))
		goto error;

	return head + off;

error:
	return NULL;
}

static __always_inline void *cur_push(struct hdr_cursor *cur, int len)
{
	int off;

	if (len < 0)
		goto error;

	off = (cur->dataoff - len);
	if (off < 0)
		goto error;

	cur->dataoff = off & PROTO_OFF_MAX;
	if (!cur_may_pull(cur, len))
		goto error;

	return cur_data(cur);

error:
	return NULL;
}

/* we define the same structure used by ip/tc which differs * from the one
 * used by libppf.
 */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};

/* the code is compiled with some MANUAL optimization which does not seem to be
 * taken into account by the optimizer.
 */
#define __OPTIMIZED_CODE 		1

/* PIN ID for iproute2 (persistence of maps) */
#define PIN_GEN_NS			4

/* ID of the map used for storing the generic ebpf programs */
#define GEN_PROG_MAP_ID			1

/* uinstruction and uprogram definitions */
struct uinstr {
	__u8 opcode;
	__u8 operand;
};

/* UIP_MAX MUST ALWAYS be a power of 2 */
#define UIP_MAX				8
#define UIP_MASK			(8 -1)

/* 32 bytes long */
struct uprogram {
	struct uinstr uins[UIP_MAX];
	__u8 uip;
	__u8 reserved[3];
	__u32 regs[3];
};

#define UINSTR_OPCODE_UNSPEC		0x00

#define UINSTR_OPCODE_END 		0xff
#define UINSTR_OPERAND_END		0xff

#define UINSTR_OPCODE_SRH_ENCAP_ENCAP	1

#define UINSTR_OPCODE_IPv6_FWD_KERNEL	2
#define UINSTR_OPERAND_IPv6_FWD_DIRECT	(BPF_FIB_LOOKUP_DIRECT)
#define UINSTR_OPERAND_IPv6_FWD_OUTPUT	(BPF_FIB_LOOKUP_OUTPUT)
#define UINSTR_OPERAND_IPv6_FWD_KERNEL	(BIT(2))

#define UINSTR_OPERAND_IPv6_FWD_OPERAND_MASK 	\
	(UINSTR_OPERAND_IPv6_FWD_DIRECT |	\
	 UINSTR_OPERAND_IPv6_FWD_OUTPUT |	\
	 UINSTR_OPERAND_IPv6_FWD_KERNEL)

#define UINSTR_OPCODE_PFPLM		3
#define UINSTR_OPERAND_PFPLM_INGRESS	BIT(0)
#define UINSTR_OPERAND_PFPLM_EGRESS	BIT(1)
#define UINSTR_OPERAND_PFPLM_MASK	\
	(UINSTR_OPERAND_PFPLM_INGRESS | \
	 UINSTR_OPERAND_PFPLM_EGRESS)

#define UINSTR_OPCODE_IPv6_RT_RAW		4
#define UINSTR_OPERAND_IPv6_RT_RAW_STRICT	BIT(0)
#define UINSTR_OPERAND_IPv6_RT_RAW_KERN_PASS	BIT(1)
#define UINSTR_OPERAND_IPv6_RT_RAW_MASK		\
	(UINSTR_OPERAND_IPv6_RT_RAW_STRICT |	\
	 UINSTR_OPERAND_IPv6_RT_RAW_KERN_PASS)


#define UINSTR_OPCODE_NOP		144 /* 0x90 in hex */

/* the total number of different programs that can be used */
#define GEN_PROG_TABLE_SIZE		256

/* the total number of entries in the SRH_ENCAPS tables */
#define SRH_ENCAP_SIDLIST_TABLE_SIZE	64

/* IPv6 SRH  Encap programs */
#define IPv6_SRH_ENCAP_SIDLIST_MAX	8

#define SRH_ENCAP_HOP_LIMIT		64

/* ~~~~~~~~~~~~~~~~~~ Packet Loss Monitoring Program ~~~~~~~~~~~~~~~~~~~~~~~~ */

/* It MUST be always a power of 2 */
#define NUM_OF_COLOR_MAX 	4
#define DSCP_BITMASK_COLOR	((__u8)(NUM_OF_COLOR_MAX - 1))

/* Number of flows per table */
#define NUM_OF_FLOWS_PER_MAP_MAX 256

enum flow_dir {
	FLOW_DIR_UNSPEC		= 0,
	FLOW_DIR_INGRESS	= 1,
	FLOW_DIR_EGRESS		= 2,
	__FLOW_DIR_MAX		= 3,
};

#define FLOW_DIR_MAX 	(__FLOW_DIR_MAX - 1)

struct color_stats {
	__u64 packets[NUM_OF_COLOR_MAX];
};

/* ~~~~~~~~~~~~~ Routing and Forwarding RAW (no kernel support) ~~~~~~~~~~~~~ */

#define FIB6_INFO_TABLE_SIZE 64

/* TODO: put some checks for warning if the alignements are not met.
 * note: keep always this structure aligned to 16 byte, dst and src MUST BE
 * contiguous !!!
 */
struct fib6_info {
	/*  key is the IPv6 address */

	/* next hop info. */
	unsigned char dst[ETH_ALEN];
	unsigned char src[ETH_ALEN];

	/* forwarding device */
	__u32 ifindex;
};

#endif
