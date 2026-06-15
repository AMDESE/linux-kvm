// SPDX-License-Identifier: GPL-2.0-only
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stddef.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1ULL << PAGE_SHIFT)
const u64 PAGE_MASK = ~(PAGE_SIZE - 1);
const u64 PAGE_SIZE_u64 = PAGE_SIZE / sizeof(u64);
#define ARRAY_SIZE(x)	(sizeof(x)/sizeof((x)[0]))

#define RMPTABLE_CPU_BOOKKEEPING_SZ	0x4000

struct {
	int fd; /* /dev/mem */
	u64 dteoff;
	u64 rmptable;
	union {
		u64 cfg; /* 0xc0010136 (RMP_CFG) */
		struct {
			u64 segmented:1;
			u64 res1:7;
			u64 shift:6; /* Size of covered memory */
			u64 res2:50;
		};
	} rmp;
	int verbose;
	int color;
	int pteoffset;
	u64 start; // pfn
	u64 end; // pfn
	u64 rmpend; // pfn
	u64 swiotlb_start; // pfn
	u64 swiotlb_end; // pfn
} g = {
	.end = 1ULL << (64 - PAGE_SHIFT),
};

static int print_addr(u64 pa)
{
	u64 pfn = pa >> PAGE_SHIFT;
	return g.start <= pfn && pfn < g.end;
}

static char *pr16color(char *b, u16 val, int leading0, int skip, int color)
{
	if (skip)
		return b;

	/* Highlight the middle 4 digits for easier reading but it requires "less -R" */
#define BOLD_ON "\033[1m"
#define BOLD_OFF "\033[0m"
	if (color) {
		strcat(b, BOLD_ON);
		b += strlen(b);
	}

	if (leading0)
		sprintf(b, "%04hx", val);
	else
		sprintf(b, "%4hx", val);
	b += strlen(b);

	if (color) {
		strcat(b, BOLD_OFF);
		b += strlen(b);
	}

	return b;
}

static const char *__praddr(char *b, size_t len, int align, u64 addr)
{
	const char *ret = b;
	u16 *v = (u16 *) &addr;

	if (len < 64)
		return "BUFOVERRUN";

	b[0] = 0;
	b = pr16color(b, v[3], 0, !v[3], g.color);
	b = pr16color(b, v[2], !!v[3], !v[3] && !v[2], 0);
	b = pr16color(b, v[1], !!v[3] || !!v[2], !v[3] && !v[2] && !v[1], g.color);
	b = pr16color(b, v[0], !!v[3] || !!v[2] || !!v[1], 0, 0);

	return ret;
}
#define praddr(b, addr) __praddr((b), sizeof(b), 1, (addr))

static ssize_t pgread(int fd, off_t off, void *pg, ssize_t cb)
{
	off_t o1 = lseek(fd, off, SEEK_SET);
	if (o1 < 0)
		return o1;

	return read(fd, pg, cb);
}

typedef union  {
	struct { u64 lo, hi; };
	struct {
		u64 assigned:1;
		u64 page_size:1; /* 0=4k 1=2M */
		u64 immutable:1;
		u64 subpage_count:9;
		u64 gfn:39;
		u64 guest_asid:10;
		u64 VMSA:1;
		u64 validated:1;
		u64 lock:1;
		union {
			struct {
				u8 vpw:1;
				u8 pw:1;
				u8 sss:1;
				u8 execute_supervisor:1;
				u8 execute_user_:1;
				u8 write:1;
				u8 read:1;
				u8 reserved1:1;
			};
			u8 r;
		}vmpl[4];
		u32 reserved2:1;
		u32 not_dirty:1;
		u32 page_state_lock:1;
		u32 reserved3:12;
		u32 mmio:1;
		u32 rootportid:6;
		u32 ide_stream_ide:8;
		u32 page_migration:2;
	};
} rmpentry;

static u64 rmp_segments[PAGE_SIZE];	/* When segmented RMP enabled, here is the table */
static int rmp_segments_initialized = 0;

static int rmp_seg_init(void)
{
	int i, r;

	r = pgread(g.fd, g.rmptable + RMPTABLE_CPU_BOOKKEEPING_SZ, rmp_segments, PAGE_SIZE);
	if (r < 0)
		return r;

	if (g.verbose > 1)
		printf("Segmented RMP, %ldGB segments (shift=%d)\n",
		       1UL << (g.rmp.shift - 30), g.rmp.shift);

	for (i = 0; i < ARRAY_SIZE(rmp_segments); ++i) {
		if (!rmp_segments[i])
			continue;

#define RMPSEGADDRMASK	0xffffffff00000ULL
#define RMPSEGSHIFTMASK 0x00000000fffffULL
		u64 start = (u64) i << g.rmp.shift;
		u64 seg = rmp_segments[i] & RMPSEGADDRMASK;
		u64 size = rmp_segments[i] & RMPSEGSHIFTMASK;

#define max(a, b) (((a) > (b)) ? (a) : (b))
		g.rmpend = max(g.rmpend, start + (size << (30 - PAGE_SHIFT)));

		if (g.verbose > 1)
			printf("Rmpseg#%d: %016llx..%016llx %lldGB @0x%llx\n",
			       i, start, start + (size << 30) - 1, size, seg);
	}

	return 0;
}

static int rmpread(u64 pfn, rmpentry *e, unsigned *seg, u64 *ep)
{
	/* RMP table is in reserved memory and __ioremap_caller is called a lot so cache it */
	static struct {
		u8 *pg;
		unsigned long n;
		u64 off;
	} cache[16] = {};
	ssize_t r;
	u64 entryoff, pgoff, segno = 0;
	unsigned long minn;
	int i, ff;

	if (g.rmp.segmented) {
		segno = pfn >> (g.rmp.shift - 12);
		if (segno > ARRAY_SIZE(rmp_segments) || !rmp_segments[segno])
			return -ERANGE;

		pfn &= (1ULL << (g.rmp.shift - 12)) - 1;
		entryoff = (rmp_segments[segno] & RMPSEGADDRMASK) + pfn * sizeof(*e);
		pgoff = entryoff & PAGE_MASK;
	} else {
		entryoff = g.rmptable + RMPTABLE_CPU_BOOKKEEPING_SZ + pfn * sizeof(*e);
		pgoff = entryoff & PAGE_MASK;
	}

	for (i = 0, ff = 0, minn = cache[0].n; i < ARRAY_SIZE(cache); ++i) {
		if (pgoff == cache[i].off) {
			++cache[i].n;
			goto copy_exit;
		}
		if (cache[i].n < minn) {
			minn = cache[i].n;
			ff = i;
		}
	}

	/* We are here so it is cache miss, evict the least popular */
	i = ff;
	if (cache[i].pg)
		free(cache[i].pg);
	cache[i].pg = malloc(PAGE_SIZE);
	cache[i].off = pgoff;
	cache[i].n = 1;

	r = pgread(g.fd, pgoff, cache[i].pg, PAGE_SIZE);
	if (r < 0)
		return r;
	if (r != PAGE_SIZE)
		return -EIO;

copy_exit:
	memcpy(e, cache[i].pg + (entryoff & ~PAGE_MASK), sizeof(*e));
	if (seg)
		*seg = segno;
	if (ep)
		*ep = cache[i].off + (entryoff & ~PAGE_MASK);
	return 0;
}

static const char *rmp(char *b, u64 pfn)
{
	unsigned segno = 0;
	rmpentry e = {};
	u64 ep = 0;
	char ba[64];
	int r, i;

	if (!g.rmptable)
		return "";

	r = rmpread(pfn, &e, &segno, &ep);
	if (r < 0)
		return " !RMPERROR";

	if (!e.hi && !e.lo)
		return " / rmp=0";

	sprintf(b, " / RMP#%d:%s %s asid%d %s%s%s%s%s%s%s%s%s%s",
		segno,
		__praddr(ba, sizeof(ba), 0, (u64)e.gfn << PAGE_SHIFT),
		e.page_size ? "2M" : "4K",
		e.guest_asid,
#define RMPF(f, n)	(e.f ? n : "")
		RMPF(validated, "V"),
		RMPF(immutable, "I"),
		RMPF(assigned, "A"),
		RMPF(lock, "L"),
		RMPF(mmio, "M"),
		RMPF(VMSA, "VMSA"),
		RMPF(reserved2, ":2"),
		RMPF(not_dirty, "[ND]"),
		RMPF(page_state_lock, "[PSL]"),
		RMPF(reserved3, ":3"));

	if (e.page_migration)
		sprintf(b + strlen(b), " PM%d", e.page_migration);

	if (e.mmio || e.ide_stream_ide || e.rootportid)
		sprintf(b + strlen(b), " ide%d,rp%d", e.ide_stream_ide, e.rootportid);

	if (e.subpage_count)
		sprintf(b + strlen(b), " sub#=%d", e.subpage_count);

	for (i = 0; i < ARRAY_SIZE(e.vmpl); ++i) {
		if (!e.vmpl[i].r)
			continue;
		sprintf(b + strlen(b), " VMPL%d=%s%s%s%s%s%s%s%s", i,
#define RMPV(i, f, v)	(e.vmpl[i].f ? v : "")
			RMPV(i, vpw, "V"),
			RMPV(i, pw, "P"),
			RMPV(i, sss, "S"),
			RMPV(i, execute_supervisor, "s"),
			RMPV(i, execute_user_, "u"),
			RMPV(i, write, "w"),
			RMPV(i, read, "r"),
			RMPV(i, reserved1, ":1")
			);
	}

	if (g.pteoffset)
		sprintf(b + strlen(b), " rmp@%llx", ep);

	return b;
}

static int dump_rmp(u64 start, u64 end)
{
	char buf[128], ba[64];

	for (u64 pfn = start; pfn < end; ++pfn) {
		const char *a = praddr(ba, pfn << PAGE_SHIFT), *r;
		rmpentry e = {};

		if (!a || rmpread(pfn, &e, NULL, NULL))
			break;

		if (!g.verbose && !e.lo && !e.hi)
			continue;

		r = rmp(buf, pfn);
		if (!r)
			break;
		printf(" %s\t%s\n", a, r);
	}

	return 0;
}

static const char *pteoffset(char *b, u64 pfn, int i, size_t entry)
{
	if (!g.pteoffset)
		return "";
	sprintf(b, " pte@%llx", (pfn << PAGE_SHIFT) + i * entry);
	return b;
}

static const char *swiotlb(u64 addr)
{
	u64 pfn = addr >> PAGE_SHIFT;

	if (g.swiotlb_start <= pfn && pfn < g.swiotlb_end)
		return " SWIOTLB";

	return "";
}

static const char *pci_name(char *b, unsigned n)
{
	sprintf(b, "%02x:%02x.%d", n >> 8, (n & 0xF8) >> 3, n & 7);
	return b;
}

typedef union {
	struct /* PTE */ {
		u64 present:1;
		u64 rw:1;
		u64 us:1;
		u64 pwt:1;
		u64 pcd:1;
		u64 a:1;
		u64 d:1;
		u64 pat:1; /* 1 for PDEs */
		u64 g:1;
		u64 avl:3;
		u64 phys_addr:39; /* or the bottom bit of this one */
		u64 c:1; /* C-bit */
		u64 res:7;
		u64 pke:4;
		u64 nx:1;
	};
	struct {
		u64 a1:12;
		u64 pfn:39;
		u64 a2:13;
	};
	u64 pte;
} pte_t;

static const char *pr_pte_flags(char *buf, pte_t pte, int lvl)
{
	sprintf(buf, " %s%s%s%s%s%s%s%s%s%s (%x %x)",
#define PTEFL(b, n)	((pte.b)? n : "")
#define PTEFL_(b, y, n)	((pte.b)? y : n)
		PTEFL(c, "C"),
		PTEFL(nx, "N"),
		PTEFL(g, "G"),
		PTEFL(d, "D"),
		PTEFL(a, "A"),
		PTEFL_(us, "U", "s"), // set: User
		PTEFL_(rw, "W", "r"), // set: Write
		PTEFL(pcd, " PCD"),
		PTEFL(pwt, " PWT"),
		(lvl && (pte.phys_addr & 1)) ? " PAT+":PTEFL(pat, " PAT"),
		(u32)pte.a2,
		(u32)pte.a1);
	return buf;
}

static const char *pr_pde_flags(char *buf, pte_t pte)
{
	sprintf(buf, " %s%s%s%s%s%s%s%s (%x %x)",
		PTEFL(c, "C"),
		PTEFL(nx, "N"),
		//PTEFL(g, "G"),
		//PTEFL(d, "D"),
		PTEFL(a, "A"),
		PTEFL_(us, "U", "s"), // set: User
		PTEFL_(rw, "W", "r"), // set: Write
		PTEFL(pcd, " PCD"),
		PTEFL(pwt, " PWT"),
		(pte.phys_addr & 1) ? " PAT":"",
		(u32)pte.a2,
		(u32)pte.a1);
	return buf;
}

static int dump_ptes(u64 pfn, unsigned tabs, const char *pgsz, u64 addr, u64 *ptes)
{
	pte_t p[PAGE_SIZE_u64];
	u64 lvlpgsz = PAGE_SIZE;
	ssize_t r = pgread(g.fd, pfn << PAGE_SHIFT, p, sizeof(p));
	const char ttt[] = "\t\t\t\t\t\t\t";
	const char *ind = ttt + sizeof(ttt) - tabs - 1;
	char buf[128], ba[64], bo[32], bp[32];
	int ret, first, i;

	if (r < 0)
		return r;

	first = 0;
	for (i = 1; i <= ARRAY_SIZE(p); ++i) {
		if (i == ARRAY_SIZE(p)) {
			// last iteration
		} else if ((p[i].a1 == p[first].a1) &&
			   (p[i].a2 == p[first].a2) &&
			   (p[i].pfn - p[i - 1].pfn == 1)) {
			if (g.verbose < 1)
				continue;
		}

		if (p[first].present) {
			if (print_addr(addr + first * lvlpgsz))
				printf(" %s%s\t%d: %llx %d*%s%s%s%s%s\n",
				       praddr(ba, addr + first * lvlpgsz),
				       ind,
				       first,
				       (u64)p[first].pfn,
				       i - first,
				       pgsz,
				       pr_pte_flags(bp, p[first], 0),
				       swiotlb(addr + first * lvlpgsz),
				       rmp(buf, p[first].pfn),
				       pteoffset(bo, pfn, first, sizeof(p[0]))
				      );
			*ptes += i - first;
		}
		first = i;
	}

	return 0;
}

static int dump_pdes(u64 pfn, unsigned lvl, unsigned tabs, u64 addr, u64 *ptes)
{
	pte_t p[PAGE_SIZE_u64];
	u64 lvlpgsz = 1ULL << ((lvl*9) + 12);
	ssize_t r = pgread(g.fd, pfn << PAGE_SHIFT, p, sizeof(p));
	const char ttt[] = "\t\t\t\t\t\t\t";
	const char *ind = ttt + sizeof(ttt) - tabs - 1;
	const char *fmt[] = { "", "", "1G", "2M", "4K" };
	char buf[128], ba[64], bo[32], bp[32];
	int ret, hugepage;

	if (r < 0)
		return r;

	for (unsigned i = 0; i < ARRAY_SIZE(p); ++i, addr += lvlpgsz) {
		if (!p[i].present)
			continue;

		hugepage = lvl && p[i].pat;
		if ((g.verbose > 1 || hugepage) && print_addr(addr))
			printf(">%s%s\t%d: %llx %s%s%s%s%s%s\n",
			       praddr(ba, addr),
			       ind,
			       i,
			       (u64)p[i].pfn,
			       fmt[ARRAY_SIZE(fmt) - lvl - 1],
			       hugepage ? " HUGE" : "",
			       hugepage ? pr_pte_flags(bp, p[i], lvl) : pr_pde_flags(bp, p[i]),
			       swiotlb(addr),
			       hugepage ? rmp(buf, p[i].pfn) : "",
			       pteoffset(bo, pfn, i, sizeof(p[0]))
			      );

		if (hugepage) {
			*ptes += 1ULL << (lvl * 9);
			continue;
		}

		if (lvl - 1)
			ret = dump_pdes(p[i].pfn, lvl - 1, tabs + 1, addr, ptes);
		else
			ret = dump_ptes(p[i].pfn, tabs + 1,
					fmt[ARRAY_SIZE(fmt) - lvl], addr, ptes);
		if (ret)
			return ret;
	}

	return 0;
}

typedef union {
	struct {
		u64 present:1;
		u64 ign:4;
		u64 a:1;
		u64 d:1;
		u64 ign2:2;
		u64 nextlevel:3;
		u64 phys_addr:39;
		u64 c:1; // part of phys_addr
		u64 res:7;
		u64 u:1;
		u64 fc:1; // Force Coherent
		u64 ir:1;
		u64 iw:1;
		u64 ign3:1;
	};
	struct {
		u64 a1:12;
		u64 pfn:39;
		u64 a2:13;
	};
	u64 pte;
} iopte_t;

static int dump_ioptes(u64 pfn, unsigned tabs, const char *pgszs, u64 addr, u64 *ptes)
{
	iopte_t p[PAGE_SIZE_u64];
	u64 lvlpgsz = PAGE_SIZE;
	ssize_t r = pgread(g.fd, pfn << PAGE_SHIFT, p, sizeof(p));
	const char ttt[] = "\t\t\t\t\t\t\t";
	const char *ind = ttt + sizeof(ttt) - tabs - 1;
	unsigned long pgsz = lvlpgsz;
	int ret, first, i;
	char buf[128], ba[64], bo[32];

	if (r < 0)
		return r;

	first = 0;
	for (i = 1 /* not zero intentionally */; i <= ARRAY_SIZE(p); ++i) {
		u64 pfn1;

		if (i == ARRAY_SIZE(p)) {
			// last iteration
		} else if ((p[i].a1 == p[first].a1) &&
			   (p[i].a2 == p[first].a2) &&
			   (p[i].pfn - p[i - 1].pfn == 1)) {
			if (g.verbose < 1)
				continue;
		}

		if (p[first].nextlevel == 7) {
			/* v1 huge page coding: the first zero bit in pfn is page shift */
			unsigned firstzero = ffsl(~(unsigned long)p[first].pfn);

			pgsz = 1ULL << (firstzero + 12);
			/* Mask out pagesize encoding from pfn */
			pfn1 = (u64)p[first].pfn & ~((1UL<<(firstzero + 1)) - 1);

			i += pgsz/lvlpgsz - 1;
		} else {
			pfn1 = p[first].pfn;
		}

		if (p[first].present) {
			if (print_addr(addr + first * lvlpgsz)) {
			    printf(" %s%s\t%d: %llx %d*%s %s%s%s%s%s%s%s%s (%x %x)",
				   praddr(ba, addr + first * lvlpgsz),
				   ind,
				   first,
				   pfn1,
				   i - first,
				   pgszs,
#define IOPTEFL(b, n)	((p[first].b)? n : "")
				   IOPTEFL(c, "C"),
				   IOPTEFL(d, "D"),
				   IOPTEFL(a, "A"),
				   IOPTEFL(u, "U"),
				   IOPTEFL(ir, " IR"),
				   IOPTEFL(iw, " IW"),
				   IOPTEFL(fc, " FC"),
				   swiotlb(addr + first * lvlpgsz),
				   (u32)p[first].a2,
				   (u32)p[first].a1);

			    if (pgsz != lvlpgsz)
			    printf(" %ld", pgsz);
			    else
			    printf(" %s", pgszs);
			    printf("%s%s\n", rmp(buf, p[first].pfn),
				   pteoffset(bo, pfn, i, sizeof(p[0])));
			}

			*ptes += i - first;
		}
		first = i;
	}

	return 0;
}

static int dump_iopdes(u64 pfn, unsigned lvl, unsigned tabs, u64 addr, u64 *ptes)
{
	iopte_t p[PAGE_SIZE_u64];
	u64 lvlpgsz = 1ULL << ((lvl*9) + 12);
	ssize_t r = pgread(g.fd, pfn << PAGE_SHIFT, p, sizeof(p));
	const char ttt[] = "\t\t\t\t\t\t\t";
	const char *ind = ttt + sizeof(ttt) - tabs - 1;
	unsigned long pgsz = lvlpgsz;
	const char *fmt[] = { "", "", "1G", "2M", "4K" };
	char buf[128], ba[64], bo[32];
	int ret;

	if (r < 0)
		return r;

	for (unsigned i = 0; i < ARRAY_SIZE(p); ++i, addr += lvlpgsz) {
		u64 pfn1;
		int hugepage = (p[i].nextlevel == 0 || p[i].nextlevel == 7);

		if (!p[i].present && g.verbose < 2)
			continue;

		if (p[i].nextlevel == 7) {
			/* v1 huge page coding: the first zero bit in pfn is page shift */
			unsigned firstzero = ffsl(~(unsigned long)p[i].pfn);

			pgsz = 1ULL << (firstzero + 12);
			/* Mask out pagesize encoding from pfn */
			pfn1 = (u64)p[i].pfn & ~((1UL<<(firstzero + 1)) - 1);
		} else {
			pfn1 = p[i].pfn;
		}

		if ((g.verbose > 1 || hugepage) && print_addr(addr)) {
			printf(">%s%s\t%d: %llx %s%s%s%s (%x %x) nxt=%d",
			       praddr(ba, addr),
			       ind,
			       i,
			       pfn1,
#define IOPDEFL(b, n)	((p[i].b)? n : "")
			       IOPDEFL(ir, " IR"),
			       IOPDEFL(iw, " IW"),
			       IOPDEFL(fc, " FC!"), /* marked as reverved in spec */
			       swiotlb(addr),
			       (u32)p[i].a2,
			       (u32)p[i].a1,
			       p[i].nextlevel);

			if (pgsz != lvlpgsz)
				printf(" %ld", pgsz);
			else
				printf(" %s", fmt[ARRAY_SIZE(fmt) - lvl - 1]);

			printf("%s%s\n", rmp(buf, p[i].pfn),
			       pteoffset(bo, pfn, i, sizeof(p[0])));
		}

		if (hugepage) {
			*ptes += 1ULL << (lvl * 9);
			continue;
		}

		if (lvl - 1)
			ret = dump_iopdes(p[i].pfn, lvl - 1, tabs + 1, addr, ptes);
		else
			ret = dump_ioptes(p[i].pfn, tabs + 1,
					  fmt[ARRAY_SIZE(fmt) - lvl], addr, ptes);
		if (ret)
			return ret;
	}

	return 0;
}

typedef union {
	struct {
		u64 v:1;
		u64 tv:1;
		u64 res:2;
		u64 cxlio:3;
		u64 had:2;
		u64 mode:3;
		u64 host_ptr:39;
		u64 c:1;
		u64 ppr:1;
		u64 gprp:1;
		u64 giov:1;
		u64 gv:1;
		u64 glx:2;
		u64 gcr3_trp_14_12:3;
		u64 ir:1;
		u64 iw:1;
		u64 res2:1;
		u64 domainid:16;
		u64 gcr3_trp_30_15:16;
		u64 i:1;
		u64 se:1;
		u64 sa:1;
		u64 ioctl:2;
		u64 cache:1;
		u64 sd:1;
		u64 ex:1;
		u64 sysmgt:1;
		u64 sats:1;
		u64 gcr3_trp_51_31:21;
		u64 iv:1;
		u64 inttablen:4;
		u64 ig:1;
		u64 intr_tbl:46;
		u64 res3:2;
		u64 guest_paging_mode:2;
		u64 initpass:1;
		u64 elntpass:1;
		u64 nmipass:1;
		u64 hptmode:1;
		u64 intctl:2;
		u64 lint0pass:1;
		u64 lint1pass:1;
		u64 res4:15;
		u64 vlmuen:1;
		u64 gdeviceid:32;
		u64 res5:6;
		u64 attrv:1;
		u64 mode0fc:1;
		u64 snoop:8;
	};
	u64 w[4];
} dte_t;

static int dump_iommu_table(unsigned devid)
{
	u64 ptes = 0;
	dte_t dte;
	int ret;
	ssize_t r = pgread(g.fd, g.dteoff + sizeof(dte) * devid, &dte, sizeof(dte));

	if (r < 0)
		return r;

	if (!dte.tv || !dte.v || dte.gv)
		return -1;

	ret = dump_iopdes(dte.host_ptr, dte.mode - 1, 0, 0, &ptes);
	if (g.verbose > 1)
		printf("PTES = %lld=%lldMB, %d levels\n",
		       ptes, ptes >> (20 - PAGE_SHIFT), dte.mode);

	return ret;
}

static int dump_dte(void)
{
	dte_t dte[0x10000];
	char tmp[32];
	ssize_t r = pgread(g.fd, g.dteoff, dte, sizeof(dte));
	const char *modes[8] = {
		"0 Translation disabled",
		"1 Levels 21-bit",
		"2 Levels 30-bit",
		"3 Levels 39-bit",
		"4 Levels 48-bit",
		"5 Levels 57-bit",
		"6 Levels 64-bit",
		"Reserved" };

	if (r < 0)
		return r;

	for (int i = 0; i < ARRAY_SIZE(dte); ++i) {
		if (!dte[i].tv || !dte[i].v)
			continue;

#define FL(x) ((dte[i].x)?'+':'-')
		printf("%s: h=%llx mode=%d \"%s\" ir%c iw%c gv%c C%c\n",
			pci_name(tmp, i), ((u64)dte[i].host_ptr)<<PAGE_SHIFT,
			dte[i].mode, modes[dte[i].mode],
			FL(ir), FL(iw), FL(gv), FL(c));
	}

	return 0;
}

static int pr_exit(int opt, const char *optarg)
{
	fprintf(stderr, "Invalid option %c: %s\n", opt, optarg);
	return -EINVAL;
}

static ssize_t read_u64(const char *fn, u64 *value)
{
	FILE *fp = fopen(fn, "r");
	u64 temp;

	if (fp == NULL) {
		//printf("fopen %s failed\n", fn);
		return -1;
	}
	if (fscanf(fp, "%llx", &temp) != 1) {
		fclose(fp);
		errno = EINVAL;
		return -1;
	}
	fclose(fp);
	*value = temp;
	if (g.verbose > 0)
		printf("%s => 0x%llx (%lld)\n", fn, temp, temp);

	return 0;
}

int main(int argc, char *argv[])
{
	u64 qemupt = 0, nptpt = 0, start = 0, size = 0, lvl = 5;
	unsigned dom = 0, bus, dev, fn = 0xFF;
	int ret, opt;
	struct { int fd, rmp, swiotlb, pt, lvl, dte; } autop = { 1, 1, 1, 0, 1, 0 };

	g.color = isatty(1);

	while ((opt = getopt(argc, argv, "l:d:f:p:q:n:r:R:s:S:t:T:vchP")) != -1) {
		switch (opt) {
		case 'f':
			g.fd = open(optarg, O_RDONLY | O_SYNC);
			if (g.fd < 0)
				return pr_exit(opt, optarg);
			autop.fd = 0;
			break;
		case 'l':
			if (strcmp(optarg, "auto")) {
				lvl = strtoul(optarg, NULL, 10);
				autop.lvl = 0;
			}
			break;
		case 'd':
			if (strcmp(optarg, "auto"))
				g.dteoff = strtol(optarg, NULL, 16);
			else
				autop.dte = 1;
			break;
		case 'p':
			ret = sscanf(optarg, "%x:%x.%d", &bus, &dev, &fn);
			if (ret != 3) {
				ret = sscanf(optarg, "%x:%x:%x.%d", &dom, &bus, &dev, &fn);
				if (ret != 4)
					return pr_exit(opt, optarg);
			}
			autop.dte = 1;
			break;
		case 'q':
			if (strcmp(optarg, "kernel"))
				qemupt = strtol(optarg, NULL, 16);
			else
				autop.pt = 1;
			break;
		case 'n':
			// atm not different from -q
			nptpt = strtol(optarg, NULL, 16);
			if (!nptpt)
				return pr_exit(opt, optarg);
			break;
		case 'R':
			if (strcmp(optarg, "auto")) {
				g.rmp.cfg = strtol(optarg, NULL, 16);
				autop.rmp = 0;
			}
			break;
		case 'r':
			if (strcmp(optarg, "auto")) {
				g.rmptable = strtol(optarg, NULL, 16);
				autop.rmp = 0;
			}
			break;
		case 'v':
			++g.verbose;
			break;
		case 'c':
			g.color = 1;
			printf("For nicer less, do: | less -R\n");
			break;
		case 'P':
			g.pteoffset = 1;
			break;
		case 's':
			start = strtol(optarg, NULL, 16);
			break;
		case 'S':
			size = strtol(optarg, NULL, 16);
			break;
		case 't':
			if (strcmp(optarg, "auto")) {
				g.swiotlb_start = strtol(optarg, NULL, 16) >> PAGE_SHIFT;
				autop.swiotlb = 0;
			}
			break;
		case 'T':
			if (strcmp(optarg, "auto")) {
				g.swiotlb_end = strtol(optarg, NULL, 16) >> PAGE_SHIFT;
				autop.swiotlb = 0;
			}
			break;
		case 'h':
		default: /* '?' */
			fprintf(stderr, "Usage: %s [-f /dev/mem] [-d [dteaddr|auto] [-p BB:DD.Fn]] "
				"[-q qemuptaddr|kernel] [-n npt] [-l levels] [-r rmptable] [-R rmpcfg] "
				"[-vcP] [-s start] [-S size] [-t swiotlb_start] [-T swiotlb_end]\n"
				"-P for ptes",
				argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (autop.fd) {
		g.fd = open("/dev/mem", O_RDONLY | O_SYNC);
		if (g.fd < 0)
			return pr_exit('f', "/dev/mem");
	}
	if (autop.lvl)
		read_u64("/sys/kernel/debug/page_tables/kernel_pt_levels", &lvl);
	if (autop.rmp) {
		read_u64("/sys/kernel/debug/page_tables/rmpcfg", &g.rmp.cfg);
		read_u64("/sys/kernel/debug/page_tables/rmptable", &g.rmptable);
		if (g.rmptable && g.rmp.segmented) {
			ret = rmp_seg_init();
			if (ret)
				return ret;
		}
	}
	if (autop.swiotlb) {
		read_u64("/sys/kernel/debug/swiotlb/start", &g.swiotlb_start);
		read_u64("/sys/kernel/debug/swiotlb/end", &g.swiotlb_end);
	}
	if (autop.pt)
		read_u64("/sys/kernel/debug/page_tables/kernel_pt", &qemupt);
	if (autop.dte)
		read_u64("/sys/devices/pci0000:00/0000:00:00.2/iommu/ivhd2/amd-iommu/dte", &g.dteoff);

	if (start)
		g.start = start >> PAGE_SHIFT;
	if (size)
		g.end = (start + size) >> PAGE_SHIFT;

	if (g.verbose > 0) {
		printf("%lld levels, RMP %llx @%llx, SWIOTLB %llx..%llx DTE @%llx PT=%llx %llx\n",
		       lvl, g.rmp.cfg, g.rmptable, g.swiotlb_start, g.swiotlb_end, g.dteoff,
		       qemupt, nptpt);
		if (g.start)
			printf("Range: %llx..%llx (%lld pages)\n",
			       g.start << PAGE_SHIFT, (g.end << PAGE_SHIFT) - 1, g.end + 1 - g.start);
	}

	if (g.dteoff) {
		if (fn < 8)
			ret = dump_iommu_table((bus << 8) | (dev << 3) | fn);
		else
			ret = dump_dte();
	}

	if (qemupt) {
		u64 ptes = 0;
		ret = dump_pdes(qemupt >> PAGE_SHIFT, lvl - 1, 0, 0, &ptes);
		if (g.verbose > 1)
			printf("PTES = %lld=%lldMB\n", ptes, ptes >> (20 - PAGE_SHIFT));
	}

	if (nptpt) {
		u64 ptes = 0;
		ret = dump_pdes(nptpt >> PAGE_SHIFT, lvl - 1, 0, 0, &ptes);
		if (g.verbose > 1)
			printf("PTES = %lld=%lldMB\n", ptes, ptes >> (20 - PAGE_SHIFT));
	}

	/* No tree selected, just dump RMP then */
#define min(a, b) ((a) < (b) ? (a) : (b))
	if (g.rmptable && !qemupt && !nptpt && fn >= 8 && !g.dteoff)
		ret = dump_rmp(g.start, min(g.end, g.rmpend));

	return 0;
}
