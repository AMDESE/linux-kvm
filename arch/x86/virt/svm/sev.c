// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD SVM-SEV Host Support.
 *
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 *
 * Author: Ashish Kalra <ashish.kalra@amd.com>
 *
 */

#include <linux/cc_platform.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/iommu.h>
#include <linux/amd-iommu.h>
#include <linux/nospec.h>

#include <asm/sev.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/cpuid.h>
#include <asm/cmdline.h>
#include <asm/iommu.h>

/*
 * The RMP entry format as returned by the RMPREAD instruction.
 */
struct rmpentry {
	u64 gpa;
	u8  assigned		:1,
	    rsvd1		:7;
	u8  pagesize		:1,
	    hpage_region_status	:1,
	    rsvd2		:6;
	u8  immutable		:1,
	    rsvd3		:7;
	u8  rsvd4;
	u32 asid;
} __packed;

/*
 * The RMP entry format is not architectural. The format is defined in PPR
 * Family 19h Model 01h, Rev B1 processor.
 */
struct rmpentry_raw {
	union {
		struct {
			u64 assigned	: 1,
			    pagesize	: 1,
			    immutable	: 1,
			    rsvd1	: 9,
			    gpa		: 39,
			    asid	: 10,
			    vmsa	: 1,
			    validated	: 1,
			    rsvd2	: 1;
		};
		u64 lo;
	};
	u64 hi;
} __packed;

/*
 * The first 16KB from the RMP_BASE is used by the processor for the
 * bookkeeping, the range needs to be added during the RMP entry lookup.
 */
#define RMPTABLE_CPU_BOOKKEEPING_SZ	0x4000

/*
 * For a non-segmented RMP table, use the maximum physical addressing as the
 * segment size in order to always arrive at index 0 in the table.
 */
#define RMPTABLE_NON_SEGMENTED_SHIFT	52

struct rmp_segment_desc {
	struct rmpentry_raw *rmp_entry;
	u64 max_index;
	u64 size;
};

/*
 * Segmented RMP Table support.
 *   - The segment size is used for two purposes:
 *     - Identify the amount of memory covered by an RMP segment
 *     - Quickly locate an RMP segment table entry for a physical address
 *
 *   - The RMP segment table contains pointers to an RMP table that covers
 *     a specific portion of memory. There can be up to 512 8-byte entries,
 *     one pages worth.
 */
#define RST_ENTRY_MAPPED_SIZE(x)	((x) & GENMASK_ULL(19, 0))
#define RST_ENTRY_SEGMENT_BASE(x)	((x) & GENMASK_ULL(51, 20))

#define RMP_SEGMENT_TABLE_SIZE	SZ_4K
static struct rmp_segment_desc **rmp_segment_table __ro_after_init;
static unsigned int rst_max_index __ro_after_init = 512;

static u64 rmp_segment_size_max;
static unsigned int rmp_segment_coverage_shift;
static unsigned long rmp_segment_coverage_size;
static unsigned long rmp_segment_coverage_mask;
#define RST_ENTRY_INDEX(x)	((x) >> rmp_segment_coverage_shift)
#define RMP_ENTRY_INDEX(x)	PHYS_PFN((x) & rmp_segment_coverage_mask)

static u64 rmp_cfg;
#define RMP_IS_SEGMENTED(x)	((x) & MSR_AMD64_SEG_RMP_ENABLED)

/* Mask to apply to a PFN to get the first PFN of a 2MB page */
#define PFN_PMD_MASK	GENMASK_ULL(63, PMD_SHIFT - PAGE_SHIFT)

static u64 probed_rmp_base, probed_rmp_size;

static LIST_HEAD(snp_leaked_pages_list);
static DEFINE_SPINLOCK(snp_leaked_pages_list_lock);

static unsigned long snp_nr_leaked_pages;

#undef pr_fmt
#define pr_fmt(fmt)	"SEV-SNP: " fmt

static int __mfd_enable(unsigned int cpu)
{
	u64 val;

	if (!cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		return 0;

	rdmsrl(MSR_AMD64_SYSCFG, val);

	val |= MSR_AMD64_SYSCFG_MFDM;

	wrmsrl(MSR_AMD64_SYSCFG, val);

	return 0;
}

static __init void mfd_enable(void *arg)
{
	__mfd_enable(smp_processor_id());
}

static int __snp_enable(unsigned int cpu)
{
	u64 val;

	if (!cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		return 0;

	rdmsrl(MSR_AMD64_SYSCFG, val);

	val |= MSR_AMD64_SYSCFG_SNP_EN;
	val |= MSR_AMD64_SYSCFG_SNP_VMPL_EN;

	wrmsrl(MSR_AMD64_SYSCFG, val);

	return 0;
}

static __init void snp_enable(void *arg)
{
	__snp_enable(smp_processor_id());
}

static void __init __snp_fixup_e820_tables(u64 pa)
{
	if (IS_ALIGNED(pa, PMD_SIZE))
		return;

	/*
	 * Handle cases where the RMP table placement by the BIOS is not
	 * 2M aligned and the kexec kernel could try to allocate
	 * from within that chunk which then causes a fatal RMP fault.
	 *
	 * The e820_table needs to be updated as it is converted to
	 * kernel memory resources and used by KEXEC_FILE_LOAD syscall
	 * to load kexec segments.
	 *
	 * The e820_table_firmware needs to be updated as it is exposed
	 * to sysfs and used by the KEXEC_LOAD syscall to load kexec
	 * segments.
	 *
	 * The e820_table_kexec needs to be updated as it passed to
	 * the kexec-ed kernel.
	 */
	pa = ALIGN_DOWN(pa, PMD_SIZE);
	if (e820__mapped_any(pa, pa + PMD_SIZE, E820_TYPE_RAM)) {
		pr_info("Reserving start/end of RMP table on a 2MB boundary [0x%016llx]\n", pa);
		e820__range_update(pa, PMD_SIZE, E820_TYPE_RAM, E820_TYPE_RESERVED);
		e820__range_update_table(e820_table_kexec, pa, PMD_SIZE, E820_TYPE_RAM, E820_TYPE_RESERVED);
		e820__range_update_table(e820_table_firmware, pa, PMD_SIZE, E820_TYPE_RAM, E820_TYPE_RESERVED);
		if (!memblock_is_region_reserved(pa, PMD_SIZE))
			memblock_reserve(pa, PMD_SIZE);
	}
}

void __init snp_fixup_e820_tables(void)
{
	__snp_fixup_e820_tables(probed_rmp_base);

	if (RMP_IS_SEGMENTED(rmp_cfg)) {
		unsigned long size;
		unsigned int i;
		u64 pa, *rst;

		pa = probed_rmp_base;
		pa += RMPTABLE_CPU_BOOKKEEPING_SZ;
		pa += RMP_SEGMENT_TABLE_SIZE;
		__snp_fixup_e820_tables(pa);

		pa -= RMP_SEGMENT_TABLE_SIZE;
		rst = early_memremap(pa, RMP_SEGMENT_TABLE_SIZE);
		if (!rst)
			return;

		for (i = 0; i < rst_max_index; i++) {
			pa = RST_ENTRY_SEGMENT_BASE(rst[i]);
			size = RST_ENTRY_MAPPED_SIZE(rst[i]);
			if (!size)
				continue;

			__snp_fixup_e820_tables(pa);

			/* Mapped size in GB */
			size *= (1UL << 30);
			if (size > rmp_segment_coverage_size)
				size = rmp_segment_coverage_size;

			__snp_fixup_e820_tables(pa + size);
		}

		early_memunmap(rst, RMP_SEGMENT_TABLE_SIZE);
	} else {
		__snp_fixup_e820_tables(probed_rmp_base + probed_rmp_size);
	}
}

static bool __init init_rmptable_bookkeeping(void)
{
	void *bk;

	bk = memremap(probed_rmp_base, RMPTABLE_CPU_BOOKKEEPING_SZ, MEMREMAP_WB);
	if (!bk) {
		pr_err("Failed to map RMP bookkeeping area\n");
		return false;
	}

	memset(bk, 0, RMPTABLE_CPU_BOOKKEEPING_SZ);

	memunmap(bk);

	return true;
}

static bool __init alloc_rmp_segment_desc(u64 segment_pa, u64 segment_size, u64 pa)
{
	struct rmp_segment_desc *desc;
	unsigned long rst_index;
	void *rmp_segment;

	/* Validate the RMP segment size */
	if (segment_size > rmp_segment_size_max) {
		pr_err("Invalid RMP size (%#llx) for configured segment size (%#llx)\n",
		       segment_size, rmp_segment_size_max);
		return false;
	}

	/* Validate the RMP segment table index */
	rst_index = RST_ENTRY_INDEX(pa);
	if (rst_index >= rst_max_index) {
		pr_err("Invalid RMP segment base address (%#llx) for configured segment size (%#lx)\n",
		       pa, rmp_segment_coverage_size);
		return false;
	}
	rst_index = array_index_nospec(rst_index, rst_max_index);

	if (rmp_segment_table[rst_index]) {
		pr_err("RMP segment descriptor already exists at index %lu\n", rst_index);
		return false;
	}

	/* Map the RMP entries */
	rmp_segment = memremap(segment_pa, segment_size, MEMREMAP_WB);
	if (!rmp_segment) {
		pr_err("Failed to map RMP segment addr 0x%llx size 0x%llx\n",
		       segment_pa, segment_size);
		return false;
	}

	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		memunmap(rmp_segment);
		return false;
	}

	desc->rmp_entry = rmp_segment;
	desc->max_index = segment_size / sizeof(*desc->rmp_entry);
	desc->size = segment_size;

	/* Add the segment descriptor to the table */
	rmp_segment_table[rst_index] = desc;

	return true;
}

static void __init free_rmp_segment_table(void)
{
	unsigned int i;

	for (i = 0; i < rst_max_index; i++) {
		struct rmp_segment_desc *desc;

		desc = rmp_segment_table[i];
		if (!desc)
			continue;

		memunmap(desc->rmp_entry);

		kfree(desc);
	}

	free_page((unsigned long)rmp_segment_table);

	rmp_segment_table = NULL;
}

static bool __init alloc_rmp_segment_table(void)
{
	struct page *page;

	/* Allocate the table used to index into the RMP segments */
	page = alloc_page(__GFP_ZERO);
	if (!page)
		return false;

	rmp_segment_table = page_address(page);

	return true;
}

static bool __init contiguous_rmptable_setup(void)
{
	u64 max_rmp_pfn, calc_rmp_sz, rmptable_segment, rmptable_size, rmp_end;

	if (!probed_rmp_size)
		return false;

	rmp_end = probed_rmp_base + probed_rmp_size - 1;

	/*
	 * Calculate the amount the memory that must be reserved by the BIOS to
	 * address the whole RAM, including the bookkeeping area. The RMP itself
	 * must also be covered.
	 */
	max_rmp_pfn = max_pfn;
	if (PFN_UP(rmp_end) > max_pfn)
		max_rmp_pfn = PFN_UP(rmp_end);

	calc_rmp_sz = (max_rmp_pfn << 4) + RMPTABLE_CPU_BOOKKEEPING_SZ;
	if (calc_rmp_sz > probed_rmp_size) {
		pr_err("Memory reserved for the RMP table does not cover full system RAM (expected 0x%llx got 0x%llx)\n",
		       calc_rmp_sz, probed_rmp_size);
		return false;
	}

	if (!alloc_rmp_segment_table())
		return false;

	/* Map only the RMP entries */
	rmptable_segment = probed_rmp_base + RMPTABLE_CPU_BOOKKEEPING_SZ;
	rmptable_size = probed_rmp_size - RMPTABLE_CPU_BOOKKEEPING_SZ;

	if (!alloc_rmp_segment_desc(rmptable_segment, rmptable_size, 0)) {
		free_rmp_segment_table();
		return false;
	}

	return true;
}

static bool __init segmented_rmptable_setup(void)
{
	u64 rst_pa, *rst, pa, ram_pa_end, ram_pa_max;
	unsigned int i, max_index;

	if (!probed_rmp_base)
		return false;

	if (!alloc_rmp_segment_table())
		return false;

	/* Map the RMP Segment Table */
	rst_pa = probed_rmp_base + RMPTABLE_CPU_BOOKKEEPING_SZ;
	rst = memremap(rst_pa, RMP_SEGMENT_TABLE_SIZE, MEMREMAP_WB);
	if (!rst) {
		pr_err("Failed to map RMP segment table addr %#llx\n", rst_pa);
		goto e_free;
	}

	/* Get the address for the end of system RAM */
	ram_pa_max = max_pfn << PAGE_SHIFT;

	/* Process each RMP segment */
	max_index = 0;
	ram_pa_end = 0;
	for (i = 0; i < rst_max_index; i++) {
		u64 rmp_segment, rmp_size, mapped_size;

		mapped_size = RST_ENTRY_MAPPED_SIZE(rst[i]);
		if (!mapped_size)
			continue;

		max_index = i;

		/* Mapped size in GB */
		mapped_size *= (1ULL << 30);
		if (mapped_size > rmp_segment_coverage_size)
			mapped_size = rmp_segment_coverage_size;

		rmp_segment = RST_ENTRY_SEGMENT_BASE(rst[i]);

		rmp_size = PHYS_PFN(mapped_size);
		rmp_size <<= 4;

		pa = (u64)i << rmp_segment_coverage_shift;

		/* Some segments may be for MMIO mapped above system RAM */
		if (pa < ram_pa_max)
			ram_pa_end = pa + mapped_size;

		if (!alloc_rmp_segment_desc(rmp_segment, rmp_size, pa))
			goto e_unmap;

		pr_info("RMP segment %u physical address [%#llx - %#llx] covering [%#llx - %#llx]\n",
			i, rmp_segment, rmp_segment + rmp_size - 1, pa, pa + mapped_size - 1);
	}

	if (ram_pa_max > ram_pa_end) {
		pr_err("Segmented RMP does not cover full system RAM (expected 0x%llx got 0x%llx)\n",
		       ram_pa_max, ram_pa_end);
		goto e_unmap;
	}

	/* Adjust the maximum index based on the found segments */
	rst_max_index = max_index + 1;

	memunmap(rst);

	return true;

e_unmap:
	memunmap(rst);

e_free:
	free_rmp_segment_table();

	return false;
}

static bool __init rmptable_setup(void)
{
	return RMP_IS_SEGMENTED(rmp_cfg) ? segmented_rmptable_setup()
					 : contiguous_rmptable_setup();
}

/*
 * Do the necessary preparations which are verified by the firmware as
 * described in the SNP_INIT_EX firmware command description in the SNP
 * firmware ABI spec.
 */
static int __init snp_rmptable_init(void)
{
	unsigned int i;
	u64 val;

	if (!cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		return 0;

	if (!amd_iommu_snp_en)
		goto nosnp;

	if (!rmptable_setup())
		goto nosnp;

	/*
	 * Check if SEV-SNP is already enabled, this can happen in case of
	 * kexec boot.
	 */
	rdmsrl(MSR_AMD64_SYSCFG, val);
	if (val & MSR_AMD64_SYSCFG_SNP_EN)
		goto skip_enable;

	/* Zero out the RMP bookkeeping area */
	if (!init_rmptable_bookkeeping()) {
		free_rmp_segment_table();
		goto nosnp;
	}

	/* Zero out the RMP entries */
	for (i = 0; i < rst_max_index; i++) {
		struct rmp_segment_desc *desc;

		desc = rmp_segment_table[i];
		if (!desc)
			continue;

		memset(desc->rmp_entry, 0, desc->size);
	}

	/* Flush the caches to ensure that data is written before SNP is enabled. */
	wbinvd_on_all_cpus();

	/* MtrrFixDramModEn must be enabled on all the CPUs prior to enabling SNP. */
	on_each_cpu(mfd_enable, NULL, 1);

	on_each_cpu(snp_enable, NULL, 1);

skip_enable:
	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/rmptable_init:online", __snp_enable, NULL);

	/*
	 * Setting crash_kexec_post_notifiers to 'true' to ensure that SNP panic
	 * notifier is invoked to do SNP IOMMU shutdown before kdump.
	 */
	crash_kexec_post_notifiers = true;

	return 0;

nosnp:
	cc_platform_clear(CC_ATTR_HOST_SEV_SNP);
	return -ENOSYS;
}

/*
 * This must be called after the IOMMU has been initialized.
 */
device_initcall(snp_rmptable_init);

static void set_rmp_segment_info(unsigned int segment_shift)
{
	rmp_segment_coverage_shift = segment_shift;
	rmp_segment_coverage_size  = 1UL << rmp_segment_coverage_shift;
	rmp_segment_coverage_mask  = rmp_segment_coverage_size - 1;

	/* Calculate the maximum size an RMP can be (16 bytes/page mapped) */
	rmp_segment_size_max = PHYS_PFN(rmp_segment_coverage_size);
	rmp_segment_size_max <<= 4;
}

#define RMP_ADDR_MASK GENMASK_ULL(51, 13)

static bool probe_contiguous_rmptable_info(void)
{
	u64 rmp_sz, rmp_base, rmp_end;

	rdmsrl(MSR_AMD64_RMP_BASE, rmp_base);
	rdmsrl(MSR_AMD64_RMP_END, rmp_end);

	if (!(rmp_base & RMP_ADDR_MASK) || !(rmp_end & RMP_ADDR_MASK)) {
		pr_err("Memory for the RMP table has not been reserved by BIOS\n");
		return false;
	}

	if (rmp_base > rmp_end) {
		pr_err("RMP configuration not valid: base=%#llx, end=%#llx\n", rmp_base, rmp_end);
		return false;
	}

	rmp_sz = rmp_end - rmp_base + 1;

	/* Treat the contiguous RMP table as a single segment */
	rst_max_index = 1;

	set_rmp_segment_info(RMPTABLE_NON_SEGMENTED_SHIFT);

	probed_rmp_base = rmp_base;
	probed_rmp_size = rmp_sz;

	pr_info("RMP table physical range [0x%016llx - 0x%016llx]\n",
		rmp_base, rmp_end);

	return true;
}

static bool probe_segmented_rmptable_info(void)
{
	unsigned int eax, ebx, segment_shift, segment_shift_min, segment_shift_max;
	u64 rmp_base, rmp_end;

	rdmsrl(MSR_AMD64_RMP_BASE, rmp_base);
	rdmsrl(MSR_AMD64_RMP_END, rmp_end);

	if (!(rmp_base & RMP_ADDR_MASK)) {
		pr_err("Memory for the RMP table has not been reserved by BIOS\n");
		return false;
	}

	WARN_ONCE(rmp_end & RMP_ADDR_MASK,
		  "Segmented RMP enabled but RMP_END MSR is non-zero\n");

	/* Obtain the min and max supported RMP segment size */
	eax = cpuid_eax(0x80000025);
	segment_shift_min = eax & GENMASK(5, 0);
	segment_shift_max = (eax & GENMASK(11, 6)) >> 6;

	/* Verify the segment size is within the supported limits */
	segment_shift = MSR_AMD64_RMP_SEGMENT_SHIFT(rmp_cfg);
	if (segment_shift > segment_shift_max || segment_shift < segment_shift_min) {
		pr_err("RMP segment size (%u) is not within advertised bounds (min=%u, max=%u)\n",
		       segment_shift, segment_shift_min, segment_shift_max);
		return false;
	}

	/* Override the max supported RST index if a hardware limit exists */
	ebx = cpuid_ebx(0x80000025);
	if (ebx & BIT(10))
		rst_max_index = ebx & GENMASK(9, 0);

	set_rmp_segment_info(segment_shift);

	probed_rmp_base = rmp_base;
	probed_rmp_size = 0;

	pr_info("RMP segment table physical address [0x%016llx - 0x%016llx]\n",
		rmp_base, rmp_base + RMPTABLE_CPU_BOOKKEEPING_SZ + RMP_SEGMENT_TABLE_SIZE);

	return true;
}

bool snp_probe_rmptable_info(void)
{
	if (cpu_feature_enabled(X86_FEATURE_SEGMENTED_RMP))
		rdmsrl(MSR_AMD64_RMP_CFG, rmp_cfg);

	return RMP_IS_SEGMENTED(rmp_cfg) ? probe_segmented_rmptable_info()
					 : probe_contiguous_rmptable_info();
}

static struct rmpentry_raw *__get_rmpentry(unsigned long pfn)
{
	struct rmp_segment_desc *desc;
	unsigned long rst_index;
	unsigned long paddr;
	u64 segment_index;

	if (!rmp_segment_table)
		return ERR_PTR(-ENODEV);

	paddr = pfn << PAGE_SHIFT;

	rst_index = RST_ENTRY_INDEX(paddr);
	if (unlikely(rst_index >= rst_max_index))
		return ERR_PTR(-EFAULT);
	rst_index = array_index_nospec(rst_index, rst_max_index);

	desc = rmp_segment_table[rst_index];
	if (unlikely(!desc))
		return ERR_PTR(-EFAULT);

	segment_index = RMP_ENTRY_INDEX(paddr);
	if (unlikely(segment_index >= desc->max_index))
		return ERR_PTR(-EFAULT);
	segment_index = array_index_nospec(segment_index, desc->max_index);

	return desc->rmp_entry + segment_index;
}

static int get_rmpentry(u64 pfn, struct rmpentry *entry)
{
	struct rmpentry_raw *e;

	if (cpu_feature_enabled(X86_FEATURE_RMPREAD)) {
		int ret;

		asm volatile(".byte 0xf2, 0x0f, 0x01, 0xfd"
			     : "=a" (ret)
			     : "a" (pfn << PAGE_SHIFT), "c" (entry)
			     : "memory", "cc");

		return ret;
	}

	e = __get_rmpentry(pfn);
	if (IS_ERR(e))
		return PTR_ERR(e);

	/*
	 * Map the RMP table entry onto the RMPREAD output format.
	 * The 2MB region status indicator (hpage_region_status field) is not
	 * calculated, since the overhead could be significant and the field
	 * is not used.
	 */
	memset(entry, 0, sizeof(*entry));
	entry->gpa       = e->gpa << PAGE_SHIFT;
	entry->asid      = e->asid;
	entry->assigned  = e->assigned;
	entry->pagesize  = e->pagesize;
	entry->immutable = e->immutable;

	return 0;
}

static int __snp_lookup_rmpentry(u64 pfn, struct rmpentry *entry, int *level)
{
	struct rmpentry large_entry;
	int ret;

	if (!cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		return -ENODEV;

	ret = get_rmpentry(pfn, entry);
	if (ret)
		return ret;

	/*
	 * Find the authoritative RMP entry for a PFN. This can be either a 4K
	 * RMP entry or a special large RMP entry that is authoritative for a
	 * whole 2M area.
	 */
	ret = get_rmpentry(pfn & PFN_PMD_MASK, &large_entry);
	if (ret)
		return ret;

	*level = RMP_TO_PG_LEVEL(large_entry.pagesize);

	return 0;
}

int snp_lookup_rmpentry(u64 pfn, bool *assigned, int *level)
{
	struct rmpentry e;
	int ret;

	ret = __snp_lookup_rmpentry(pfn, &e, level);
	if (ret)
		return ret;

	*assigned = !!e.assigned;
	return 0;
}
EXPORT_SYMBOL_GPL(snp_lookup_rmpentry);

/*
 * Dump the raw RMP entry for a particular PFN. These bits are documented in the
 * PPR for a particular CPU model and provide useful information about how a
 * particular PFN is being utilized by the kernel/firmware at the time certain
 * unexpected events occur, such as RMP faults.
 */
static void dump_rmpentry(u64 pfn)
{
	struct rmpentry_raw *e_raw;
	u64 pfn_i, pfn_end;
	struct rmpentry e;
	int level, ret;

	ret = __snp_lookup_rmpentry(pfn, &e, &level);
	if (ret) {
		pr_err("Failed to read RMP entry for PFN 0x%llx, error %d\n",
		       pfn, ret);
		return;
	}

	if (e.assigned) {
		e_raw = __get_rmpentry(pfn);
		if (IS_ERR(e_raw)) {
			pr_err("Failed to read RMP contents for PFN 0x%llx, error %ld\n",
			       pfn, PTR_ERR(e_raw));
			return;
		}

		pr_info("PFN 0x%llx, RMP entry: [0x%016llx - 0x%016llx]\n",
			pfn, e_raw->lo, e_raw->hi);
		return;
	}

	/*
	 * If the RMP entry for a particular PFN is not in an assigned state,
	 * then it is sometimes useful to get an idea of whether or not any RMP
	 * entries for other PFNs within the same 2MB region are assigned, since
	 * those too can affect the ability to access a particular PFN in
	 * certain situations, such as when the PFN is being accessed via a 2MB
	 * mapping in the host page table.
	 */
	pfn_i = ALIGN_DOWN(pfn, PTRS_PER_PMD);
	pfn_end = pfn_i + PTRS_PER_PMD;

	pr_info("PFN 0x%llx unassigned, dumping non-zero entries in 2M PFN region: [0x%llx - 0x%llx]\n",
		pfn, pfn_i, pfn_end);

	while (pfn_i < pfn_end) {
		e_raw = __get_rmpentry(pfn_i);
		if (IS_ERR(e_raw)) {
			pr_err("Error %ld reading RMP contents for PFN 0x%llx\n",
			       PTR_ERR(e_raw), pfn_i);
			pfn_i++;
			continue;
		}

		if (e_raw->lo || e_raw->hi)
			pr_info("PFN: 0x%llx, [0x%016llx - 0x%016llx]\n",
				pfn_i, e_raw->lo, e_raw->hi);

		pfn_i++;
	}
}

void snp_dump_hva_rmpentry(unsigned long hva)
{
	unsigned long paddr;
	unsigned int level;
	pgd_t *pgd;
	pte_t *pte;

	pgd = __va(read_cr3_pa());
	pgd += pgd_index(hva);
	pte = lookup_address_in_pgd(pgd, hva, &level);

	if (!pte) {
		pr_err("Can't dump RMP entry for HVA %lx: no PTE/PFN found\n", hva);
		return;
	}

	paddr = PFN_PHYS(pte_pfn(*pte)) | (hva & ~page_level_mask(level));
	dump_rmpentry(PHYS_PFN(paddr));
}

/*
 * PSMASH a 2MB aligned page into 4K pages in the RMP table while preserving the
 * Validated bit.
 */
int psmash(u64 pfn)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	int ret;

	if (!cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		return -ENODEV;

	if (!pfn_valid(pfn))
		return -EINVAL;

	/* Binutils version 2.36 supports the PSMASH mnemonic. */
	asm volatile(".byte 0xF3, 0x0F, 0x01, 0xFF"
		      : "=a" (ret)
		      : "a" (paddr)
		      : "memory", "cc");

	return ret;
}
EXPORT_SYMBOL_GPL(psmash);

/*
 * If the kernel uses a 2MB or larger directmap mapping to write to an address,
 * and that mapping contains any 4KB pages that are set to private in the RMP
 * table, an RMP #PF will trigger and cause a host crash. Hypervisor code that
 * owns the PFNs being transitioned will never attempt such a write, but other
 * kernel tasks writing to other PFNs in the range may trigger these checks
 * inadvertently due a large directmap mapping that happens to overlap such a
 * PFN.
 *
 * Prevent this by splitting any 2MB+ mappings that might end up containing a
 * mix of private/shared PFNs as a result of a subsequent RMPUPDATE for the
 * PFN/rmp_level passed in.
 *
 * Note that there is no attempt here to scan all the RMP entries for the 2MB
 * physical range, since it would only be worthwhile in determining if a
 * subsequent RMPUPDATE for a 4KB PFN would result in all the entries being of
 * the same shared/private state, thus avoiding the need to split the mapping.
 * But that would mean the entries are currently in a mixed state, and so the
 * mapping would have already been split as a result of prior transitions.
 * And since the 4K split is only done if the mapping is 2MB+, and there isn't
 * currently a mechanism in place to restore 2MB+ mappings, such a check would
 * not provide any usable benefit.
 *
 * More specifics on how these checks are carried out can be found in APM
 * Volume 2, "RMP and VMPL Access Checks".
 */
static int adjust_direct_map(u64 pfn, int rmp_level)
{
	unsigned long vaddr;
	unsigned int level;
	int npages, ret;
	pte_t *pte;

	/*
	 * pfn_to_kaddr() will return a vaddr only within the direct
	 * map range.
	 */
	vaddr = (unsigned long)pfn_to_kaddr(pfn);

	/* Only 4KB/2MB RMP entries are supported by current hardware. */
	if (WARN_ON_ONCE(rmp_level > PG_LEVEL_2M))
		return -EINVAL;

	if (!pfn_valid(pfn))
		return -EINVAL;

	if (rmp_level == PG_LEVEL_2M &&
	    (!IS_ALIGNED(pfn, PTRS_PER_PMD) || !pfn_valid(pfn + PTRS_PER_PMD - 1)))
		return -EINVAL;

	/*
	 * If an entire 2MB physical range is being transitioned, then there is
	 * no risk of RMP #PFs due to write accesses from overlapping mappings,
	 * since even accesses from 1GB mappings will be treated as 2MB accesses
	 * as far as RMP table checks are concerned.
	 */
	if (rmp_level == PG_LEVEL_2M)
		return 0;

	pte = lookup_address(vaddr, &level);
	if (!pte || pte_none(*pte))
		return 0;

	if (level == PG_LEVEL_4K)
		return 0;

	npages = page_level_size(rmp_level) / PAGE_SIZE;
	ret = set_memory_4k(vaddr, npages);
	if (ret)
		pr_warn("Failed to split direct map for PFN 0x%llx, ret: %d\n",
			pfn, ret);

	return ret;
}

/*
 * It is expected that those operations are seldom enough so that no mutual
 * exclusion of updaters is needed and thus the overlap error condition below
 * should happen very rarely and would get resolved relatively quickly by
 * the firmware.
 *
 * If not, one could consider introducing a mutex or so here to sync concurrent
 * RMP updates and thus diminish the amount of cases where firmware needs to
 * lock 2M ranges to protect against concurrent updates.
 *
 * The optimal solution would be range locking to avoid locking disjoint
 * regions unnecessarily but there's no support for that yet.
 */
static int rmpupdate(u64 pfn, struct rmp_state *state)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	int ret, level;

	if (!cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		return -ENODEV;

	level = RMP_TO_PG_LEVEL(state->pagesize);

	if (adjust_direct_map(pfn, level))
		return -EFAULT;

	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)state)
			     : "memory", "cc");
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	if (ret) {
		pr_err("RMPUPDATE failed for PFN %llx, pg_level: %d, ret: %d\n",
		       pfn, level, ret);
		dump_rmpentry(pfn);
		dump_stack();
		return -EFAULT;
	}

	return 0;
}

/* Transition a page to guest-owned/private state in the RMP table. */
int rmp_make_private(u64 pfn, u64 gpa, enum pg_level level, u32 asid, bool immutable)
{
	struct rmp_state state;

	memset(&state, 0, sizeof(state));
	state.assigned = 1;
	state.asid = asid;
	state.immutable = immutable;
	state.gpa = gpa;
	state.pagesize = PG_LEVEL_TO_RMP(level);

	return rmpupdate(pfn, &state);
}
EXPORT_SYMBOL_GPL(rmp_make_private);

/* Transition a page to hypervisor-owned/shared state in the RMP table. */
int rmp_make_shared(u64 pfn, enum pg_level level)
{
	struct rmp_state state;

	memset(&state, 0, sizeof(state));
	state.pagesize = PG_LEVEL_TO_RMP(level);

	return rmpupdate(pfn, &state);
}
EXPORT_SYMBOL_GPL(rmp_make_shared);

void snp_leak_pages(u64 pfn, unsigned int npages)
{
	struct page *page = pfn_to_page(pfn);

	pr_warn("Leaking PFN range 0x%llx-0x%llx\n", pfn, pfn + npages);

	spin_lock(&snp_leaked_pages_list_lock);
	while (npages--) {

		/*
		 * Reuse the page's buddy list for chaining into the leaked
		 * pages list. This page should not be on a free list currently
		 * and is also unsafe to be added to a free list.
		 */
		if (likely(!PageCompound(page)) ||

			/*
			 * Skip inserting tail pages of compound page as
			 * page->buddy_list of tail pages is not usable.
			 */
		    (PageHead(page) && compound_nr(page) <= npages))
			list_add_tail(&page->buddy_list, &snp_leaked_pages_list);

		dump_rmpentry(pfn);
		snp_nr_leaked_pages++;
		pfn++;
		page++;
	}
	spin_unlock(&snp_leaked_pages_list_lock);
}
EXPORT_SYMBOL_GPL(snp_leak_pages);

void kdump_sev_callback(void)
{
	/*
	 * Do wbinvd() on remote CPUs when SNP is enabled in order to
	 * safely do SNP_SHUTDOWN on the local CPU.
	 */
	if (cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		wbinvd();
}
