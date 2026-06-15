// SPDX-License-Identifier: GPL-2.0-only
#include <linux/debugfs.h>
#include <linux/efi.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/pgtable.h>

static int ptdump_show(struct seq_file *m, void *v)
{
	ptdump_walk_pgd_level_debugfs(m, &init_mm, false);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump);

static int ptdump_curknl_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd)
		ptdump_walk_pgd_level_debugfs(m, current->mm, false);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curknl);

#ifdef CONFIG_MITIGATION_PAGE_TABLE_ISOLATION
static int ptdump_curusr_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd)
		ptdump_walk_pgd_level_debugfs(m, current->mm, true);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curusr);
#endif

#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
static int ptdump_efi_show(struct seq_file *m, void *v)
{
	if (efi_mm.pgd)
		ptdump_walk_pgd_level_debugfs(m, &efi_mm, false);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_efi);
#endif

#if defined(CONFIG_DEBUG_PAGETABLES) || defined(CONFIG_DEBUG_PAGETABLES_MODULE)
static int kernel_pt(void *data, u64 *val)
{
	pgd_t *pt = init_mm.pgd;

	*val = (u64) __pa(pt);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(kernel_pt_fops, kernel_pt, NULL, "%llx\n");

static int rmptable(void *data, u64 *val)
{
	rdmsrq(MSR_AMD64_RMP_BASE, *val);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(rmptable_fops, rmptable, NULL, "%llx\n");

static int rmpcfg(void *data, u64 *val)
{
	rdmsrq(MSR_AMD64_RMP_CFG, *val);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(rmpcfg_fops, rmpcfg, NULL, "%llx\n");

static int kernel_pt_levels(void *data, u64 *val)
{
	*val = pgtable_l5_enabled() ? 5 : 4;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(kernel_pt_levels_fops, kernel_pt_levels, NULL, "%lld\n");

static int max_pfn_fn(void *data, u64 *val)
{
	*val = max_pfn;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(max_pfn_fops, max_pfn_fn, NULL, "%llx\n");
#endif

static struct dentry *dir;

static int __init pt_dump_debug_init(void)
{
	dir = debugfs_create_dir("page_tables", NULL);

	debugfs_create_file("kernel", 0400, dir, NULL, &ptdump_fops);
	debugfs_create_file("current_kernel", 0400, dir, NULL,
			    &ptdump_curknl_fops);

#ifdef CONFIG_MITIGATION_PAGE_TABLE_ISOLATION
	debugfs_create_file("current_user", 0400, dir, NULL,
			    &ptdump_curusr_fops);
#endif
#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
	debugfs_create_file("efi", 0400, dir, NULL, &ptdump_efi_fops);
#endif
#if defined(CONFIG_DEBUG_PAGETABLES) || defined(CONFIG_DEBUG_PAGETABLES_MODULE)
	debugfs_create_file("kernel_pt", 0444, dir, NULL, &kernel_pt_fops);
	debugfs_create_file("rmptable", 0444, dir, NULL, &rmptable_fops);
	debugfs_create_file("rmpcfg", 0444, dir, NULL, &rmpcfg_fops);
	debugfs_create_file("kernel_pt_levels", 0444, dir, NULL, &kernel_pt_levels_fops);
	debugfs_create_file("max_pfn", 0444, dir, NULL, &max_pfn_fops);
#endif
	return 0;
}

static void __exit pt_dump_debug_exit(void)
{
	debugfs_remove_recursive(dir);
}

module_init(pt_dump_debug_init);
module_exit(pt_dump_debug_exit);
MODULE_AUTHOR("Arjan van de Ven <arjan@linux.intel.com>");
MODULE_DESCRIPTION("Kernel debugging helper that dumps pagetables");
