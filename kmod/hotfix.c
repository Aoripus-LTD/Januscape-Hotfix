/*
 * Januscape (CVE-2026-53359) + UAF Escape Chain Fix — Kernel Module
 *
 * Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD.
 * Copyright (c) 2026 GEELINX LTD.
 *
 * Zero-downtime livepatch for KVM/x86 shadow MMU vulnerabilities.
 * Uses the kernel livepatch API to fix two bugs:
 *
 *   1. 81ccda30b4e8 — role.word comparison in kvm_mmu_get_child_sp()
 *      Prevents gfn mismatch → pte_list_remove → host DoS.
 *
 *   2. 0cb2af2ea66ad — stale SPTE unlink in __link_shadow_page()
 *      Prevents UAF write on freed shadow page → host RCE.
 *
 * Architecture: resolves ALL KVM internal symbols at load time via
 * kallsyms (kprobe fallback for >= 5.7). No KVM headers needed —
 * uses offset-based struct field access with tunable module params.
 *
 * Contact: master@aoripus.com
 * License: GPL v2
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/livepatch.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <generated/utsrelease.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Januscape (CVE-2026-53359) + UAF escape chain livepatch");
MODULE_AUTHOR("AORIPUS (BEIJING) TECHNOLOGY CO., LTD. / GEELINX LTD. <master@aoripus.com>");
MODULE_INFO(livepatch, "Y");

/* Module parameters */
static unsigned long gfn_off  = 0x38;
static unsigned long role_off = 0x28;
module_param(gfn_off,  ulong, 0444);
module_param(role_off, ulong, 0444);

/* ═══════════════════════════════════════════════════════════════════════
 *  kallsyms_lookup_name resolution
 * ═══════════════════════════════════════════════════════════════════════ */

typedef unsigned long (*kln_t)(const char *name);
static kln_t kln_fn;

static int resolve_kln(void)
{
	kln_fn = (kln_t)__symbol_get("kallsyms_lookup_name");
	if (kln_fn) return 0;
	{
		struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
		int ret = register_kprobe(&kp);
		if (ret < 0) return ret;
		kln_fn = (kln_t)kp.addr;
		unregister_kprobe(&kp);
	}
	return kln_fn ? 0 : -ENOENT;
}

static void *resolve(const char *name)
{
	void *addr = kln_fn ? (void *)kln_fn(name) : NULL;
	if (!addr) pr_err("symbol NOT FOUND: %s\n", name);
	return addr;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Offset-based field access
 * ═══════════════════════════════════════════════════════════════════════ */

static inline unsigned long read_field(void *sp, unsigned long off)
{
	unsigned long v;
	memcpy(&v, (char *)sp + off, sizeof(v));
	return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Resolved KVM internal function pointers (x86_64 ABI-compatible)
 * ═══════════════════════════════════════════════════════════════════════ */

static u32  (*fn_kvm_mmu_child_role)(u64 *sptep, bool direct, unsigned int access);
static void *(*fn_get_shadow_page)(void *kvm, void *vcpu, void *caches,
				    unsigned long gfn, u32 role);
static bool (*fn_is_shadow_present_pte)(u64 pte);
static bool (*fn_is_large_pte)(u64 pte);
static void *(*fn_spte_to_child_sp)(u64 spte);
static void *(*fn_sptep_to_sp)(u64 *sptep);

static int  (*fn_mmu_page_zap_pte)(void *kvm, void *sp, u64 *sptep, void *list);
static int  (*fn_pte_list_add)(void *cache, u64 *sptep, void *head);
static void (*fn_commit_zap_page)(void *kvm, void *list);
static void (*fn_flush_remote_tlbs)(void *kvm);
static u64  (*fn_make_nonleaf_spte)(u64 *child_pt, bool ad_disabled);
static bool (*fn_sp_ad_disabled)(void *sp);

/* ═══════════════════════════════════════════════════════════════════════
 *  Fix 1: kvm_mmu_get_child_sp() — add role.word comparison
 *  Upstream: 81ccda30b4e8
 * ═══════════════════════════════════════════════════════════════════════ */

static void *
livepatch_kvm_mmu_get_child_sp(void *vcpu, u64 *sptep, unsigned long gfn,
				bool direct, unsigned int access)
{
	u32  role_word = fn_kvm_mmu_child_role(sptep, direct, access);
	void *child;
	u64  spte = *sptep;

	if (fn_is_shadow_present_pte && fn_is_shadow_present_pte(spte) &&
	    fn_is_large_pte && !fn_is_large_pte(spte) &&
	    fn_spte_to_child_sp &&
	    (child = fn_spte_to_child_sp(spte)) != NULL &&
	    read_field(child, gfn_off) == gfn &&
	    read_field(child, role_off) == role_word)
		return ERR_PTR(-EEXIST);

	return fn_get_shadow_page(*(void **)vcpu, vcpu, NULL, gfn, role_word);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Fix 2: __link_shadow_page() — unlink stale SPTE before overwriting
 *  Upstream: 0cb2af2ea66ad
 * ═══════════════════════════════════════════════════════════════════════ */

static void
livepatch___link_shadow_page(void *kvm, void *cache, u64 *sptep,
			       void *sp, bool flush)
{
	u64 spte;

	if (fn_is_shadow_present_pte && fn_is_shadow_present_pte(*sptep)) {
		void *parent_sp = NULL;
		LIST_HEAD(invalid_list);

		if (fn_sptep_to_sp)
			parent_sp = fn_sptep_to_sp(sptep);

		fn_mmu_page_zap_pte(kvm, parent_sp, sptep, &invalid_list);

		if (!list_empty(&invalid_list))
			fn_commit_zap_page(kvm, &invalid_list);
		else
			fn_flush_remote_tlbs(kvm);
	}

	spte = fn_make_nonleaf_spte(*(u64 **)sp,
				     fn_sp_ad_disabled ? fn_sp_ad_disabled(sp) : false);
	WRITE_ONCE(*sptep, spte);
	fn_pte_list_add(cache, sptep, (void *)((char *)sp + 0x0)); /* sp->parent_ptes */
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Livepatch definitions — dynamic: patch what we can resolve
 * ═══════════════════════════════════════════════════════════════════════ */

static struct klp_func funcs[3];  /* up to 2 fixes + sentinel */
static struct klp_object objs[] = {
	{ .name = "kvm", .funcs = funcs },
	{ }
};
static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int __init livepatch_init(void)
{
	int ret, fix_count = 0;

	pr_info("═══════════════════════════════════════════\n");
	pr_info("Januscape (CVE-2026-53359) livepatch\n");
	pr_info("Kernel: %s\n", UTS_RELEASE);
	pr_info("gfn_off=0x%lx  role_off=0x%lx\n", gfn_off, role_off);

	ret = resolve_kln();
	if (ret) { pr_err("kallsyms_lookup_name unavailable\n"); return ret; }

	/* Fix 1: kvm_mmu_get_child_sp — needs all child_role + shadow_page + pte helpers */
	fn_kvm_mmu_child_role = resolve("kvm_mmu_child_role");
	fn_is_shadow_present_pte = resolve("is_shadow_present_pte");
	fn_is_large_pte          = resolve("is_large_pte");
	fn_spte_to_child_sp      = resolve("spte_to_child_sp");

	fn_get_shadow_page = resolve("__kvm_mmu_get_shadow_page");
	if (!fn_get_shadow_page)
		fn_get_shadow_page = resolve("kvm_mmu_get_shadow_page");

	if (fn_kvm_mmu_child_role && fn_get_shadow_page) {
		funcs[fix_count].old_name = "kvm_mmu_get_child_sp";
		funcs[fix_count].new_func = livepatch_kvm_mmu_get_child_sp;
		fix_count++;
		pr_info("  Fix 1: kvm_mmu_get_child_sp (role.word) — 81ccda30b4e8\n");
	} else {
		pr_warn("  Fix 1 skipped: missing kvm_mmu_child_role or shadow page allocator\n");
	}

	/* Fix 2: __link_shadow_page — needs zap_pte + pte_list_add + commit_zap + flush + make_nonleaf */
	fn_sptep_to_sp       = resolve("sptep_to_sp");
	fn_mmu_page_zap_pte  = resolve("mmu_page_zap_pte");
	fn_pte_list_add      = resolve("pte_list_add");
	fn_commit_zap_page   = resolve("kvm_mmu_commit_zap_page");
	if (!fn_commit_zap_page)
		fn_commit_zap_page = resolve("kvm_mmu_commit_zap_page.part.0");
	fn_flush_remote_tlbs = resolve("kvm_flush_remote_tlbs");
	fn_make_nonleaf_spte = resolve("make_nonleaf_spte");
	fn_sp_ad_disabled    = resolve("sp_ad_disabled");

	if (fn_mmu_page_zap_pte && fn_pte_list_add && fn_commit_zap_page &&
	    fn_flush_remote_tlbs && fn_make_nonleaf_spte) {
		funcs[fix_count].old_name = "__link_shadow_page";
		funcs[fix_count].new_func = livepatch___link_shadow_page;
		fix_count++;
		pr_info("  Fix 2: __link_shadow_page (UAF escape)    — 0cb2af2ea66ad\n");
	} else {
		pr_warn("  Fix 2 skipped: missing link_shadow_page helpers\n");
	}

	if (fix_count == 0) {
		pr_err("No fixes could be applied — kernel API not supported\n");
		return -ENOTSUPP;
	}

	ret = klp_enable_patch(&patch);
	if (ret) { pr_err("klp_enable_patch failed: %d\n", ret); return ret; }

	pr_info("PATCH ACTIVE (%d/%d fixes applied)\n", fix_count, 2);
	pr_info("Rollback: echo 0 > /sys/kernel/livepatch/%s/enabled\n", KBUILD_MODNAME);
	pr_info("═══════════════════════════════════════════\n");
	return 0;
}

static void __exit livepatch_exit(void)
{
	pr_info("Module unloaded\n");
}

module_init(livepatch_init);
module_exit(livepatch_exit);
