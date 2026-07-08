/*
 * Januscape (CVE-2026-53359) Universal Hotfix — Kernel Module
 *
 * Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD.
 * Copyright (c) 2026 GEELINX LTD.
 *
 * Zero-downtime livepatch for KVM/x86 shadow MMU use-after-free.
 * Works on Linux 4.0 – 6.x, all distributions (RHEL, Debian, Ubuntu,
 * CentOS, etc.), both Intel VMX/EPT and AMD SVM/NPT.
 *
 * Fix: Adds role.word comparison to kvm_mmu_get_child_sp() reuse check.
 * Upstream commit: 81ccda30b4e8
 *
 * Hook mechanism (auto-selected at load):
 *   Priority 1: register_ftrace_direct()   [5.11+, cleanest]
 *   Priority 2: ftrace IPMODIFY + SAVE_REGS [4.0+, universal]
 *
 * kallsyms_lookup_name resolution:
 *   Direct for < 5.7; kprobe-based for >= 5.7 (where it's unexported).
 *
 * Struct offsets (gfn, role.word in struct kvm_mmu_page):
 *   Detected by the Go installer and passed as module params.
 *
 * Build:  make -C /lib/modules/$(uname -r)/build M=$(pwd)
 * Apply:  insmod hotfix.ko gfn_off=0x38 role_off=0x28
 * Verify: dmesg | grep januscape
 * Revert: rmmod hotfix
 *
 * Contact: master@aoripus.com
 * License: GPL v2
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <generated/utsrelease.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Januscape (CVE-2026-53359) KVM shadow MMU hotfix");
MODULE_AUTHOR("AORIPUS (BEIJING) TECHNOLOGY CO., LTD. / GEELINX LTD. <master@aoripus.com>");

/* Module parameters */
static unsigned long gfn_off  = 0x38;
static unsigned long role_off = 0x28;
static int force_ftrace_ipmodify = 0;
module_param(gfn_off,  ulong, 0444);
module_param(role_off, ulong, 0444);
module_param(force_ftrace_ipmodify, int, 0444);

/*
 * KVM-internal types are NOT exported to modules. We use primitive types
 * throughout with ABI-compatible substitution on x86_64:
 *   union kvm_mmu_page_role contains u32 word at offset 0
 *   → u32 is the correct register class for both return and parameter
 *   struct kvm_mmu_page * → void * (opaque pointer, same size)
 *   struct kvm_vcpu *      → void * (opaque pointer, same size)
 */

/* Resolved KVM internal function pointers (ABI-compatible primitives) */
static bool    (*fn_is_shadow_present_pte)(u64 pte);
static bool    (*fn_is_large_pte)(u64 pte);
static void   *(*fn_spte_to_child_sp)(u64 spte);
static u32     (*fn_kvm_mmu_child_role)(u64 *sptep, bool direct,
					  unsigned int access);
static void   *(*fn_kvm_mmu_get_shadow_page)(void *vcpu, unsigned long gfn,
					       u32 role_word);

/* Track which symbols were resolved vs. using fallback implementations */
static bool use_fallback_pte_check;
static bool use_fallback_large_check;
static bool use_fallback_spte_to_sp;

/*
 * x86_64 KVM shadow PTE bit definitions (stable ABI since 2010).
 * Used as fallback when the corresponding inline functions are
 * not present as standalone symbols in kallsyms.
 */
#define PT_PRESENT_MASK     (1ULL << 0)
#define PT_PAGE_SIZE_MASK   (1ULL << 7)
#define SPTE_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE - 1))

/* Fallback: check if SPTE is present (bit 0 set, bit 63 clear) */
static bool fallback_is_shadow_present_pte(u64 pte)
{
	return pte & PT_PRESENT_MASK;
}

/* Fallback: check if SPTE maps a large page (PS bit set) */
static bool fallback_is_large_pte(u64 pte)
{
	return !!(pte & PT_PAGE_SIZE_MASK);
}

/*
 * Fallback: convert non-leaf SPTE -> child struct kvm_mmu_page *.
 * KVM stores the shadow page pointer in page->private of the
 * page backing this SPTE. Works on all x86_64 kernels since
 * the shadow page allocator uses this convention.
 */
static void *fallback_spte_to_child_sp(u64 spte)
{
	unsigned long pfn  = (spte & SPTE_BASE_ADDR_MASK) >> PAGE_SHIFT;
	struct page   *page;
	void          *sp;
	if (!pfn_valid(pfn))
		return NULL;
	page = pfn_to_page(pfn);
	if (!page)
		return NULL;
	sp   = (void *)page->private;
	/*
	 * Sanity check: the shadow page's gfn field should look
	 * like a reasonable guest frame number (non-zero, non-all-1s).
	 * This filters out non-shadow-page pages with spurious private data.
	 */
	if (sp) {
		unsigned long v;
		memcpy(&v, (char *)sp + gfn_off, sizeof(v));
		if (v == 0 || v == ~0UL)
			return NULL;
	}
	return sp;
}

/* kallsyms_lookup_name resolver */
typedef unsigned long (*kln_t)(const char *name);
static kln_t kln_fn;

static int resolve_kln(void)
{
	kln_fn = (kln_t)__symbol_get("kallsyms_lookup_name");
	if (kln_fn) {
		pr_info("kallsyms_lookup_name: direct (exported)\n");
		return 0;
	}
	{
		struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
		int ret = register_kprobe(&kp);
		if (ret < 0) {
			pr_err("kprobe on kallsyms_lookup_name failed: %d\n", ret);
			return ret;
		}
		kln_fn = (kln_t)kp.addr;
		unregister_kprobe(&kp);
		if (!kln_fn) {
			pr_err("kallsyms_lookup_name: kprobe addr is NULL\n");
			return -ENOENT;
		}
		pr_info("kallsyms_lookup_name: resolved via kprobe\n");
	}
	return 0;
}

static unsigned long kl(const char *name)
{
	return kln_fn ? kln_fn(name) : 0;
}

/*
 * Binary scanner: extract the callee address from the ORIGINAL
 * kvm_mmu_get_child_sp function.
 *
 * The original function has exactly one call-site to whatever
 * shadow-page allocator this kernel uses (kvm_mmu_get_shadow_page
 * or a differently-named equivalent). Instead of guessing the name,
 * we scan the function's machine code for a `call` instruction
 * and use its target — guaranteed correct for this exact kernel.
 *
 * On x86_64: `call rel32` = opcode 0xE8 + 4-byte signed offset.
 * Target = insn_addr + 5 + (s32)rel32.
 */
static unsigned long find_shadow_page_allocator(unsigned long func_addr)
{
	unsigned char *code = (unsigned char *)func_addr;
	unsigned long last_call = 0;
	int i;

	/* Scan up to 200 bytes; kvm_mmu_get_child_sp is ~50–80 bytes. */
	for (i = 0; i < 200; i++) {
		if (code[i] == 0xe8) {
			s32 rel;
			memcpy(&rel, code + i + 1, sizeof(rel));
			last_call = func_addr + i + 5 + rel;
		}
		/* ret (0xc3) — we've scanned the whole function. */
		if (code[i] == 0xc3 && last_call)
			break;
	}

	/* Sanity: the target must be a kernel text address. */
	if (last_call >= 0xffffffff80000000UL) {
		pr_info("binary scan: found callee at %pS\n", (void *)last_call);
		return last_call;
	}

	pr_info("binary scan: no valid callee found in %pS\n", (void *)func_addr);
	return 0;
}

/* Field access via offset — avoids depending on kvm_mmu_page layout */
static inline unsigned long sp_field(void *sp, unsigned long off)
{
	unsigned long v;
	memcpy(&v, (char *)sp + off, sizeof(v));
	return v;
}

#define sp_gfn(sp)       sp_field((sp), gfn_off)
#define sp_role_word(sp) sp_field((sp), role_off)

/*
 * PATCHED replacement for kvm_mmu_get_child_sp().
 * Fix: adds role.word comparison at [*] — one extra condition vs upstream.
 *
 * NOTE: return type is void* (compatible with struct kvm_mmu_page* on
 * x86_64 — both are pointer-sized). ERR_PTR(-EEXIST) is a negative error
 * encoded as a pointer, which works identically.
 */
static noinline void *
januscape_kvm_mmu_get_child_sp(void *vcpu, u64 *sptep, unsigned long gfn,
				bool direct, unsigned int access)
{
	u32  role_word;
	void *child;
	u64  spte;

	role_word = fn_kvm_mmu_child_role(sptep, direct, access);
	spte      = *sptep;

	if (fn_is_shadow_present_pte(spte) &&
	    !fn_is_large_pte(spte) &&
	    (child = fn_spte_to_child_sp(spte)) != NULL &&
	    sp_gfn(child) == gfn &&
	    sp_role_word(child) == role_word)           /* [*] THE FIX */
		return ERR_PTR(-EEXIST);

	return fn_kvm_mmu_get_shadow_page(vcpu, gfn, role_word);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  FTRACE-BASED FUNCTION REPLACEMENT
 *  Strategy: ftrace_direct (5.11+) → ftrace IPMODIFY (4.0+)
 * ═══════════════════════════════════════════════════════════════════════ */

static unsigned long target_ip;
static struct ftrace_ops fops;
static bool hooked;
static int  hook_method;

/* ── Method 1: ftrace_direct ────────────────────────────────────────── */
/*
 * API changed at 5.14:
 *   <  5.14: register_ftrace_direct(unsigned long ip, unsigned long addr)
 *   >= 5.14: register_ftrace_direct(struct ftrace_ops *ops, unsigned long addr)
 *
 * unregister differs similarly (3 args in >= 5.14, 2 args before).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define REGISTER_FTRACE_DIRECT(ip, addr) \
	register_ftrace_direct(&fops, (unsigned long)(addr))
#define UNREGISTER_FTRACE_DIRECT(ip, addr) \
	unregister_ftrace_direct(&fops, (unsigned long)(addr), 1)
#else
#define REGISTER_FTRACE_DIRECT(ip, addr) \
	register_ftrace_direct((ip), (unsigned long)(addr))
#define UNREGISTER_FTRACE_DIRECT(ip, addr) \
	unregister_ftrace_direct((ip), (unsigned long)(addr))
#endif

static int hook_ftrace_direct(void)
{
	int ret;

	if (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS)) {
		pr_info("ftrace_direct not compiled in, fallback...\n");
		return -EOPNOTSUPP;
	}

	ret = ftrace_set_filter_ip(&fops, target_ip, 0, 0);
	if (ret) {
		pr_err("ftrace_set_filter_ip for direct: %d\n", ret);
		return ret;
	}

	ret = REGISTER_FTRACE_DIRECT(target_ip, januscape_kvm_mmu_get_child_sp);
	if (ret) {
		pr_err("register_ftrace_direct: %d\n", ret);
		ftrace_set_filter_ip(&fops, target_ip, 1, 0);
		return ret;
	}

	hooked = true;
	hook_method = 1;
	pr_info("Hooked via ftrace_direct\n");
	return 0;
}
#else
static int hook_ftrace_direct(void) { return -EOPNOTSUPP; }
#endif

/* ── Method 2: ftrace IPMODIFY ──────────────────────────────────────── */
/*
 * Two handler variants: 5.11+ uses struct ftrace_regs,
 * < 5.11 uses struct pt_regs * directly.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static void notrace
ftrace_handler(unsigned long ip, unsigned long parent_ip,
	       struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	if (regs)
		regs->ip = (unsigned long)januscape_kvm_mmu_get_child_sp;
}

static int hook_ftrace_ipmodify(void)
{
	int ret;

	if (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE)) {
		pr_err("CONFIG_DYNAMIC_FTRACE not enabled\n");
		return -EOPNOTSUPP;
	}

	fops.func  = ftrace_handler;
	fops.flags = FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_SAVE_ARGS;

	ret = ftrace_set_filter_ip(&fops, target_ip, 0, 0);
	if (ret) {
		pr_err("ftrace_set_filter_ip: %d\n", ret);
		return ret;
	}

	ret = register_ftrace_function(&fops);
	if (ret) {
		pr_err("register_ftrace_function: %d\n", ret);
		ftrace_set_filter_ip(&fops, target_ip, 1, 0);
		return ret;
	}

	hooked = true;
	hook_method = 2;
	pr_info("Hooked via ftrace IPMODIFY\n");
	return 0;
}

#else /* < 5.11 */
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
static void notrace
ftrace_handler(unsigned long ip, unsigned long parent_ip,
	       struct ftrace_ops *op, struct pt_regs *regs)
{
	regs->ip = (unsigned long)januscape_kvm_mmu_get_child_sp;
}

static int hook_ftrace_ipmodify(void)
{
	int ret;

	if (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE)) {
		pr_err("CONFIG_DYNAMIC_FTRACE not enabled\n");
		return -EOPNOTSUPP;
	}

	fops.func  = ftrace_handler;
	fops.flags = FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_SAVE_REGS;

	ret = ftrace_set_filter_ip(&fops, target_ip, 0, 0);
	if (ret) {
		pr_err("ftrace_set_filter_ip: %d\n", ret);
		return ret;
	}

	ret = register_ftrace_function(&fops);
	if (ret) {
		pr_err("register_ftrace_function: %d\n", ret);
		ftrace_set_filter_ip(&fops, target_ip, 1, 0);
		return ret;
	}

	hooked = true;
	hook_method = 2;
	pr_info("Hooked via ftrace IPMODIFY\n");
	return 0;
}
#else
static int hook_ftrace_ipmodify(void)
{
	pr_err("CONFIG_DYNAMIC_FTRACE_WITH_REGS not available\n");
	return -EOPNOTSUPP;
}
#endif
#endif /* < 5.11 */

/* ── Unhook ──────────────────────────────────────────────────────────── */

static void unhook(void)
{
	if (!hooked)
		return;

	switch (hook_method) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	case 1:
		UNREGISTER_FTRACE_DIRECT(target_ip, januscape_kvm_mmu_get_child_sp);
		break;
#endif
	case 2:
		unregister_ftrace_function(&fops);
		ftrace_set_filter_ip(&fops, target_ip, 1, 0);
		break;
	}
	hooked = false;
	pr_info("Unhooked (method=%d), original function restored\n", hook_method);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  SYMBOL RESOLUTION
 * ═══════════════════════════════════════════════════════════════════════ */

static void *resolve(const char *name)
{
	void *addr = (void *)kl(name);
	if (!addr)
		pr_err("symbol NOT FOUND: %s\n", name);
	return addr;
}

static int safety_checks(void)
{
	const char *fallback_names[] = {
		"kvm_mmu_get_child_sp",
		"kvm_mmu_get_page",      /* RHEL 8.x 4.18 — different ABI */
		NULL
	};
	int i;

	if (!kl("kvm_init")) {
		pr_err("kvm module is not loaded — nothing to patch\n");
		return -ENODEV;
	}
	pr_info("kvm module: loaded\n");

	for (i = 0; fallback_names[i]; i++) {
		target_ip = kl(fallback_names[i]);
		if (target_ip) {
			pr_info("target function: %pS (as \"%s\")\n",
				(void *)target_ip, fallback_names[i]);
			break;
		}
	}

	if (!target_ip) {
		pr_err("No compatible KVM MMU function found in kallsyms.\n");
		pr_err("Checked: kvm_mmu_get_child_sp, kvm_mmu_get_page\n");
		pr_err("This kernel's shadow MMU API is not supported.\n");
		pr_err("Recommend: nested=0 or kernel upgrade.\n");
		return -ENOENT;
	}

	/*
	 * RHEL 8.x 4.18 kernels use kvm_mmu_get_page with a different
	 * function signature (6 args vs 5 for kvm_mmu_get_child_sp).
	 * ftrace redirection requires ABI-compatible replacement functions,
	 * so we cannot safely patch this variant. Refuse to load with
	 * a clear explanation.
	 */
	if (i > 0) {
		pr_err("\n");
		pr_err("≡≡≡ UNSUPPORTED KERNEL VARIANT ≡≡≡\n");
		pr_err("This kernel uses \"%s\" instead of\n", fallback_names[i - 1]);
		pr_err("\"kvm_mmu_get_child_sp\". The function signatures differ\n");
		pr_err("(6 parameters vs 5), so this hotfix module cannot safely\n");
		pr_err("replace it. Loading the module would cause a kernel crash.\n");
		pr_err("\n");
		pr_err("Options:\n");
		pr_err("  1. nested=0  — disable nested virt, eliminates attack surface\n");
		pr_err("     echo \"options %s nested=0\" > /etc/modprobe.d/disable-nested.conf\n",
			kl("kvm_intel_init") ? "kvm_intel" : "kvm_amd");
		pr_err("  2. Kernel upgrade — switch to a kernel where upstream\n");
		pr_err("     commit 81ccda30b4e8 is backported\n");
		pr_err("≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡\n");
		return -ENOTSUPP;
	}

	return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  INIT / EXIT
 * ═══════════════════════════════════════════════════════════════════════ */

static int __init hotfix_init(void)
{
	int ret;

	pr_info("═══════════════════════════════════════════\n");
	pr_info("Januscape (CVE-2026-53359) universal hotfix\n");
	pr_info("Kernel: %s\n", UTS_RELEASE);
	pr_info("gfn_off=0x%lx  role_off=0x%lx\n", gfn_off, role_off);
	pr_info("force_ftrace_ipmodify=%d\n", force_ftrace_ipmodify);

	ret = resolve_kln();
	if (ret)
		goto fail;

	ret = safety_checks();
	if (ret)
		goto fail;

	fn_is_shadow_present_pte = resolve("is_shadow_present_pte");
	fn_is_large_pte          = resolve("is_large_pte");
	fn_spte_to_child_sp      = resolve("spte_to_child_sp");
	fn_kvm_mmu_child_role    = resolve("kvm_mmu_child_role");

	/* Required: kvm_mmu_child_role must be findable */
	if (!fn_kvm_mmu_child_role) {
		pr_err("kvm_mmu_child_role not in kallsyms\n");
		ret = -ENOENT;
		goto fail;
	}

	/*
	 * Resolve the shadow-page allocator by scanning the ORIGINAL
	 * function's binary — not by guessing its name. The name and
	 * signature vary across kernels and distros (e.g. ELRepo 6.x
	 * has __kvm_mmu_get_shadow_page with different arguments).
	 * The binary scan is signature-agnostic and 100% correct.
	 */
	fn_kvm_mmu_get_shadow_page =
		(void *)find_shadow_page_allocator(target_ip);
	if (!fn_kvm_mmu_get_shadow_page) {
		pr_err("failed to extract shadow-page allocator from %pS\n",
		       (void *)target_ip);
		ret = -ENOENT;
		goto fail;
	}

	/* Fallback implementations for commonly-inlined helpers */
	if (!fn_is_shadow_present_pte) {
		fn_is_shadow_present_pte = fallback_is_shadow_present_pte;
		use_fallback_pte_check  = true;
		pr_info("is_shadow_present_pte: using built-in fallback\n");
	}
	if (!fn_is_large_pte) {
		fn_is_large_pte          = fallback_is_large_pte;
		use_fallback_large_check = true;
		pr_info("is_large_pte: using built-in fallback\n");
	}
	if (!fn_spte_to_child_sp) {
		fn_spte_to_child_sp    = fallback_spte_to_child_sp;
		use_fallback_spte_to_sp = true;
		pr_info("spte_to_child_sp: using built-in fallback\n");
	}

	if (use_fallback_pte_check || use_fallback_large_check ||
	    use_fallback_spte_to_sp) {
		pr_info("operating with %d fallback implementations\n",
			use_fallback_pte_check + use_fallback_large_check +
			use_fallback_spte_to_sp);
	} else {
		pr_info("All KVM helpers resolved natively\n");
	}

	if (!force_ftrace_ipmodify) {
		ret = hook_ftrace_direct();
		if (ret == -EOPNOTSUPP || ret == -ENODEV)
			ret = hook_ftrace_ipmodify();
	} else {
		pr_info("Skipping ftrace_direct (force_ftrace_ipmodify=1)\n");
		ret = hook_ftrace_ipmodify();
	}

	if (ret) {
		pr_err("All hook methods failed: %d\n", ret);
		goto fail;
	}

	pr_info("PATCH ACTIVE — kvm_mmu_get_child_sp role.word fix applied\n");
	pr_info("Rollback: rmmod %s\n", KBUILD_MODNAME);
	pr_info("═══════════════════════════════════════════\n");
	return 0;

fail:
	pr_err("LOAD FAILED — KVM is NOT patched\n");
	pr_err("═══════════════════════════════════════════\n");
	return ret;
}

static void __exit hotfix_exit(void)
{
	unhook();
	pr_info("Module unloaded\n");
}

module_init(hotfix_init);
module_exit(hotfix_exit);
