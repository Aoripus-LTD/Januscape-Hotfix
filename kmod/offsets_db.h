/*
 * Januscape Hotfix — Struct kvm_mmu_page Offset Database
 *
 * Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD.
 * Copyright (c) 2026 GEELINX LTD.
 *
 * This file provides fallback offset values when BTF/DWARF debug
 * information is not available on the target machine.
 *
 * PRIMARY DETECTION:   Go installer extracts offsets from BTF/DWARF.
 * FALLBACK:            This database (looked up by kernel version).
 * LAST RESORT:         Module default params (gfn=0x38, role=0x28).
 *
 * LAYOUT NOTE: struct kvm_mmu_page is defined in
 *   arch/x86/kvm/mmu/mmu_internal.h (6.x) or
 *   arch/x86/include/asm/kvm_host.h (4.x/5.x).
 *
 * Fields we need:
 *   gfn        (gfn_t = unsigned long, 8 bytes on x86_64)
 *   role.word  (unsigned long, 8 bytes within union kvm_mmu_page_role)
 *
 * TO VERIFY on a specific kernel:
 *   pahole -C kvm_mmu_page /usr/lib/debug/lib/modules/$(uname -r)/vmlinux
 *   bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A 80 'STRUCT.*kvm_mmu_page'
 *
 * Add new entries for unsupported kernels as needed.
 */

#ifndef JANUSCAPE_OFFSETS_DB_H
#define JANUSCAPE_OFFSETS_DB_H

struct offset_entry {
	const char *distro;      /* e.g. "el8", "deb11", "ubuntu2204" */
	const char *vermagic;    /* kernel version substring to match   */
	unsigned long gfn;       /* offset of kvm_mmu_page->gfn       */
	unsigned long role;      /* offset of kvm_mmu_page->role.word */
};

/*
 * Database of verified offsets.
 * Entries are matched by substring of the kernel release string.
 * First match wins.
 *
 * ⚠ WARNING: These are best-effort values. Always prefer BTF detection.
 * ⚠ Layout may differ with backported patches or config changes.
 * ⚠ RHEL backports can change struct layout relative to upstream.
 */
static const struct offset_entry offset_db[] = {

	/* ── RHEL / CentOS / ELRepo ─────────────────────────────────── */

	/* ELRepo 6.19 ML (Feb 2026) */
	{ "el8/6.19",     "6.19.",   0x38, 0x28 },
	/* RHEL 9.4 (5.14.0-427) */
	{ "el9/5.14",     "5.14.0-", 0x38, 0x28 },
	/* RHEL 9.x */
	{ "el9/5.14",     "el9",      0x38, 0x28 },
	/* RHEL 8.8 (4.18.0-477) */
	{ "el8/4.18",     "el8",      0x38, 0x28 },
	/* RHEL 7.9 (3.10.0-1160) — not supported (too old, lacks ftrace_regs) */

	/* ── Ubuntu ──────────────────────────────────────────────────── */

	/* Ubuntu 24.04 (6.8) */
	{ "ubuntu2404",   "6.8.0-",   0x38, 0x28 },
	/* Ubuntu 22.04 (5.15) */
	{ "ubuntu2204",   "5.15.0-",  0x38, 0x28 },
	/* Ubuntu 20.04 (5.4) */
	{ "ubuntu2004",   "5.4.0-",   0x30, 0x20 },

	/* ── Debian ──────────────────────────────────────────────────── */

	/* Debian 12 (6.1) */
	{ "deb12",        "6.1.0-",   0x38, 0x28 },
	/* Debian 11 (5.10) */
	{ "deb11",        "5.10.0-",  0x38, 0x28 },
	/* Debian 10 (4.19) */
	{ "deb10",        "4.19.0-",  0x30, 0x20 },

	/* ── Upstream (vanilla) ──────────────────────────────────────── */

	/* Upstream 6.x (6.0 – 6.12) */
	{ "upstream-6.x", "6.",       0x38, 0x28 },
	/* Upstream 5.x (5.0 – 5.19) */
	{ "upstream-5.x", "5.",       0x38, 0x28 },
	/* Upstream 4.x (4.0 – 4.20) */
	{ "upstream-4.x", "4.",       0x30, 0x20 },

	/* ── Sentinel ────────────────────────────────────────────────── */

	{ NULL, NULL, 0, 0 },
};

#endif /* JANUSCAPE_OFFSETS_DB_H */
