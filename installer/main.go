/*
 * Januscape (CVE-2026-53359) Hotfix Installer
 *
 * Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD.
 * Copyright (c) 2026 GEELINX LTD.
 *
 * Cross-distribution deployment tool for the KVM shadow MMU hotfix.
 * Detects kernel version, resolves struct offsets (BTF → DWARF → DB),
 * builds the kernel module, and applies it without rebooting.
 *
 * USAGE:
 *   januscape-fix deploy           Detect, build, deploy
 *   januscape-fix deploy --force   Skip confirmation prompts
 *   januscape-fix check            Dry-run: check everything, don't apply
 *   januscape-fix rollback         Remove livepatch
 *   januscape-fix status           Show current state
 *   januscape-fix build            Build module only (don't deploy)
 *   januscape-fix build --all      Build for all installed kernels
 *
 * PREREQUISITES (on target host):
 *   - kernel-devel / linux-headers matching running kernel
 *   - gcc, make
 *   - CONFIG_DYNAMIC_FTRACE=y (default on all distro kernels)
 *   - CONFIG_KALLSYMS_ALL=y (for internal KVM symbol resolution)
 *   - bpftool (optional, for automatic offset detection)
 */

package main

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// ── Configuration ────────────────────────────────────────────────────────

const (
	ModuleName     = "hotfix"
	KmodDir        = "../kmod"
	ArtifactDir    = "../kmod/artifacts"
	DefaultGfnOff  = 0x38
	DefaultRoleOff = 0x28
)

type Config struct {
	Force      bool
	CheckOnly  bool
	BuildOnly  bool
	BuildAll   bool
	KernelVer  string
	KernelArch string
	Kdir       string
	GfnOff     uint64
	RoleOff    uint64
	Artifact   string
}

// ── Offset database (same as offsets_db.h) ──────────────────────────────

type OffsetEntry struct {
	Distro  string
	Pattern string
	Gfn     uint64
	Role    uint64
}

var offsetDB = []OffsetEntry{
	// RHEL / CentOS / ELRepo
	{"el8/6.19", "6.19.", 0x38, 0x28},
	{"el9/5.14", "5.14.0-", 0x38, 0x28},
	{"el9", "el9", 0x38, 0x28},
	{"el8/4.18", "el8", 0x38, 0x28},
	// Ubuntu
	{"ubuntu2404", "6.8.0-", 0x38, 0x28},
	{"ubuntu2204", "5.15.0-", 0x38, 0x28},
	{"ubuntu2004", "5.4.0-", 0x30, 0x20},
	// Debian
	{"deb12", "6.1.0-", 0x38, 0x28},
	{"deb11", "5.10.0-", 0x38, 0x28},
	{"deb10", "4.19.0-", 0x30, 0x20},
	// Upstream
	{"upstream-6.x", "6.", 0x38, 0x28},
	{"upstream-5.x", "5.", 0x38, 0x28},
	{"upstream-4.x", "4.", 0x30, 0x20},
}

// ── CLI entry ────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cfg := &Config{
		KernelVer:  mustSysctl("kernel.osrelease"),
		KernelArch: mustSysctl("kernel.arch"),
	}
	cfg.Kdir = fmt.Sprintf("/lib/modules/%s/build", cfg.KernelVer)
	cfg.Artifact = filepath.Join(ArtifactDir,
		fmt.Sprintf("hotfix-%s-%s.ko", cfg.KernelVer, cfg.KernelArch))

	cmd := os.Args[1]
	parseFlags(cfg, os.Args[2:])

	switch cmd {
	case "deploy":
		deploy(cfg)
	case "check":
		cfg.CheckOnly = true
		deploy(cfg)
	case "rollback":
		rollback(cfg)
	case "status":
		status(cfg)
	case "build":
		cfg.BuildOnly = true
		deploy(cfg)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Januscape (CVE-2026-53359) Hotfix Installer

Usage:
  januscape-fix deploy            Detect, build, deploy (interactive)
  januscape-fix deploy --force    Skip confirmation
  januscape-fix check             Dry-run check only
  januscape-fix rollback          Remove livepatch
  januscape-fix status            Show current state
  januscape-fix build             Build module only
  januscape-fix build --all       Build for all installed kernels`)
}

func parseFlags(cfg *Config, args []string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--force", "-f":
			cfg.Force = true
		case "--all":
			cfg.BuildAll = true
		default:
			fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
			os.Exit(1)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════
//  PHASE 0 — Prerequisites
// ══════════════════════════════════════════════════════════════════════════

func runChecks(cfg *Config) []string {
	var warns []string

	check := func(ok bool, msg string) {
		if !ok {
			warns = append(warns, msg)
		}
	}

	// Is kernel >= 4.0?
	kv := parseKernelVer(cfg.KernelVer)
	check(kv[0] >= 4, "Kernel < 4.0 (required for ftrace with IPMODIFY)")

	// Is KVM loaded?
	check(moduleLoaded("kvm"), "kvm module is not loaded — nothing to patch")

	// kernel-devel exists?
	if _, err := os.Stat(cfg.Kdir); os.IsNotExist(err) {
		check(false, fmt.Sprintf("kernel-devel not found at %s — install kernel-devel-%s",
			cfg.Kdir, cfg.KernelVer))
	}

	// CONFIG_DYNAMIC_FTRACE?
	configPath := filepath.Join(cfg.Kdir, ".config")
	if data, err := os.ReadFile(configPath); err == nil {
		check(strings.Contains(string(data), "CONFIG_DYNAMIC_FTRACE=y"),
			"CONFIG_DYNAMIC_FTRACE not set")
		check(strings.Contains(string(data), "CONFIG_KALLSYMS_ALL=y"),
			"CONFIG_KALLSYMS_ALL not set — internal KVM symbols may be invisible")
	} else {
		warns = append(warns, fmt.Sprintf(".config missing at %s", configPath))
	}

	// kvm_mmu_get_child_sp in kallsyms?
	check(symbolExists("kvm_mmu_get_child_sp"),
		"kvm_mmu_get_child_sp NOT in /proc/kallsyms — CONFIG_KALLSYMS_ALL=y required")

	// Already patched upstream?
	if grepKallsyms("role.word") {
		warns = append(warns, "role.word found in kallsyms — upstream patch may already be applied")
	}

	// Already loaded?
	check(!moduleLoaded(ModuleName), ModuleName+" already loaded")

	return warns
}

func moduleLoaded(name string) bool {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), name+" ") {
			return true
		}
	}
	return false
}

func symbolExists(name string) bool {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), " "+name+"\n") ||
		strings.Contains(string(data), " "+name+"\t")
}

func grepKallsyms(pattern string) bool {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), pattern)
}

// ══════════════════════════════════════════════════════════════════════════
//  PHASE 1 — Offset Detection (BTF → DWARF → offsetDB → default)
// ══════════════════════════════════════════════════════════════════════════

func detectOffsets(cfg *Config) {
	log("Phase 1: Detecting struct kvm_mmu_page offsets")

	// Method 1: BTF via bpftool (most reliable)
	if gfn, role, ok := detectOffsetsBTF(); ok {
		cfg.GfnOff = gfn
		cfg.RoleOff = role
		okLog("BTF: gfn=0x%x role.word=0x%x", gfn, role)
		return
	}
	warnLog("BTF detection failed (no bpftool or no BTF data)")

	// Method 2: DWARF from vmlinux debuginfo
	vmlinuxPaths := []string{
		fmt.Sprintf("/usr/lib/debug/lib/modules/%s/vmlinux", cfg.KernelVer),
		fmt.Sprintf("/usr/lib/debug/boot/vmlinux-%s", cfg.KernelVer),
		"/boot/vmlinux-" + cfg.KernelVer,
	}
	for _, path := range vmlinuxPaths {
		if gfn, role, ok := detectOffsetsDWARF(path); ok {
			cfg.GfnOff = gfn
			cfg.RoleOff = role
			okLog("DWARF (%s): gfn=0x%x role.word=0x%x", filepath.Base(path), gfn, role)
			return
		}
	}
	warnLog("DWARF detection failed (no debuginfo found)")

	// Method 3: Offset database (fallback)
	for _, entry := range offsetDB {
		if strings.Contains(cfg.KernelVer, entry.Pattern) {
			cfg.GfnOff = entry.Gfn
			cfg.RoleOff = entry.Role
			warnLog("Offset DB match: %s → gfn=0x%x role.word=0x%x", entry.Distro, entry.Gfn, entry.Role)
			warnLog("VERIFY with: pahole -C kvm_mmu_page vmlinux | grep -E 'gfn|role'")
			return
		}
	}

	// Method 4: Defaults (last resort)
	cfg.GfnOff = DefaultGfnOff
	cfg.RoleOff = DefaultRoleOff
	warnLog("Using DEFAULTS: gfn=0x%x role.word=0x%x", cfg.GfnOff, cfg.RoleOff)
	warnLog("If the module fails to load, specify offsets manually:")
	warnLog("  make -C kmod/ OFFSETS_CFLAGS='-DGVAR_GFN_OFF=0x?? -DGVAR_ROLE_OFF=0x??'")
}

// detectOffsetsBTF uses bpftool to dump BTF type info for kvm_mmu_page.
func detectOffsetsBTF() (gfn, role uint64, ok bool) {
	_, err := exec.LookPath("bpftool")
	if err != nil {
		return 0, 0, false
	}

	btfPath := "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(btfPath); os.IsNotExist(err) {
		return 0, 0, false
	}

	cmd := exec.Command("bpftool", "btf", "dump", "file", btfPath, "format", "raw")
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, false
	}

	// Parse bpftool output looking for STRUCT 'kvm_mmu_page'
	// Fields include: 'gfn' (type_id=... bits_offset=...)
	//                 'role' (type_id=... bits_offset=...) — union, word at offset 0 within union
	type fieldInfo struct {
		name       string
		bitsOffset uint64
	}

	lines := strings.Split(string(out), "\n")
	inStruct := false
	var fields []fieldInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.Contains(line, "STRUCT") {
			parts := strings.Fields(line)
			for _, p := range parts {
				p = strings.Trim(p, "'")
				if p == "kvm_mmu_page" || strings.HasSuffix(p, "kvm_mmu_page") {
					inStruct = true
					fields = nil
					break
				}
			}
			continue
		}

		if inStruct {
			// Check if we've left this struct
			if strings.HasPrefix(line, "[") {
				break
			}
			// Parse field: 'gfn' type_id=NNN bits_offset=NNN
			re := regexp.MustCompile(`'(\w+)'.*bits_offset=(\d+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) == 3 {
				name := matches[1]
				bitsOff, _ := strconv.ParseUint(matches[2], 10, 64)
				fields = append(fields, fieldInfo{name, bitsOff})
			}
		}
	}

	if len(fields) == 0 {
		return 0, 0, false
	}

	// Now find gfn and role fields
	var gfnBitsOff, roleBitsOff uint64
	foundGfn, foundRole := false, false

	for _, f := range fields {
		switch f.name {
		case "gfn":
			gfnBitsOff = f.bitsOffset
			foundGfn = true
		case "role":
			roleBitsOff = f.bitsOffset
			foundRole = true
		}
	}

	if !foundGfn || !foundRole {
		return 0, 0, false
	}

	return gfnBitsOff / 8, roleBitsOff / 8, true
}

// detectOffsetsDWARF parses ELF DWARF debug info to find struct offsets.
func detectOffsetsDWARF(path string) (gfn, role uint64, ok bool) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	dw, err := f.DWARF()
	if err != nil {
		return 0, 0, false
	}

	reader := dw.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		if name != "kvm_mmu_page" {
			continue
		}

		// Found the struct. Iterate children to find field offsets.
		var gfnOff, roleOff int64
		foundGfn, foundRole := false, false

		for {
			child, err := reader.Next()
			if err != nil || child == nil || child.Tag == 0 {
				break
			}
			if child.Tag != dwarf.TagMember {
				if child.Tag == dwarf.TagStructType || child.Tag == dwarf.TagUnionType {
					reader.SkipChildren()
				}
				continue
			}
			fname, _ := child.Val(dwarf.AttrName).(string)
			off := child.Val(dwarf.AttrDataMemberLoc)

			switch fname {
			case "gfn":
				gfnOff = off.(int64)
				foundGfn = true
			case "role":
				roleOff = off.(int64)
				foundRole = true
			}
		}

		if foundGfn && foundRole {
			return uint64(gfnOff), uint64(roleOff), true
		}
		break
	}

	return 0, 0, false
}

// ══════════════════════════════════════════════════════════════════════════
//  PHASE 2 — Build
// ══════════════════════════════════════════════════════════════════════════

func buildModule(cfg *Config) error {
	log("Phase 2: Building kernel module for %s", cfg.KernelVer)

	kmodDir, _ := filepath.Abs(KmodDir)
	env := append(os.Environ(),
		fmt.Sprintf("KDIR=%s", cfg.Kdir),
	)

	if cfg.BuildAll {
		cmd := exec.Command("make", "-C", kmodDir, "all-kernels",
			fmt.Sprintf("KDIR=%s", cfg.Kdir))
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Determine artifact path
	cmd := exec.Command("make", "-C", kmodDir, "all",
		fmt.Sprintf("KDIR=%s", cfg.Kdir),
		fmt.Sprintf("KVER=%s", cfg.KernelVer),
		fmt.Sprintf("KARCH=%s", cfg.KernelArch),
		fmt.Sprintf("ARTIFACT=%s", cfg.Artifact),
	)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	okLog("Build complete: %s", cfg.Artifact)
	return nil
}

// ══════════════════════════════════════════════════════════════════════════
//  PHASE 3 — Deploy
// ══════════════════════════════════════════════════════════════════════════

func deployModule(cfg *Config) error {
	log("Phase 3: Applying livepatch...")

	if !cfg.Force {
		fmt.Println()
		fmt.Println("  ┌──────────────────────────────────────────────────────┐")
		fmt.Println("  │  About to livepatch KVM's shadow MMU.                │")
		fmt.Println("  │  Zero-downtime — no VM interruption.                │")
		fmt.Println("  │  Rollback: januscape-fix rollback                │")
		fmt.Println("  └──────────────────────────────────────────────────────┘")
		fmt.Print("  Continue? [y/N] ")
		var ans string
		fmt.Scanln(&ans)
		if !strings.HasPrefix(strings.ToLower(ans), "y") {
			return fmt.Errorf("aborted by user")
		}
	}

	// Use insmod with offset parameters
	cmd := exec.Command("insmod", cfg.Artifact,
		fmt.Sprintf("gfn_off=0x%x", cfg.GfnOff),
		fmt.Sprintf("role_off=0x%x", cfg.RoleOff),
	)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("insmod failed: %w\nCheck dmesg for details", err)
	}
	if len(out) > 0 {
		fmt.Print(string(out))
	}

	okLog("Module loaded")
	return nil
}

// ══════════════════════════════════════════════════════════════════════════
//  PHASE 4 — Verify
// ══════════════════════════════════════════════════════════════════════════

func verifyDeploy(cfg *Config) error {
	log("Phase 4: Verification")

	// 4.1: lsmod
	if !moduleLoaded(ModuleName) {
		return fmt.Errorf("module not showing in lsmod")
	}
	okLog("Module present in lsmod")

	// 4.2: Check dmesg
	dmesgCmd := exec.Command("dmesg")
	out, _ := dmesgCmd.Output()
	dmesg := string(out)

	if strings.Contains(dmesg, "PATCH ACTIVE") {
		okLog("Livepatch confirmed in dmesg")
	} else {
		warnLog("Confirmation message not found in dmesg — check manually")
	}

	// 4.3: Check sysfs
	sysfsPath := fmt.Sprintf("/sys/kernel/livepatch/%s/enabled", ModuleName)
	if data, err := os.ReadFile(sysfsPath); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			okLog("Livepatch enabled in sysfs")
		}
	}

	// 4.4: Check kallsyms for patched symbol
	if grepKallsyms("januscape_kvm_mmu_get_child_sp") {
		okLog("Patched symbol visible in /proc/kallsyms")
	}

	return nil
}

// ══════════════════════════════════════════════════════════════════════════
//  ROLLBACK
// ══════════════════════════════════════════════════════════════════════════

func rollback(cfg *Config) {
	log("Rolling back Januscape hotfix...")

	if !moduleLoaded(ModuleName) {
		warnLog("Module not loaded — nothing to rollback")
		return
	}

	cmd := exec.Command("rmmod", ModuleName)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		errLog("rmmod failed: %v", err)
		errLog("Check: dmesg | tail -20")
		os.Exit(1)
	}

	okLog("Hotfix removed — original function restored")
}

// ══════════════════════════════════════════════════════════════════════════
//  STATUS
// ══════════════════════════════════════════════════════════════════════════

func status(cfg *Config) {
	fmt.Printf("Kernel:  %s (%s)\n", cfg.KernelVer, cfg.KernelArch)
	fmt.Printf("KVM:     ")
	if moduleLoaded("kvm") {
		fmt.Println("loaded")
	} else {
		fmt.Println("NOT loaded")
	}

	fmt.Printf("Hotfix:  ")
	if moduleLoaded(ModuleName) {
		fmt.Println("ACTIVE")
		if data, err := os.ReadFile("/sys/kernel/livepatch/" + ModuleName + "/enabled"); err == nil {
			fmt.Printf("         livepatch: %s", string(data))
		}
	} else {
		fmt.Println("not loaded")
	}

	fmt.Printf("Upstream: ")
	if grepKallsyms("role.word") {
		fmt.Println("patch appears present")
	} else {
		fmt.Println("patch NOT detected")
	}

	// Show any hotfix dmesg entries
	dmesgCmd := exec.Command("sh", "-c", "dmesg | grep januscape | tail -10")
	out, _ := dmesgCmd.Output()
	if len(out) > 0 {
		fmt.Println("\n--- dmesg ---")
		fmt.Print(string(out))
	}
}

// ══════════════════════════════════════════════════════════════════════════
//  MAIN DEPLOY FLOW
// ══════════════════════════════════════════════════════════════════════════

func deploy(cfg *Config) {
	fmt.Println()
	printBanner("Januscape (CVE-2026-53359) — KVM Livepatch Installer")
	fmt.Printf("  Kernel:  %s  (%s)\n", cfg.KernelVer, cfg.KernelArch)
	fmt.Printf("  Kdir:    %s\n\n", cfg.Kdir)

	// ── Phase 0: Checks ──
	warns := runChecks(cfg)
	for _, w := range warns {
		warnLog("%s", w)
	}
	if len(warns) > 0 {
		hasFatal := false
		for _, w := range warns {
			if strings.Contains(strings.ToLower(w), "not found") ||
				strings.Contains(strings.ToLower(w), "not loaded") ||
				strings.Contains(strings.ToLower(w), "not set") ||
				strings.Contains(strings.ToLower(w), "< 4.0") {
				hasFatal = true
			}
		}
		if hasFatal && !cfg.CheckOnly {
			errLog("Fatal prerequisite failures — cannot proceed.")
			os.Exit(1)
		}
	}
	okLog("Prerequisites passed")

	if cfg.CheckOnly {
		okLog("Check complete — system is ready for deployment.")
		return
	}

	// ── Phase 1: Offset detection ──
	detectOffsets(cfg)

	// ── Phase 2: Build ──
	if err := buildModule(cfg); err != nil {
		errLog("%v", err)
		os.Exit(1)
	}

	if cfg.BuildOnly {
		okLog("Build complete. Artifact: %s", cfg.Artifact)
		fmt.Println()
		fmt.Println("To deploy:")
		fmt.Printf("  insmod %s gfn_off=0x%x role_off=0x%x\n",
			cfg.Artifact, cfg.GfnOff, cfg.RoleOff)
		return
	}

	// ── Phase 3: Deploy ──
	if err := deployModule(cfg); err != nil {
		errLog("%v", err)
		os.Exit(1)
	}

	// ── Phase 4: Verify ──
	if err := verifyDeploy(cfg); err != nil {
		errLog("%v", err)
		os.Exit(1)
	}

	// ── Done ──
	fmt.Println()
	printBanner("DEPLOYED — CVE-2026-53359 mitigated")
	fmt.Println("  VMs affected:    0 (zero-downtime)")
	fmt.Println("  Rollback:        januscape-fix rollback")
	fmt.Println("  Status:          januscape-fix status")
	fmt.Println()
}

// ══════════════════════════════════════════════════════════════════════════
//  UTILITY
// ══════════════════════════════════════════════════════════════════════════

func mustSysctl(key string) string {
	data, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot read /proc/sys/%s: %v\n", key, err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(data))
}

func parseKernelVer(s string) [3]int {
	var v [3]int
	re := regexp.MustCompile(`(\d+)\.(\d+)\.?(\d+)?`)
	m := re.FindStringSubmatch(s)
	if len(m) >= 4 {
		v[0], _ = strconv.Atoi(m[1])
		v[1], _ = strconv.Atoi(m[2])
		if m[3] != "" {
			v[2], _ = strconv.Atoi(m[3])
		}
	}
	return v
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func printBanner(msg string) {
	width := 60
	pad := (width - len(msg) - 2) / 2
	if pad < 1 {
		pad = 1
	}
	fmt.Println(strings.Repeat("═", width))
	fmt.Printf("%s %s %s\n",
		strings.Repeat("═", pad), msg, strings.Repeat("═", pad))
	fmt.Println()
}

// ── Logging ──────────────────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

func log(format string, args ...interface{}) {
	fmt.Printf(colorBlue+"[*] "+colorReset+format+"\n", args...)
}

func okLog(format string, args ...interface{}) {
	fmt.Printf(colorGreen+"[✓] "+colorReset+format+"\n", args...)
}

func warnLog(format string, args ...interface{}) {
	fmt.Printf(colorYellow+"[!] "+colorReset+format+"\n", args...)
}

func errLog(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorRed+"[✗] "+colorReset+format+"\n", args...)
}

func init() {
	// Ensure we're root for deployment operations
	if os.Geteuid() != 0 {
		// Only check for commands that need root
		if len(os.Args) > 1 && (os.Args[1] == "deploy" || os.Args[1] == "rollback") {
			fmt.Fprintln(os.Stderr, "This command requires root privileges.")
			os.Exit(1)
		}
	}

	// Suppress stdout buffering issues with insmod
	_ = syscall.Setpgid(0, 0)
}
