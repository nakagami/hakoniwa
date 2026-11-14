/*
MIT License

Copyright (c) 2026 Hajime Nakagami<nakagami@mail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	PR_SET_NO_NEW_PRIVS = 38
	PR_SET_SECCOMP      = 22
	SECCOMP_MODE_FILTER = 2

	BPF_LD  = 0x00
	BPF_W   = 0x00
	BPF_ABS = 0x20
	BPF_JMP = 0x05
	BPF_JEQ = 0x10
	BPF_K   = 0x00
	BPF_RET = 0x06

	SECCOMP_RET_ALLOW = 0x7fff0000
	SECCOMP_RET_ERRNO = 0x00050000
)

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// disableChroot disables the chroot syscall using seccomp BPF filter.
func disableChroot() error {
	var chrootSyscall uint32
	switch runtime.GOARCH {
	case "amd64":
		chrootSyscall = 161
	case "arm64":
		chrootSyscall = 51
	case "386":
		chrootSyscall = 61
	case "arm":
		chrootSyscall = 61
	default:
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0)
	if errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %v", errno)
	}

	filter := []sockFilter{
		// Load syscall number (offset 0 in struct seccomp_data)
		{code: BPF_LD | BPF_W | BPF_ABS, k: 0},
		// If SYS_chroot, jump to ERRNO (1 step forward)
		{code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 1, k: chrootSyscall},
		// Return EPERM (Operation not permitted)
		{code: BPF_RET | BPF_K, k: SECCOMP_RET_ERRNO | uint32(syscall.EPERM)},
		// Allow all other syscalls
		{code: BPF_RET | BPF_K, k: SECCOMP_RET_ALLOW},
	}

	prog := sockFprog{
		len:    uint16(len(filter)),
		filter: &filter[0],
	}

	_, _, errno = syscall.RawSyscall(syscall.SYS_PRCTL, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return fmt.Errorf("prctl(PR_SET_SECCOMP): %v", errno)
	}
	return nil
}

func main() {
	var (
		initMode  bool
		origUID   int
		origGID   int
		origHome  string
		origShell string
		origUser  string
		origCWD   string
	)

	flag.BoolVar(&initMode, "init", false, "internal init mode")
	flag.IntVar(&origUID, "uid", 0, "original UID")
	flag.IntVar(&origGID, "gid", 0, "original GID")
	flag.StringVar(&origHome, "home", "", "original HOME")
	flag.StringVar(&origShell, "shell", "", "original SHELL")
	flag.StringVar(&origUser, "user", "", "original USER")
	flag.StringVar(&origCWD, "cwd", "", "original CWD")
	flag.Parse()

	if initMode {
		runInNamespace(origUID, origGID, origHome, origShell, origUser, origCWD)
		return
	}

	// 1. If not running as root, re-execute via sudo
	if os.Geteuid() != 0 {
		exe, err := os.Executable()
		if err != nil {
			exe = os.Args[0]
		}
		exe, _ = filepath.Abs(exe)

		currentUser, _ := user.Current()
		uID := os.Getuid()
		gID := os.Getgid()
		home := os.Getenv("HOME")
		sh := os.Getenv("SHELL")
		uName := os.Getenv("USER")
		if currentUser != nil {
			if home == "" {
				home = currentUser.HomeDir
			}
			if uName == "" {
				uName = currentUser.Username
			}
		}
		if sh == "" {
			sh = "/bin/bash"
		}
		cwd, _ := os.Getwd()

		args := []string{
			exe,
			"-uid", strconv.Itoa(uID),
			"-gid", strconv.Itoa(gID),
			"-home", home,
			"-shell", sh,
			"-user", uName,
			"-cwd", cwd,
		}

		cmd := exec.Command("sudo", args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			os.Exit(1)
		}
		return
	}

	// 2. We are root. Spawn child with a new Mount Namespace (CLONE_NEWNS)
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}

	childArgs := []string{
		"-init",
		"-uid", strconv.Itoa(origUID),
		"-gid", strconv.Itoa(origGID),
		"-home", origHome,
		"-shell", origShell,
		"-user", origUser,
		"-cwd", origCWD,
	}

	cmd := exec.Command(exe, childArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS,
	}

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func runInNamespace(uid, gid int, home, shell, username, cwd string) {
	// Make all mounts private to prevent host namespace pollution
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Fprintf(os.Stderr, "failed to make / private: %v\n", err)
		os.Exit(1)
	}

	// Create temporary directory for tmpfs and overlayfs
	tmpDir, err := os.MkdirTemp("/tmp", "hakoniwa-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = syscall.Unmount(filepath.Join(tmpDir, "merged", "dev", "pts"), syscall.MNT_DETACH)
		_ = syscall.Unmount(filepath.Join(tmpDir, "merged", "dev"), syscall.MNT_DETACH)
		_ = syscall.Unmount(filepath.Join(tmpDir, "merged", "proc"), syscall.MNT_DETACH)
		_ = syscall.Unmount(filepath.Join(tmpDir, "merged", "sys"), syscall.MNT_DETACH)
		_ = syscall.Unmount(filepath.Join(tmpDir, "merged", "run"), syscall.MNT_DETACH)
		_ = syscall.Unmount(filepath.Join(tmpDir, "merged"), syscall.MNT_DETACH)
		_ = syscall.Unmount(tmpDir, syscall.MNT_DETACH)
		_ = os.RemoveAll(tmpDir)
	}()

	// Mount tmpfs
	if err := syscall.Mount("tmpfs", tmpDir, "tmpfs", 0, ""); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mount tmpfs: %v\n", err)
		os.Exit(1)
	}

	upperDir := filepath.Join(tmpDir, "upper")
	workDir := filepath.Join(tmpDir, "work")
	mergedDir := filepath.Join(tmpDir, "merged")

	for _, d := range []string{upperDir, workDir, mergedDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to mkdir %s: %v\n", d, err)
			os.Exit(1)
		}
	}

	// Mount overlayfs
	overlayOpts := fmt.Sprintf("lowerdir=/,upperdir=%s,workdir=%s", upperDir, workDir)
	if err := syscall.Mount("overlay", mergedDir, "overlay", 0, overlayOpts); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mount overlayfs: %v\n", err)
		os.Exit(1)
	}

	// Bind mount virtual filesystems
	bindMounts := []struct {
		src string
		dst string
	}{
		{"/proc", filepath.Join(mergedDir, "proc")},
		{"/sys", filepath.Join(mergedDir, "sys")},
		{"/dev", filepath.Join(mergedDir, "dev")},
		{"/dev/pts", filepath.Join(mergedDir, "dev", "pts")},
		{"/run", filepath.Join(mergedDir, "run")},
	}

	for _, bm := range bindMounts {
		_ = os.MkdirAll(bm.dst, 0755)
		if err := syscall.Mount(bm.src, bm.dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			fmt.Fprintf(os.Stderr, "failed to bind mount %s: %v\n", bm.src, err)
			os.Exit(1)
		}
	}

	// Chroot into mergedDir
	if err := syscall.Chroot(mergedDir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to chroot into overlay: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Chdir("/"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to chdir to /: %v\n", err)
		os.Exit(1)
	}

	// Setup prompt to show (hakoniwa) in command prompt
	_ = os.WriteFile("/etc/debian_chroot", []byte("hakoniwa\n"), 0644)
	promptSnippet := `if [ -n "$PS1" ] && [ "${PS1#*(hakoniwa)}" = "$PS1" ] && [ "${PS1#*debian_chroot}" = "$PS1" ]; then
    PS1="(hakoniwa) $PS1"
fi
`
	_ = os.WriteFile("/etc/profile.d/hakoniwa.sh", []byte(promptSnippet), 0644)
	if home != "" {
		userBashrc := filepath.Join(home, ".bashrc")
		if f, err := os.OpenFile(userBashrc, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			_, _ = f.WriteString("\n" + promptSnippet)
			_ = f.Close()
		}
	}

	// Change working directory to original CWD if available
	if cwd != "" {
		_ = syscall.Chdir(cwd)
	}

	// Switch UID/GID back to the original user
	if gid != 0 {
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			if gids, err := u.GroupIds(); err == nil {
				intGids := make([]int, 0, len(gids))
				for _, g := range gids {
					if id, err := strconv.Atoi(g); err == nil {
						intGids = append(intGids, id)
					}
				}
				if len(intGids) > 0 {
					_ = syscall.Setgroups(intGids)
				}
			}
		}
		if err := syscall.Setresgid(gid, gid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "failed to setgid: %v\n", err)
			os.Exit(1)
		}
	}
	if uid != 0 {
		if err := syscall.Setresuid(uid, uid, uid); err != nil {
			fmt.Fprintf(os.Stderr, "failed to setuid: %v\n", err)
			os.Exit(1)
		}
	}

	// Set environment variables
	if home != "" {
		os.Setenv("HOME", home)
	}
	if username != "" {
		os.Setenv("USER", username)
		os.Setenv("LOGNAME", username)
	}
	if shell == "" {
		shell = "/bin/bash"
	}
	os.Setenv("SHELL", shell)
	os.Setenv("HAKONIWA", "1")
	os.Setenv("debian_chroot", "hakoniwa")

	// Prohibit chroot syscall using seccomp BPF filter
	if err := disableChroot(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to disable chroot: %v\n", err)
		os.Exit(1)
	}

	// Launch login shell
	shellCmd := exec.Command(shell, "-l")
	shellCmd.Stdin = os.Stdin
	shellCmd.Stdout = os.Stdout
	shellCmd.Stderr = os.Stderr

	if err := shellCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
