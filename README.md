# hakoniwa

A lightweight, ephemeral sandbox environment tool that allows you to safely test commands and applications without affecting the host OS filesystem.

## Features
- **Uses Host Environment Directly**: No need to build or download container images like Docker; it runs directly using your current host filesystem.
- **In-Memory Writes via OverlayFS**: All file modifications and new files are written to memory (`tmpfs`) through OverlayFS and never affect the host OS.
- **Launches Your Login Shell**: Automatically launches the invoking user's login shell while preserving UID, GID, supplementary groups, environment variables, and current working directory.
- **Visual Prompt Indicator**: Automatically prepends `(hakoniwa)` to your command prompt so you always know you are inside the sandbox.
- **Disables `chroot` Syscall**: Uses a seccomp BPF filter to block `chroot` system calls (`EPERM`) inside the sandbox.
- **Clean Exit with Ctrl + D**: Exiting the shell discards all changes from memory and cleanly returns you to your original host environment.

## Installation
```bash
go install github.com/nakagami/hakoniwa@latest
```

Or install from the local source directory:
```bash
go install .
```

Make sure `$GOPATH/bin` (or `~/go/bin`) is included in your `$PATH`.

## Usage
```bash
# Launch interactive login shell inside sandbox
hakoniwa

# Run a specific command inside sandbox and exit
hakoniwa <command> [args...]
```

> **Note**: Requires `sudo` privileges upon launch to configure the mount namespace and OverlayFS. Once initialized, privileges are immediately and automatically dropped back to your original user.

## License
[MIT License](LICENSE)
