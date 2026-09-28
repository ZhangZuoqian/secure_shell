# Secure Shell

A cross-platform shell executor for MCDReforged. Run Linux, macOS, or Windows commands from the in-game chat or the MCDR console, with an allowlist and audit logging.

## Why this exists

Panel-hosted servers usually have no shell access. This plugin gives you a way to run system commands without logging into an SSH terminal: type them in the game chat instead.

## Features

- Runs commands through `!!shell` or `!!sh`
- Works on Linux, macOS, and Windows (detects the platform and uses the right shell)
- Allowlist mode: only commands you whitelist can run (optional)
- Blacklist: dangerous commands such as `rm -rf /` or `shutdown` are blocked regardless of allowlist state
- Audit log: every execution is written to `logs/secure_shell.log`
- Streaming output for long-running commands
- Per-command timeout

## Usage

Requires MCDR permission level 4 (or whatever you set in `required_permission`).

```
!!shell "ls -la"
!!sh "df -h"
!!shell --timeout=10 "ping -c 4 8.8.8.8"
!!shellstatus        # shows whether the allowlist is enabled
```

`cd` and `pwd` are handled specially and update the working directory:

```
!!shell "cd /home/container"
!!shell "pwd"
```

## Configuration

The plugin reads `config/secure_shell/config.json`. If the file does not exist, defaults are used.

| Key | Default | Description |
| --- | --- | --- |
| `required_permission` | `4` | MCDR permission level needed to run commands |
| `default_timeout` | `60` | Default timeout in seconds |
| `enforce_allowlist` | `false` | When true, only allowlisted commands run |
| `allowlist` | list | Command prefixes allowed when the allowlist is on |
| `blacklist` | list | Dangerous command prefixes that are always blocked |

The allowlist is off by default so the plugin does not get in the way. The blacklist always applies as a safety net.

## Install

Put `ShellExecutor.py` (or the `.mcdr`/`.pyz` package) in the `plugins/` directory, then:

```
!!MCDR reload plugin
```

## Building the package

This plugin can be packaged as a `.pyz` or `.mcdr` file. See the MCDR documentation for details.

## License

MIT. See LICENSE.
