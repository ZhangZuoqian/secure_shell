# Secure Shell

**English** | [简体中文](README_CN.md)

An MCDReforged plugin for panel-hosted servers. It runs shell commands for you — from the MCDR console, and from the game chat too if you turn that on. Comes with a permission gate, a blacklist/allowlist and an audit log.

On a panel host you get a web console whose input goes straight to the game server. No root, no SSH, no terminal of your own. Want to check disk usage or see which process is eating memory? Nowhere to type. I wrote this for exactly that — it runs on my own panel server (SimpFun, a free one), and I use it daily for those little checks.

## Features

- Console-first: by default only the MCDR console can run commands; in-game execution is opt-in
- Two gates for in-game use: `allow_player_execution` must be on, and the player needs MCDR permission level 4 (`required_permission`, configurable)
- No shell involved: input is split with `shlex` and executed directly, so pipes, redirects, globs and `$()` never pass through
- Always-on dangerous-command blacklist, plus an optional allowlist-only mode
- Every execution and denial is logged to `logs/secure_shell.log`
- Cross-platform (Linux / macOS / Windows), per-command timeout with force-kill

## Usage

By default only the MCDR console can run commands; in-game execution is disabled (since v2.0.2). To let players use `!!shell`, set `allow_player_execution` to `true` in the config — and even then a player still needs MCDR permission level `required_permission` (default `4`). Both checks have to pass. While the switch is off, players who try get told so, and every attempt is logged.

```
!!shell "df -h"                    run a command
!!sh "ping -c 4 8.8.8.8"           !!sh is an alias of !!shell
!!shell --timeout=10 "..."         override the timeout for one command
!!shellstatus                      show the current switches
```

`cd` and `pwd` are handled by the plugin itself, so the working directory follows you around and resets when the plugin is reloaded:

```
!!shell "cd /home/container"
!!shell "ls"
```

Replies come in order: an info line with the effective `cwd` and timeout, the streamed output, then an exit-code line. `[OK] 退出码 0` means success, `[FAIL] 退出码 N` means failure. stderr is merged into the output. A blocked command never runs and answers `[FAIL] 安全拦截: <原因>`; a command past its timeout is killed with `[FAIL] 命令超时(>Ns)，已强制终止`; unclosed quotes are rejected before anything runs. All of this — denials included — lands in `logs/secure_shell.log`.

`!!shellstatus` shows whether the allowlist is enforced, whether in-game execution is on, and reminds you the blacklist always applies.

## Configuration

`config/secure_shell/config.json`, created with defaults on first load:

| Key | Default | What it does |
| --- | --- | --- |
| `required_permission` | `4` | MCDR permission level needed to run commands |
| `allow_player_execution` | `false` | `false`: MCDR console only. `true`: players may run commands too, but still need `required_permission` |
| `default_timeout` | `60` | Timeout in seconds |
| `enforce_allowlist` | `false` | `true`: only allowlisted programs may run |
| `allowlist` | (a set of common safe commands) | Entries match the program name, i.e. the first word of the command |
| `blacklist` | (dangerous commands) | Checked before the allowlist, always applies |

Matching works on the actual program name — the first word after splitting. So `git status` in the allowlist allows `git`, and `rm -rf /` in the blacklist blocks `rm`. The blacklist always wins; the allowlist only matters when `enforce_allowlist` is `true`.

## Security notes

Since v2.0.1 commands no longer go through a shell. Input is split into a program name and arguments (`shlex.split`) and executed directly — pipes `|`, redirection `>`, globs `*`, `;`, `&&`, `$()` and backticks no longer work. Plain commands with plain arguments behave as before. If you really need pipes or redirection, write a script, put it on the server and allowlist the script.

Think twice before you set `allow_player_execution` to `true`. Whoever can run `!!shell` runs real commands on the host. The blacklist and allowlist are pattern matching, not a sandbox. Enable it only for your own owner account — MCDR permission level 4 comes from `permission.yml`, and that list is empty for players by default — and don't lower `required_permission` just to make it work for someone else.

Keep interpreters (`bash`, `sh`, `zsh`, `python`, `perl`, ...) out of the allowlist. An interpreter can run arbitrary commands on its own, so allowing one defeats the whitelist. The plugin won't stop you — it's your config. Stick to plain tools like `ping`, `df`, `free`, `uptime`, `systemctl`.

Every execution is logged to `logs/secure_shell.log` with time, player, command and result — denials included.

## Install

Grab `secure_shell.mcdr` from the [releases](https://github.com/ZhangZuoqian/secure_shell/releases), drop it into `plugins/`, then:

```
!!MCDR reload plugin
```

## License

MIT. See [LICENSE](LICENSE).
