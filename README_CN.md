# Secure Shell

[English](README.md) | **简体中文**

一个给面板服用的 MCDReforged 插件，帮你跑 shell 命令——从 MCDR 控制台跑，游戏聊天框里也能跑（但要自己开）。带权限等级门槛、黑白名单和审计日志。

面板服只给你一个网页控制台，敲进去的东西直接进游戏服务端。没有 root，没有 SSH，也没有系统终端。想看磁盘占了多少、哪个进程在吃内存？没地方敲。这插件就是干这个的——我自己就跑在简幻欢上，日常这些检查全靠它。

## 功能

- 控制台优先：默认只有 MCDR 控制台能执行命令，游戏内执行是可选项
- 游戏内双重门槛：`allow_player_execution` 开关要打开，玩家还得有 MCDR 4 级权限（`required_permission` 可调）
- 不经过 shell：输入用 `shlex` 拆分后直接启动程序，管道、重定向、通配符、`$()` 一概不通
- 危险命令黑名单常开，另有可选的白名单-only 模式
- 每次执行和拒绝都写进 `logs/secure_shell.log`
- 跨平台（Linux / macOS / Windows），单条命令超时强杀

## 用法

默认只有 MCDR 控制台能执行，游戏内是禁用的（v2.0.2 起）。想让游戏里也能用，把配置里的 `allow_player_execution` 改成 `true`——就算开了，玩家还得有 MCDR 权限等级 `required_permission`（默认 4），两道门都过才放行。开关关着的时候，玩家尝试会被拒绝并记进日志。

```
!!shell "df -h"                    执行命令
!!sh "ping -c 4 8.8.8.8"           !!sh 是 !!shell 的别名
!!shell --timeout=10 "..."         单条命令临时改超时
!!shellstatus                      查看当前各开关状态
```

`cd` 和 `pwd` 由插件自己处理，工作目录会跟着走，重载插件后恢复原样：

```
!!shell "cd /home/container"
!!shell "ls"
```

返回内容依次是：一行执行信息（当前 `cwd` 和超时）、流式输出、一行退出码。`[OK] 退出码 0` 是成功，`[FAIL] 退出码 N` 是失败，stderr 会并进输出。被拦下的命令不会执行，提示 `[FAIL] 安全拦截: <原因>`；超时的会被强杀，提示 `[FAIL] 命令超时(>Ns)，已强制终止`；引号没闭合这类格式错误直接不执行。以上这些——包括拒绝记录——都会写进 `logs/secure_shell.log`。

`!!shellstatus` 会显示白名单是否强制、游戏内执行开没开，还会提醒你黑名单始终兜底。

## 配置

配置文件在 `config/secure_shell/config.json`，首次加载自动生成：

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `required_permission` | `4` | 执行命令需要的 MCDR 权限等级 |
| `allow_player_execution` | `false` | `false`：仅 MCDR 控制台。`true`：玩家也能执行，但仍需满足 `required_permission` |
| `default_timeout` | `60` | 超时时间（秒） |
| `enforce_allowlist` | `false` | `true` 时只放行白名单里的程序 |
| `allowlist` | （一组常用的安全命令） | 条目按程序名（命令的第一个词）匹配 |
| `blacklist` | （危险命令） | 优先于白名单，始终生效 |

匹配对象是拆分后的真实程序名（首词全等）：白名单里的 `git status` 放行的是 `git`，黑名单里的 `rm -rf /` 拦的是 `rm`。黑名单永远兜底，白名单只在 `enforce_allowlist` 为 `true` 时生效。

## 安全说明

从 v2.0.1 起，命令不再经过 shell。输入先拆成程序名和参数（`shlex.split`），然后直接启动程序——管道 `|`、重定向 `>`、通配符 `*`、`;`、`&&`、`$()`、反引号都不再生效。普通命令加普通参数不受影响。真需要管道、重定向，就写个脚本放到服务器上，把脚本加进白名单。

把 `allow_player_execution` 改成 `true` 之前想清楚：能用 `!!shell` 的人就是在你主机上跑真实命令。黑名单和白名单只是模式匹配，不是沙箱。只开给自己的服主账号——MCDR 的 4 级权限来自 `permission.yml`，玩家默认一个都没有——也别为了让某个人用起来就把 `required_permission` 调低。

bash、sh、zsh、python、perl 这类解释器别放进白名单。解释器自己就能跑任意命令，放一个进去等于白名单作废。插件不会拦你——配置是你的事。白名单老老实实放 ping、df、free、uptime、systemctl 这类单纯工具。

每次执行都会记录到 `logs/secure_shell.log`，含时间、玩家、命令和结果——拒绝记录也在内。

## 安装

从 [Releases](https://github.com/ZhangZuoqian/secure_shell/releases) 下载 `secure_shell.mcdr`，丢进 `plugins/` 目录，然后：

```
!!MCDR reload plugin
```

## 许可

MIT，见 [LICENSE](LICENSE)。
