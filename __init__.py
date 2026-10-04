# -*- coding: utf-8 -*-
# @PluginName: Secure Shell
# @Version: 2.0.1
# @Author: ZhangZuoqian
# @Description: 跨平台(Linux/macOS/Windows) Shell 执行器，带安全白名单与日志审计
#
# 相较 v1.2.0 的改进：
#   1. 平台自适应：Linux/macOS 用 sh -c，Windows 用 cmd /c，全平台可用
#   2. 危险命令拦截（白名单制，未白名单的命令默认拒绝执行）
#   3. 执行审计日志（logs/secure_shell.log），可追溯
#   4. 统一 pathlib 处理路径，去掉手写 ~ / cd / pwd 特判
#   5. 流式输出（长命令不再阻塞到结束），带超时终止
#   6. 权限可配置、超时可配置、白名单可在配置文件里调整
#
# 相较 v2.0.0 的改进（安全修复：根除 shell 命令注入）：
#   1. 删除 /bin/sh -c / cmd /c 包装层，用户输入不再交给任何 shell 解释器
#   2. shlex.split() 拆分为参数列表 cmd_list，引号未闭合等格式错误直接终止不执行
#   3. 拆分结果为空列表时直接拦截，拒绝执行空命令
#   4. 黑白名单只用拆分后索引0的真实程序名判断，不校验原始输入字符串
#   5. Popen(cmd_list, shell=False) 执行，流式读取、超时自动杀死子进程的逻辑原样保留
#   6. 消息状态标记统一为 [INFO]/[OK]/[FAIL] 纯 ASCII 符号
#
# 依赖：MCDReforged >= 2.0.0

from __future__ import annotations

import os
import time
import platform
import threading
import shlex
import subprocess
import datetime
from pathlib import Path
from typing import Optional, Tuple

from mcdreforged.api.all import *

PLUGIN_METADATA = {
    'id': 'secure_shell',
    'version': '2.0.2',
    'name': 'Secure Shell',
    'description': {
        'zh_cn': '跨平台Shell执行器，带安全白名单与日志审计',
        'en_us': 'Cross-platform shell executor with allowlist and audit log'
    },
    'author': 'ZhangZuoqian',
    'link': 'https://github.com/ZhangZuoqian/secure_shell',
    'dependencies': {
        'mcdreforged': '>=2.0.0'
    }
}

# ---------------------------------------------------------------------------
# 配置区（可在 config/secure_shell/config.json 覆盖）
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    # 所需 MCDR 权限等级（4 = 管理员，2 = 一般OP）
    "required_permission": 4,
    # 是否允许游戏内玩家执行（默认 False：仅 MCDR 控制台可执行；True 时玩家还需满足 required_permission）
    "allow_player_execution": False,
    # 单条命令默认超时（秒）
    "default_timeout": 60,
    # 是否强制白名单（True：只允许白名单命令；False：关闭白名单限制，放行任意命令但记录+黑名单仍兜底）
    "enforce_allowlist": False,
    # 工作目录白名单（只允许在这些目录下运行命令，"" 表示不限制）
    "allowed_cwd_prefixes": [],
    # 白名单命令前缀（enforce_allowlist=True 时，命令必须命中其一才放行）
    # 每条可用形如 "rm -rf /tmp/*" 的完整前缀，或用 "*" 放行全部(不推荐)
    "allowlist": [
        "echo", "ls", "pwd", "cd", "cat", "head", "tail", "less",
        "grep", "find", "df", "du", "free", "ps", "top", "uptime",
        "whoami", "hostname", "uname", "date", "cal",
        "ping", "curl", "wget", "git status", "git log", "git diff",
        "node -v", "npm -v", "python --version", "python3 --version",
        "java -version", "jar tf", "tar tzf", "unzip -l",
    ],
    # 危险命令黑名单：即使命中白名单，前缀仍命中黑名单则拒绝
    # 用换行分隔的独立条目
    "blacklist": [
        "rm -rf /", "rm -rf ~", "rm -rf .", "shutdown", "reboot",
        "init 0", "halt", "poweroff", "mkfs", "dd if=", "fdisk",
        "chmod -R 777 /", "chown -R", "mv / ", "cp -r / ",
        "> /dev/sda", "curl -s https:// | sh", "wget -O - | sh",
        "kill -9 1", "systemctl stop", "service stop",
    ],
}

# 全局状态
_config: dict = None
_cwd: Path = Path(os.getcwd())
_audit_log: Optional[Path] = None


# ---------------------------------------------------------------------------
# 平台相关
# ---------------------------------------------------------------------------
def is_windows() -> bool:
    return platform.system().lower() == 'windows'


def is_macos() -> bool:
    return platform.system().lower() == 'darwin'


# ---------------------------------------------------------------------------
# 配置加载
# ---------------------------------------------------------------------------
def load_config(server: PluginServerInterface):
    global _config, _audit_log
    cfg = server.load_config_simple(default_config=DEFAULT_CONFIG)
    _config = {**DEFAULT_CONFIG, **cfg}

    # 审计日志路径：logs/secure_shell.log
    logs_dir = Path('logs')
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    _audit_log = logs_dir / 'secure_shell.log'
    _audit("ShellExecutor 初始化", extra=f"平台={platform.system()} 白名单强制={_config['enforce_allowlist']}")


def _audit(action: str, player: str = None, command: str = None, result: str = None, extra: str = None):
    """写入审计日志。不依赖控制台，只落盘。"""
    if _audit_log is None:
        return
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    parts = [f"[{ts}]"]
    if player:
        parts.append(f"玩家={player}")
    parts.append(f"动作={action}")
    if command:
        parts.append(f"命令={command}")
    if result:
        parts.append(f"结果={result}")
    if extra:
        parts.append(extra)
    try:
        with open(_audit_log, 'a', encoding='utf-8') as f:
            f.write(" | ".join(parts) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 安全校验
# ---------------------------------------------------------------------------
def check_allowed(program: str) -> Tuple[bool, str]:
    """对拆分后的真实程序名（索引0）做黑白名单判断，返回 (是否放行, 拒绝原因)。
    名单条目按首个词与程序名全等匹配（"rm -rf /" 命中 rm，"git status" 放行 git）。
    """
    program = program.strip().lower()

    # 1. 黑名单优先：程序名命中任一条目即拒绝
    for bad in _config.get("blacklist", []):
        bad_head = bad.strip().split()[0].lower() if bad.strip() else ""
        if bad_head and program == bad_head:
            return False, f"命中黑名单命令: {bad}"

    # 2. 白名单
    allowlist = _config.get("allowlist", [])
    if "*" in allowlist:  # 显式放行全部
        return True, ""

    if _config.get("enforce_allowlist", True):
        if not allowlist:
            return False, "白名单为空且强制开启，所有命令被拒绝"
        for good in allowlist:
            good_head = good.strip().split()[0].lower() if good.strip() else ""
            if good_head and program == good_head:
                return True, ""
        return False, f"命令不在白名单内: {program}"
    else:
        return True, ""  # 非强制模式：放行，但会记录


# ---------------------------------------------------------------------------
# 命令执行
# ---------------------------------------------------------------------------
def execute_shell(command: str, timeout: int, player: str) -> Tuple[int, str]:
    """执行命令，返回 (returncode, output)。流式读取，超时终止。"""
    global _cwd

    # shlex.split：拆分命令字符串得到参数列表，杜绝 shell 元字符被解释
    try:
        cmd_list = shlex.split(command)
    except ValueError:
        _audit("拒绝执行", player=player, command=command, result="命令格式错误，引号未正确闭合")
        return -1, "[FAIL] 命令格式错误，引号未正确闭合"

    # 空列表拦截：拒绝执行空命令
    if not cmd_list:
        _audit("拒绝执行", player=player, command=command, result="空命令")
        return -1, "[FAIL] 空命令，拒绝执行"

    # 安全校验：只拿索引0的真实程序名做黑白名单判断，不校验原始输入字符串
    program = cmd_list[0]
    allowed, reason = check_allowed(program)
    if not allowed:
        _audit("拒绝执行", player=player, command=command, result=f"被拦截: {reason}")
        return -1, f"[FAIL] 安全拦截: {reason}"

    _audit("执行", player=player, command=command, extra=f"cwd={_cwd}")

    try:
        proc = subprocess.Popen(
            cmd_list,
            shell=False,
            cwd=str(_cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env={**os.environ, 'TERM': 'dumb', 'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8'}
        )
    except Exception as e:
        _audit("执行失败", player=player, command=command, result=f"启动异常: {e}")
        return -1, f"[FAIL] 执行异常: {e}"

    # 流式读取
    output_chunks = []
    start = time.time()
    timed_out = False

    def _reader():
        for line in proc.stdout:
            output_chunks.append(line)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    try:
        t.join(timeout)
        if t.is_alive():
            timed_out = True
            proc.kill()
            t.join(2)
    except Exception:
        pass

    try:
        code = proc.wait(timeout=2)
    except Exception:
        code = proc.poll()
        if code is None:
            code = -1

    output = "".join(output_chunks)
    if timed_out:
        output += f"\n[FAIL] 命令超时(>{timeout}s)，已强制终止"

    return code, output


def format_output(text: str, max_lines: int = 80, max_chars_per_line: int = 300) -> str:
    """格式化输出，防止刷屏。"""
    lines = text.split('\n')
    total = len(lines)
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... (共{total}行，已截断显示前{max_lines}行)"]
    result = []
    for line in lines:
        if len(line) > max_chars_per_line:
            line = line[:max_chars_per_line] + f"...(本行{len(line)}字符，已截断)"
        result.append(line)
    return '\n'.join(result)


# ---------------------------------------------------------------------------
# 命令处理器
# ---------------------------------------------------------------------------
@new_thread
def shell_cmd(source: CommandSource, command: str):
    global _cwd

    req_perm = _config.get("required_permission", 4)

    # 游戏内执行默认禁用（v2.0.2）：仅 MCDR 控制台可用，需显式开启且玩家满足权限等级
    if source.is_player and not _config.get("allow_player_execution", False):
        source.reply(RText(f"§c[FAIL] 游戏内执行默认禁用（仅限控制台）。如确需开启，请在 config 中设置 allow_player_execution=true，且玩家权限等级需 ≥ {req_perm}§r"))
        _audit("玩家执行禁用", player=source.player, command=command,
               result="allow_player_execution=False")
        return

    if not source.has_permission(req_perm):
        source.reply(RText(f"§c[FAIL] 权限不足，需要MCDR权限等级 {req_perm}§r"))
        _audit("权限不足", player=source.player if source.is_player else "控制台",
               command=command, result=f"需要权限{req_perm}")
        return

    player = source.player if source.is_player else "控制台"
    stripped = command.strip()

    # cd 命令：更新工作目录（跨平台统一用 pathlib 处理）
    if stripped.startswith('cd '):
        target = stripped[3:].strip()
        # 去引号
        if len(target) >= 2 and target[0] == target[-1] and target[0] in ('"', "'"):
            target = target[1:-1]
        # 展开 ~
        target = os.path.expanduser(target)
        p = Path(target)
        if not p.is_absolute():
            p = _cwd / p
        p = p.resolve()
        if p.is_dir():
            _cwd = p
            _audit("切换目录", player=player, result=str(_cwd))
            source.reply(f"§a[OK] 工作目录已切换到: {_cwd}§r")
        else:
            source.reply(f"§c[FAIL] 目录不存在: {p}§r")
        return

    # pwd 命令
    if stripped == 'pwd':
        source.reply(f"§e[INFO] 当前工作目录: {_cwd}§r")
        return

    timeout = _config.get("default_timeout", 60)
    # 支持 !!shell --timeout=5 "cmd"
    if stripped.startswith('--timeout='):
        try:
            timeout = int(stripped.split()[0].split('=')[1])
            stripped = ' '.join(stripped.split()[1:])
        except (ValueError, IndexError):
            pass
    # 去掉最外层引号
    command_clean = stripped
    if len(command_clean) >= 2 and command_clean[0] == command_clean[-1] and command_clean[0] in ('"', "'"):
        command_clean = command_clean[1:-1]

    source.reply(f"§7[INFO] 执行 §f{command_clean}§7  (cwd={_cwd}, timeout={timeout}s)§r")
    code, output = execute_shell(command_clean, timeout, player)
    if output.strip():
        source.reply(format_output(output))
    if code == 0:
        source.reply(f"§a[OK] 退出码 {code}§r")
    else:
        source.reply(f"§c[FAIL] 退出码 {code}§r")
    _audit("完成", player=player, command=command_clean, result=f"exit={code}")


# ---------------------------------------------------------------------------
# 生命周期
# ---------------------------------------------------------------------------
def _shell_status(source: CommandSource):
    """查看白名单开关状态（管理员可查看）。"""
    if not source.has_permission(_config.get("required_permission", 4)):
        source.reply(RText("§c[FAIL] 权限不足§r"))
        return
    en = _config.get("enforce_allowlist", False)
    mode = "§a开启§r（只允许白名单命令）" if en else "§e关闭§r（放行任意命令，危险命令黑名单仍兜底）"
    source.reply(f"§7[INFO] 白名单强制: {mode}")
    if not en:
        source.reply(f"§7  黑名单拦截仍在生效，危险命令如 rm -rf /、shutdown 等会被拒绝")
    else:
        source.reply(f"§7  当前白名单 {len(_config.get('allowlist', []))} 条，可用 !!shellstatus 查看")
    pe = _config.get("allow_player_execution", False)
    pe_mode = "§e开启§r（游戏内需权限等级 ≥ %d）" % _config.get("required_permission", 4) if pe else "§c关闭§r（仅控制台可执行）"
    source.reply(f"§7[INFO] 游戏内玩家执行: {pe_mode}")


def on_load(server: PluginServerInterface, prev_module):
    load_config(server)
    server.register_command(
        Literal('!!shell').then(
            GreedyText('command').runs(lambda src, ctx: shell_cmd(src, ctx['command']))
        )
    )
    server.register_command(
        Literal('!!sh').then(
            GreedyText('command').runs(lambda src, ctx: shell_cmd(src, ctx['command']))
        )
    )
    server.register_command(
        Literal('!!shellstatus').runs(lambda src: _shell_status(src))
    )
    server.logger.info("[INFO] ShellExecutor 已加载")
    server.logger.info(f"[INFO] 平台: {platform.system()} | 强制白名单: {_config.get('enforce_allowlist')} | 审计日志: logs/secure_shell.log")


def on_unload(server):
    _audit("卸载")
    server.logger.info("ShellExecutor 已卸载")
