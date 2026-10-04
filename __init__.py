# -*- coding: utf-8 -*-
# @PluginName: Secure Shell
# @Version: 2.1.0
# @Author: ZhangZuoqian
# @Description: 跨平台(Linux/macOS/Windows) Shell 执行器，带安全白名单与日志审计
#
# 相较 v2.0.3 的改进（执行引擎拆分为可选扩展包）：
#   1. shell 执行引擎拆入可选扩展包，主插件默认不带、不下载、不加载
#   2. 扩展包管理命令（!!secure_shell *）仅限控制台，游戏内玩家一律拒绝
#   3. 下载用标准库 urllib（零第三方依赖），强制 SHA256 完整性校验
#   4. 进阶 RSA-2048 签名校验（PKCS#1 v1.5 + SHA-256），公钥内置本文件，私钥只在构建侧
#   5. 可选二次密码验证（PBKDF2-SHA256 存配置文件，源码零硬编码）
#   6. 安装后不自动启用，需 !!secure_shell enable_ext 显式开启
#
# 历史改进摘要：
#   v2.0.x 注入修复（shlex + shell=False）、allow_player_execution 默认关、回复语双语
#
# 依赖：MCDReforged >= 2.0.0

from __future__ import annotations

import os
import json
import platform
import threading
import hashlib
import secrets
import zipfile
import urllib.request
import urllib.error
import importlib.util
import io
import datetime
from pathlib import Path
from typing import Optional, Tuple

from mcdreforged.api.all import *

PLUGIN_METADATA = {
    'id': 'secure_shell',
    'version': '2.1.0',
    'name': 'Secure Shell',
    'description': {
        'zh_cn': '跨平台Shell执行器（执行引擎为可选扩展包），带安全白名单与日志审计',
        'en_us': 'Cross-platform shell executor with pluggable engine extension, allowlist and audit log'
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
    # 注意：默认名单按 Linux 编写，Windows/macOS 用户请按自己的系统调整
    "allowlist": [
        "echo", "ls", "pwd", "cd", "cat", "head", "tail", "less",
        "grep", "find", "df", "du", "free", "ps", "top", "uptime",
        "whoami", "hostname", "uname", "date", "cal",
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
    # ---- 扩展包（shell 执行引擎）----
    # 下载地址（签名文件为该地址 + ".sig"）
    "ext_download_url": "https://github.com/ZhangZuoqian/secure_shell/releases/latest/download/shell_ext-latest.zip",
    # 期望的 SHA256；留空 = 使用源码内置值。自定义下载源时必须改成对应包的哈希
    "ext_expected_sha256": "",
    # 下载大小上限（字节），防磁盘炸弹
    "ext_max_bytes": 10485760,
    # 下载超时（秒）
    "ext_download_timeout": 60,
    # 二次密码验证：PBKDF2 串，格式见 !!secure_shell hash_password；留空 = 不启用
    "ext_password_pbkdf2": "",
}

MAIN_VERSION = PLUGIN_METADATA['version']

# ---------------------------------------------------------------------------
# 扩展包内置信任锚（公钥 + 当前扩展包哈希）
# 私钥只在构建机（secure_shell_keys/，不入仓库），插件侧仅能验证不能签名
# ---------------------------------------------------------------------------
EXT_PUBKEY_N_HEX = "cdb4f61f3e214c7ad0297941fecb2131aad071992a4346f9540c972f08dd82b8c1d5b4f54bdea25d20bf78d0c8c59a6b93c030ebe2ffb35a61e261bb49ac37a3e90ad244c5e00bdf4eaf47bad40e6009a5795eaafa3de89e2aec5bb028722efea77a4884e446820ebda1726cbcc649a954bb45049c3f1006d3c2bcc1f0160f1cecf930951595cbc7e7a9be411f30bba9a430d312cc5f46b009a10c30c994f4627c82be42e3a1be9bbde5e9aeba1b45d84bdc2c761b8a0c616c060b5427390b897130b4e219a4c540dad461618fce5b56328a34aef530c93634a7be4ae6a62ca3a0816f6c68be2edf002fc172f33204fc7f172dba797e82637337381938469a63"
EXT_PUBKEY_E_HEX = "10001"
EXT_EXPECTED_SHA256 = "3f4c9081b9eef3dd721dfb986e9278ef9aff46657d428de9f23f616aecacc9fc"
# SHA-256 的 PKCS#1 v1.5 DigestInfo 前缀
_RSA_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")

# 全局状态
_config: dict = None
_audit_log: Optional[Path] = None
_ext_module = None          # 已加载的扩展引擎模块（enable 后才有值）
_ext_lock = threading.Lock()


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
    _audit("ShellExecutor 初始化", extra=f"平台={platform.system()} 白名单强制={_config['enforce_allowlist']} 扩展已启用={_ext_module is not None}")


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
# 扩展包管理器
# ---------------------------------------------------------------------------
def _ext_dir() -> Path:
    return Path('config') / 'secure_shell' / 'ext'


def _ext_py() -> Path:
    return _ext_dir() / 'shell_ext.py'


def _ext_manifest() -> Path:
    return _ext_dir() / 'manifest.json'


def _ext_state_path() -> Path:
    return Path('config') / 'secure_shell' / 'ext_state.json'


def _load_state() -> dict:
    try:
        return json.loads(_ext_state_path().read_text(encoding='utf-8'))
    except Exception:
        return {"installed_version": None, "enabled": False}


def _save_state(state: dict):
    _ext_state_path().parent.mkdir(parents=True, exist_ok=True)
    _ext_state_path().write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding='utf-8')


def _console_only(source, action: str) -> bool:
    """扩展包管理命令的硬闸门：游戏内玩家一律拒绝（含 4 级 owner）。
    说明：MCDR 权限等级量表为 0-4，不存在更高等级；按需求"所有游戏内玩家
    一律禁止"，此处直接以来源是否为玩家判断，比权限数字更严格。"""
    if source.is_player:
        source.reply(RText("§c[FAIL] 扩展包管理仅限控制台 (extension management is console-only)§r"))
        _audit("扩展管理拒绝", player=source.player, result=f"动作={action}")
        return False
    return True


def _password_ok(password: str) -> bool:
    """可选二次密码校验。未配置 → 直接通过；配置了 → PBKDF2 比对。"""
    stored = _config.get("ext_password_pbkdf2", "")
    if not stored:
        return True
    if not password:
        return False
    try:
        algo, iters, salt_hex, hash_hex = stored.split('$')
        iters = int(iters)
        if algo != 'pbkdf2_sha256':
            return False
        calc = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                   bytes.fromhex(salt_hex), iters).hex()
        return secrets.compare_digest(calc, hash_hex)
    except Exception:
        return False


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rsa_verify(data: bytes, sig: bytes) -> bool:
    """纯标准库 RSA-2048 PKCS#1 v1.5 + SHA-256 验签（公钥内置，无 DER 解析面）。"""
    try:
        n = int(EXT_PUBKEY_N_HEX, 16)
        e = int(EXT_PUBKEY_E_HEX, 16)
        k = (n.bit_length() + 7) // 8
        if len(sig) != k:
            return False
        s = int.from_bytes(sig, 'big')
        if s >= n:
            return False
        m = pow(s, e, n)
        em = m.to_bytes(k, 'big')
        h = hashlib.sha256(data).digest()
        pad_len = k - len(_RSA_SHA256_DIGESTINFO) - len(h) - 3
        if pad_len < 8:
            return False
        expected = b'\x00\x01' + b'\xff' * pad_len + b'\x00' + _RSA_SHA256_DIGESTINFO + h
        return secrets.compare_digest(em, expected)
    except Exception:
        return False


def _download(url: str, max_bytes: int, timeout: int) -> bytes:
    """标准库 urllib 下载，仅允许 http/https，分块读取防超大文件。"""
    if not url.lower().startswith(('http://', 'https://')):
        raise ValueError(f"不支持的下载协议 (unsupported scheme): {url.rsplit('/', 1)[-1][:20]}")
    req = urllib.request.Request(url, headers={'User-Agent': 'secure_shell-ext-installer'})
    chunks = []
    got = 0
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            got += len(chunk)
            if got > max_bytes:
                raise ValueError(f"文件超过大小上限 (exceeds {max_bytes} bytes)")
            chunks.append(chunk)
    if got == 0:
        raise ValueError("下载内容为空 (empty download)")
    return b"".join(chunks)


def _safe_extract(zip_bytes: bytes) -> None:
    """解包扩展包到 ext 目录。防 zip-slip：只接受固定白名单文件名。"""
    ext_dir = _ext_dir()
    ext_dir.mkdir(parents=True, exist_ok=True)
    allowed = {'manifest.json', 'shell_ext.py'}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            name = Path(info.filename).name  # 去掉任何目录成分
            if name not in allowed:
                raise ValueError(f"扩展包含未知文件 (unexpected member): {info.filename[:40]}")
        for name in allowed:
            target = ext_dir / name
            target.write_bytes(z.read(name))


def _ext_load_module():
    """从已安装文件加载扩展引擎，校验接口与版本。"""
    global _ext_module
    py = _ext_py()
    if not py.exists():
        raise FileNotFoundError("扩展文件不存在 (shell_ext.py missing)")
    spec = importlib.util.spec_from_file_location('secure_shell_ext_engine', py)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attr in ('EXT_VERSION', 'MIN_MAIN_VERSION', 'init', 'handle_shell'):
        if not hasattr(mod, attr):
            raise ValueError(f"扩展缺少接口 (missing interface): {attr}")
    if tuple(int(x) for x in mod.MIN_MAIN_VERSION.split('.')) > tuple(int(x) for x in MAIN_VERSION.split('.')):
        raise ValueError(f"主插件版本过低 (main too old): 需要 ≥ {mod.MIN_MAIN_VERSION}")
    mod.init(config=_config, audit=_audit)
    _ext_module = mod


def _ext_unload_module():
    global _ext_module
    _ext_module = None


def _installed_manifest() -> dict:
    try:
        return json.loads(_ext_manifest().read_text(encoding='utf-8'))
    except Exception:
        return {}


# ---- 扩展管理命令处理器（全部仅控制台）----
def ext_cmd_install(source, password: str = ""):
    if not _console_only(source, "install_ext"):
        return
    if not _password_ok(password):
        _audit("扩展安装失败", result="二次密码校验未通过 (password check failed)")
        source.reply(RText("§c[FAIL] 二次密码校验未通过 (password check failed)§r"))
        return

    with _ext_lock:
        url = _config.get("ext_download_url", "")
        max_bytes = int(_config.get("ext_max_bytes", 10485760))
        timeout = int(_config.get("ext_download_timeout", 60))
        try:
            source.reply(f"§7[INFO] 下载扩展包 downloading: {url.rsplit('/', 1)[-1]}§r")
            data = _download(url, max_bytes, timeout)
            sig = _download(url + ".sig", 4096, timeout)

            expected = _config.get("ext_expected_sha256") or EXT_EXPECTED_SHA256
            actual = _sha256_hex(data)
            if actual != expected.lower():
                _audit("扩展安装失败", result=f"SHA256 不匹配 expected={expected[:12]} actual={actual[:12]}")
                source.reply(RText(f"§c[FAIL] SHA256 校验失败 (integrity check failed)§r"))
                return

            if not _rsa_verify(data, sig):
                _audit("扩展安装失败", result="RSA 签名验证失败 (signature invalid)")
                source.reply(RText("§c[FAIL] RSA 签名验证失败 (signature invalid)，文件可能被篡改§r"))
                return

            _safe_extract(data)
            manifest = _installed_manifest()
            state = _load_state()
            state["installed_version"] = manifest.get("version", "unknown")
            state["enabled"] = False
            state["installed_at"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            _save_state(state)
            _audit("扩展安装", result=f"v{state['installed_version']} sha256={actual[:12]} 已验证 verified")
            source.reply(f"§a[OK] 扩展包 v{state['installed_version']} 安装完成并已验证 (installed & verified)，未启用 not enabled§r")
            source.reply(f"§7[INFO] 执行 !!secure_shell enable_ext 启用 shell 能力§r")
        except urllib.error.URLError as e:
            _audit("扩展安装失败", result=f"网络错误 (network): {e}")
            source.reply(RText(f"§c[FAIL] 下载失败 (download failed): {e}§r"))
        except (ValueError, zipfile.BadZipFile, OSError) as e:
            _audit("扩展安装失败", result=f"{e}")
            source.reply(RText(f"§c[FAIL] 安装失败 (install failed): {e}§r"))


def ext_cmd_check(source):
    if not _console_only(source, "check_ext"):
        return
    state = _load_state()
    manifest = _installed_manifest()
    py = _ext_py()
    source.reply(f"§7[INFO] 扩展状态 extension state:§r")
    source.reply(f"§7  安装 installed: {'§a是 yes§r' if py.exists() else '§c否 no§r'}"
                 + (f"  v{manifest.get('version', '?')}" if py.exists() else ""))
    source.reply(f"§7  启用 enabled: {'§a是 yes§r' if state.get('enabled') and _ext_module else '§c否 no§r'}"
                 + (f" （引擎已加载 loaded）" if _ext_module else ""))
    if py.exists():
        source.reply(f"§7  文件 SHA256: {_sha256_hex(py.read_bytes())[:32]}…§r")
    source.reply(f"§7  下载源 url: {_config.get('ext_download_url', '')}§r")
    source.reply(f"§7  二次密码 password: {'§a已启用 on§r' if _config.get('ext_password_pbkdf2') else '§e未启用 off§r'}§r")


def ext_cmd_uninstall(source, password: str = ""):
    if not _console_only(source, "uninstall_ext"):
        return
    if not _password_ok(password):
        _audit("扩展卸载失败", result="二次密码校验未通过 (password check failed)")
        source.reply(RText("§c[FAIL] 二次密码校验未通过 (password check failed)§r"))
        return
    with _ext_lock:
        _ext_unload_module()
        removed = []
        for f in (_ext_py(), _ext_manifest()):
            if f.exists():
                f.unlink()
                removed.append(f.name)
        state_path = _ext_state_path()
        if state_path.exists():
            state_path.unlink()
        _audit("扩展卸载", result=f"删除 removed={removed}")
        source.reply(f"§a[OK] 扩展包已卸载 (uninstalled): {', '.join(removed) if removed else '本来就不存在 nothing to remove'}§r")


def ext_cmd_enable(source):
    if not _console_only(source, "enable_ext"):
        return
    with _ext_lock:
        if not _ext_py().exists():
            source.reply(RText("§c[FAIL] 扩展包未安装 (extension not installed)，先执行 !!secure_shell install_ext§r"))
            return
        try:
            _ext_load_module()
        except Exception as e:
            _audit("扩展启用失败", result=f"{e}")
            source.reply(RText(f"§c[FAIL] 启用失败 (enable failed): {e}§r"))
            return
        state = _load_state()
        state["enabled"] = True
        _save_state(state)
        _audit("扩展启用", result=f"v{_ext_module.EXT_VERSION}")
        source.reply(f"§a[OK] shell 能力已启用 (enabled) v{_ext_module.EXT_VERSION}，现在可用 !!shell / !!sh§r")


def ext_cmd_disable(source):
    if not _console_only(source, "disable_ext"):
        return
    with _ext_lock:
        _ext_unload_module()
        state = _load_state()
        state["enabled"] = False
        _save_state(state)
        _audit("扩展禁用")
        source.reply(f"§a[OK] shell 能力已禁用 (disabled)§r")


def ext_cmd_hash_password(source, password: str):
    if not _console_only(source, "hash_password"):
        return
    if not password:
        source.reply(RText("§c[FAIL] 用法 usage: !!secure_shell hash_password <密码>§r"))
        return
    salt = secrets.token_bytes(16)
    iters = 200000
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters).hex()
    line = f"pbkdf2_sha256${iters}${salt.hex()}${digest}"
    _audit("生成密码哈希", result="已输出到控制台 (printed to console only)")
    source.reply(f"§7[INFO] 把下面这行填入 config 的 ext_password_pbkdf2（此行含密码派生值，勿外发）:§r")
    source.reply(line)


# ---------------------------------------------------------------------------
# 命令处理器
# ---------------------------------------------------------------------------
@new_thread
def shell_cmd(source: CommandSource, command: str):
    # 1. 扩展引擎必须已启用，否则给出指引（这是主插件"默认不带 shell"的核心闸门）
    if _ext_module is None:
        if source.is_player:
            source.reply(RText("§c[FAIL] shell 功能未启用 (shell engine not enabled)§r"))
        else:
            source.reply(RText("§c[FAIL] shell 引擎未启用 (shell engine not enabled)§r"))
            source.reply(f"§7[INFO] 安装扩展: !!secure_shell install_ext §7→ 启用: !!secure_shell enable_ext§r")
        return

    # 2. 游戏内执行默认禁用（v2.0.2 起）：仅 MCDR 控制台可用，需显式开启且玩家满足权限等级
    req_perm = _config.get("required_permission", 4)
    if source.is_player and not _config.get("allow_player_execution", False):
        source.reply(RText(f"§c[FAIL] 游戏内执行默认禁用，仅限控制台 (in-game execution disabled by default, console only)。如需开启 set allow_player_execution=true in config，且玩家权限等级需 ≥ {req_perm}§r"))
        _audit("玩家执行禁用", player=source.player, command=command,
               result="allow_player_execution=False")
        return

    # 3. 权限闸门
    if not source.has_permission(req_perm):
        source.reply(RText(f"§c[FAIL] 权限不足 (permission denied)：需要 MCDR 权限等级 {req_perm}§r"))
        _audit("权限不足", player=source.player if source.is_player else "控制台",
               command=command, result=f"需要权限{req_perm}")
        return

    # 4. 委托给扩展引擎执行
    player = source.player if source.is_player else "控制台"
    _ext_module.handle_shell(source, command, player)


# ---------------------------------------------------------------------------
# 生命周期
# ---------------------------------------------------------------------------
def _shell_status(source: CommandSource):
    """查看各开关状态（管理员可查看）。"""
    if not source.has_permission(_config.get("required_permission", 4)):
        source.reply(RText("§c[FAIL] 权限不足 (permission denied)§r"))
        return
    en = _config.get("enforce_allowlist", False)
    mode = "§a开启 ON§r（只允许白名单命令 allowlist-only）" if en else "§e关闭 OFF§r（放行任意命令 any command，危险命令黑名单仍兜底 blacklist still applies）"
    source.reply(f"§7[INFO] 白名单 allowlist 强制: {mode}")
    if not en:
        source.reply(f"§7  黑名单拦截仍在生效 blacklist always applies：rm -rf /、shutdown 等会被拒绝 denied")
    else:
        source.reply(f"§7  当前白名单 allowlist {len(_config.get('allowlist', []))} 条 entries，可用 !!shellstatus 查看")
    pe = _config.get("allow_player_execution", False)
    pe_mode = "§e开启 ON§r（玩家需权限等级 ≥ %d）" % _config.get("required_permission", 4) if pe else "§c关闭 OFF§r（仅控制台 console only）"
    source.reply(f"§7[INFO] 游戏内执行 in-game execution: {pe_mode}")
    # 扩展状态
    state = _load_state()
    if _ext_module is not None:
        ext_line = f"§a已启用 enabled§r（引擎 v{_ext_module.EXT_VERSION}）"
    elif _ext_py().exists():
        ext_line = f"§e已安装未启用 installed, disabled§r（v{state.get('installed_version', '?')}）"
    else:
        ext_line = "§c未安装 not installed§r"
    source.reply(f"§7[INFO] shell 引擎 engine: {ext_line}")


def on_load(server: PluginServerInterface, prev_module):
    global _ext_module
    load_config(server)

    # shell 执行入口（引擎未启用时给指引）
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

    # 扩展包管理（全部仅控制台）
    root = Literal('!!secure_shell')
    root.then(Literal('install_ext').then(GreedyText('password').requires(lambda s: not s.is_player, lambda s: s.reply(RText("§c[FAIL] 扩展包管理仅限控制台 (console only)§r"))).runs(
        lambda src, ctx: ext_cmd_install(src, ctx['password'].strip()))).runs(lambda src: ext_cmd_install(src)))
    root.then(Literal('check_ext').runs(lambda src: ext_cmd_check(src)))
    root.then(Literal('uninstall_ext').then(GreedyText('password').requires(lambda s: not s.is_player, lambda s: s.reply(RText("§c[FAIL] 扩展包管理仅限控制台 (console only)§r"))).runs(
        lambda src, ctx: ext_cmd_uninstall(src, ctx['password'].strip()))).runs(lambda src: ext_cmd_uninstall(src)))
    root.then(Literal('enable_ext').runs(lambda src: ext_cmd_enable(src)))
    root.then(Literal('disable_ext').runs(lambda src: ext_cmd_disable(src)))
    root.then(Literal('hash_password').then(GreedyText('password').runs(
        lambda src, ctx: ext_cmd_hash_password(src, ctx['password'].strip()))))
    server.register_command(root)

    # 已启用状态下重启：静默重载引擎（enable 是管理员的持久决定；安装/下载永远不会自动发生）
    state = _load_state()
    if state.get("enabled") and _ext_py().exists():
        try:
            _ext_load_module()
            server.logger.info(f"[INFO] shell 引擎已自动载入 (engine autoloaded) v{_ext_module.EXT_VERSION}")
        except Exception as e:
            server.logger.error(f"[ERROR] shell 引擎载入失败 (engine load failed): {e}")

    server.logger.info("[INFO] ShellExecutor 已加载 (主插件 v" + MAIN_VERSION + ")")
    server.logger.info(f"[INFO] 平台: {platform.system()} | shell 引擎: {'已启用' if _ext_module else '未启用'} | 审计日志: logs/secure_shell.log")


def on_unload(server):
    _audit("卸载")
    server.logger.info("ShellExecutor 已卸载")
