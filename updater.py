#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub 版本检查和 Windows 单文件 exe 自更新。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

REPO_FULL_NAME = "paynehe3023/devices_neighbors"
DEFAULT_MANIFEST_URL = (
    f"https://raw.githubusercontent.com/{REPO_FULL_NAME}/main/version.json"
)
RELEASE_API_URL = f"https://api.github.com/repos/{REPO_FULL_NAME}/releases/latest"
USER_AGENT = "devices-neighbors-updater"
HTTP_TIMEOUT = 15
CHUNK_SIZE = 256 * 1024


class UpdateError(RuntimeError):
    """更新流程中的可展示错误。"""


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    download_url: str
    notes: str = ""
    published_at: str = ""
    sha256: str = ""


def _version_key(value: str) -> tuple[int, int, int, int]:
    match = re.search(r"(\d+(?:\.\d+)*)", str(value).strip())
    if not match:
        raise UpdateError(f"无效版本号: {value}")
    parts = [int(part) for part in match.group(1).split(".")]
    return tuple((parts + [0, 0, 0, 0])[:4])


def is_newer(remote_version: str, current_version: str) -> bool:
    return _version_key(remote_version) > _version_key(current_version)


def _request(url: str) -> Request:
    return Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json, application/json",
        },
    )


def _read_json(url: str) -> dict:
    try:
        with urlopen(_request(url), timeout=HTTP_TIMEOUT) as response:
            raw = response.read()
    except HTTPError as exc:
        if exc.code == 404:
            raise
        raise UpdateError(f"更新服务器返回 HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"无法连接更新服务器: {exc}") from exc

    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError("更新清单格式无效") from exc
    if not isinstance(payload, dict):
        raise UpdateError("更新清单必须是 JSON 对象")
    return payload


def _clean_sha256(value: object) -> str:
    digest = str(value or "").strip().lower()
    if digest.startswith("sha256:"):
        digest = digest.split(":", 1)[1]
    if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise UpdateError("更新清单中的 sha256 无效")
    return digest


def _manifest_from_version_json(payload: dict) -> UpdateInfo:
    version = str(
        payload.get("version")
        or payload.get("latest_version")
        or payload.get("tag_name")
        or ""
    ).strip()
    download_url = str(
        payload.get("download_url")
        or payload.get("asset_url")
        or payload.get("url")
        or ""
    ).strip()
    if not version or not download_url:
        raise UpdateError("version.json 缺少 version 或 download_url")
    return UpdateInfo(
        version=version,
        download_url=download_url,
        notes=str(payload.get("notes") or payload.get("changelog") or "").strip(),
        published_at=str(payload.get("published_at") or "").strip(),
        sha256=_clean_sha256(payload.get("sha256")),
    )


def _manifest_from_release(payload: dict) -> UpdateInfo:
    version = str(payload.get("tag_name") or payload.get("name") or "").strip()
    assets = payload.get("assets") or []
    exe_assets = [
        asset
        for asset in assets
        if str(asset.get("name") or "").lower().endswith(".exe")
    ]
    asset = exe_assets[0] if exe_assets else None
    if not version or not asset:
        raise UpdateError("GitHub Release 缺少版本标签或 exe 资产")
    return UpdateInfo(
        version=version,
        download_url=str(asset.get("browser_download_url") or "").strip(),
        notes=str(payload.get("body") or "").strip(),
        published_at=str(payload.get("published_at") or "").strip(),
        sha256=_clean_sha256(asset.get("digest")),
    )


def check_for_update(
    current_version: str, manifest_url: str = DEFAULT_MANIFEST_URL
) -> UpdateInfo | None:
    """返回较新的版本信息；已是最新版则返回 None。"""
    try:
        payload = _read_json(manifest_url)
        info = _manifest_from_version_json(payload)
    except HTTPError as exc:
        if exc.code != 404:
            raise UpdateError(f"更新清单不可访问: HTTP {exc.code}") from exc
        try:
            payload = _read_json(RELEASE_API_URL)
            info = _manifest_from_release(payload)
        except HTTPError as release_exc:
            if release_exc.code == 404:
                raise UpdateError(
                    "仓库中还没有 version.json，也没有可用的 GitHub Release"
                ) from release_exc
            raise UpdateError(
                f"GitHub Release 不可访问: HTTP {release_exc.code}"
            ) from release_exc

    return info if is_newer(info.version, current_version) else None


def _update_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    path = Path(base) / "devices_neighbors" / "updates"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _download_name(url: str) -> str:
    name = unquote(urlparse(url).path.rsplit("/", 1)[-1])
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip()
    if not name.lower().endswith(".exe"):
        name = "网络拓扑扫描工具.exe"
    return name


def download_update(
    url: str,
    expected_sha256: str = "",
    progress=None,
    cancel_event=None,
) -> Path:
    """下载并校验 exe，返回本地文件路径。"""
    target = _update_dir() / _download_name(url)
    part = target.with_suffix(target.suffix + ".part")
    part.unlink(missing_ok=True)

    digest = hashlib.sha256()
    received = 0
    first_bytes = b""
    try:
        with urlopen(_request(url), timeout=HTTP_TIMEOUT) as response:
            total = int(response.headers.get("Content-Length") or 0)
            with open(part, "wb") as output:
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise UpdateError("更新下载已取消")
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    if not first_bytes:
                        first_bytes = chunk[:2]
                    output.write(chunk)
                    digest.update(chunk)
                    received += len(chunk)
                    if progress is not None:
                        progress(received, total)
    except HTTPError as exc:
        part.unlink(missing_ok=True)
        if exc.code == 404:
            raise UpdateError(
                "下载地址不存在(HTTP 404): 请确认已在 GitHub Release 上传 exe 附件, "
                "且附件名与 version.json 的 download_url 完全一致"
            ) from exc
        raise UpdateError(f"下载更新失败: HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        part.unlink(missing_ok=True)
        raise UpdateError(f"下载更新失败: {exc}") from exc
    except UpdateError:
        part.unlink(missing_ok=True)
        raise

    if first_bytes != b"MZ":
        part.unlink(missing_ok=True)
        raise UpdateError("下载内容不是有效的 Windows 程序，请检查下载地址")

    expected = _clean_sha256(expected_sha256)
    actual = digest.hexdigest()
    if expected and actual != expected:
        part.unlink(missing_ok=True)
        raise UpdateError("更新文件校验失败，已删除下载内容")

    os.replace(part, target)
    return target


def can_self_update() -> bool:
    return bool(getattr(sys, "frozen", False))


def _check_target_writable(target: Path) -> None:
    probe = target.parent / f".{target.stem}.update_test"
    try:
        probe.write_bytes(b"1")
        probe.unlink()
    except OSError as exc:
        raise UpdateError(f"程序目录不可写，请用管理员权限运行后再更新: {exc}") from exc


def launch_updater(downloaded_exe: Path) -> Path:
    """启动独立脚本，等待当前进程退出后替换 exe 并重启。"""
    if not can_self_update():
        raise UpdateError("开发模式下不会自动替换程序，请手动运行下载的新版本")

    new_exe = Path(downloaded_exe).resolve()
    target = Path(sys.executable).resolve()
    if not new_exe.is_file():
        raise UpdateError("更新文件不存在，请重新下载")
    if new_exe == target:
        raise UpdateError("更新文件与当前程序路径相同")
    _check_target_writable(target)

    script = new_exe.parent / "apply_update.cmd"
    script.write_text(
        "\n".join(
            [
                "@echo off",
                "setlocal EnableExtensions",
                'set "NEW=%~1"',
                'set "TARGET=%~2"',
                'set "PID=%~3"',
                "set /a tries=0",
                ":wait",
                'tasklist /FI "PID eq %PID%" /NH 2>nul | find "%PID%" >nul',
                "if not errorlevel 1 (",
                "  ping -n 2 127.0.0.1 >nul",
                "  goto wait",
                ")",
                ":replace",
                'move /Y "%NEW%" "%TARGET%" >nul 2>&1',
                "if not errorlevel 1 goto restart",
                "set /a tries+=1",
                "if %tries% GEQ 30 goto restart",
                "ping -n 2 127.0.0.1 >nul",
                "goto replace",
                ":restart",
                'start "" /D "%~dp2" "%TARGET%"',
                'del "%~f0" >nul 2>&1',
            ]
        )
        + "\n",
        encoding="ascii",
    )

    # 只用 CREATE_NO_WINDOW (隐藏控制台)。切勿加 DETACHED_PROCESS(0x8):
    # 那会让 cmd.exe 失去控制台, 脚本中的管道/find/ping 会失效, 整个替换流程静默失败,
    # 表现为"点安装后没有新版"。实测: 带 0x8 时脚本 0.2s 直接退出且未替换文件。
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.Popen(
            [
                "cmd.exe",
                "/d",
                "/c",
                str(script),
                str(new_exe),
                str(target),
                str(os.getpid()),
            ],
            close_fds=True,
            creationflags=flags,
        )
    except OSError as exc:
        raise UpdateError(f"无法启动更新程序: {exc}") from exc
    return script
