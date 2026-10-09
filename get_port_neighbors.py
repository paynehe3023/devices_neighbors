#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全网交换机端口"上下联"拓扑探测工具 v2
================================================================
核心修复: LLDP 邻居解析不再要求 System name —— 缺失时用 Chassis ID
兜底, 永不丢弃邻居 (旧版把 GE0/0/2、GE0/0/8 这类邻居静默丢进 MAC 轨)。

新增能力:
  1. 默认单机模式(只扫指定一台); --recursive 才全网递归发现
  2. 按设备角色判定每个端口的 上联/下联 方向
  3. MAC 轨 OUI 厂商识别 (manuf + 内置补充库) + ARP 关联 IP
  4. 报表: port_topology.csv / network_links.csv / --query 单口查询

用法:
  python get_port_neighbors.py                    # 单机模式: 只扫 TARGET_SWITCH 一台
  python get_port_neighbors.py --recursive        # 显式开启全网递归发现
  python get_port_neighbors.py --query GE0/0/49   # 扫描后查询指定端口上下联
  python get_port_neighbors.py --query GE0/0/49 --offline  # 用上次缓存查询, 不重扫
"""
import argparse
import concurrent.futures as _cf
import csv
import json
import os
import re
import socket
import struct
import sys
import threading
from collections import defaultdict
from netmiko import ConnectHandler

# ==================== 配置区 ====================
APP_VERSION = "1.0.3"
# 凭据不落盘: 优先环境变量, 其次由交互模式/GUI/批量CSV在运行时注入
USERNAME = os.environ.get("TOPO_USERNAME", "admin")
PASSWORD = os.environ.get("TOPO_PASSWORD", "")
# 单机模式目标: 仅指定 IP, 设备名(sysname)登录后动态获取; --recursive 才递归发现全网
TARGET_SWITCH = {"host": "10.175.10.65"}
MAX_SCAN = 256                         # --recursive 防失控上限(公司网络规模内不会截断)
MAX_WORKERS = 6                        # 并发SSH扫描数(华为默认并发会话有限, 不宜过大)
CONN_TIMEOUT = 18                      # SSH 握手较慢, 需 >=15s
# 附加 ARP 来源: 只登录拉 display arp 补全 MAC->IP 视角(不递归扫描),
# 解决"终端IP在网关/核心ARP表而本机查不到"的问题。可配置多台。
ARP_SOURCES = [{"host": "10.175.10.254", "name": "CoreSW-INTERNET-01"}]
AUTO_ARP_UPLINK = True                 # ARP_SOURCES 为空时, 自动尝试借用 LLDP 上联设备的 ARP
PROBE_HOSTNAME = True                  # 对终端口探测主机名(NetBIOS/mDNS); 网络关闭时静默无结果, 不影响其余功能
TERMINAL_MAC_LIMIT = 3                 # 端口MAC数 <= 该值视为终端口(与 build_records 共用)
OUTPUT_CSV = "port_topology.csv"
LINKS_CSV = "network_links.csv"
MAC_DETAIL_CSV = "mac_detail.csv"      # 端口MAC明细单独存放, 主表不再带
CACHE_JSON = "topology_cache.json"
# 这些命令"空回显"意味着数据不可信(而非真的没数据), 单独记为采集异常
_CRITICAL_CMDS = {"lldp_verbose", "mac_raw", "arp_raw", "ifbrief"}
# 已知设备名 -> 真实管理IP (缓存+本次扫描合并), 上联口对端IP优先取此映射
_KNOWN_IPS = {}
# ================================================

try:
    from manuf import manuf as _manuf
    _MAC_PARSER = _manuf.MacParser()
except Exception:
    _MAC_PARSER = None

# OUI 补充库 (manuf 缺失的厂商, 本网络实测验证: API/多台设备交叉确认)
OUI_EXTRA = {
    "08cc81": "Hikvision(海康威视)", "548c81": "Hikvision(海康威视)",
    "dc07f8": "Hikvision(海康威视)", "3c1bf8": "Hikvision(海康威视)",
    "244845": "Hikvision(海康威视)", "a4d5c2": "Hikvision(海康威视)",
    "807c62": "Hikvision(海康威视)", "bc5e33": "Hikvision(海康威视)",
    "346f11": "Zhipai(青岛智拍)", "10ffe0": "GIGA-BYTE(技嘉)",
    "10321d": "Huawei(华为)", "8c83e8": "Huawei(华为)", "000c29": "VMware(虚拟机)",
    "8c3223": "JWIPC(杰和科技)",   # 深信服等安全设备常用 OEM 硬件
}

# 设备角色: 3=核心 2=汇聚/无线控制器 1=接入交换机 0=终端
ROLE_CORE, ROLE_CTRL, ROLE_SW, ROLE_END = 3, 2, 1, 0


def normalize_port(port_name):
    """接口名规范化: GigabitEthernet0/0/3 -> GE0/0/3
    长前缀必须按长度降序匹配, 否则 40G/100G 会被 GigabitEthernet 子串抢先截断。"""
    if not port_name:
        return ""
    port_name = port_name.strip()
    for long, short in (("100GigabitEthernet", "100GE"), ("40GigabitEthernet", "40GE"),
                        ("10GigabitEthernet", "10GE"), ("XGigabitEthernet", "XGE"),
                        ("GigabitEthernet", "GE"), ("Ethernet", "Eth")):
        if re.match(rf"^{long}(?![A-Za-z])", port_name, flags=re.IGNORECASE):
            return short + port_name[len(long):]
    return port_name


def unescape_huawei(s):
    """还原华为非ASCII转义(UTF-8八进制字节): \\345\\215\\227\\346\\245\\274 -> 南楼"""
    if not s or "\\" not in s:
        return s
    def _repl(m):
        try:
            return bytes(int(x, 8) for x in m.group(0).split("\\")[1:]).decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)
    return re.sub(r'(?:\\[0-7]{3})+', _repl, s)


def parse_lldp_verbose(raw):
    """解析 'display lldp neighbor' 全量输出。
    关键修复: System name 缺失时用 Chassis ID 兜底, 绝不丢邻居。"""
    lldp = {}
    # 按端口分块: "GigabitEthernet0/0/2 has 1 neighbor(s):"
    parts = re.split(r'(?m)^(\S+)\s+has\s+\d+\s+neighbor', raw)
    for i in range(1, len(parts), 2):
        port = normalize_port(parts[i])
        for nsec in re.split(r'(?i)Neighbor\s*index\s*:\s*\d+', parts[i + 1]):
            if not nsec.strip():
                continue
            sys_name = re.search(r'(?im)^\s*System\s*name\s*:\s*(\S+)', nsec)
            chassis = re.search(r'(?im)^\s*Chassis\s*ID\s*:\s*(\S+)', nsec)
            chassis_type = re.search(r'(?im)^\s*Chassis\s*type\s*:\s*([^\n]+)', nsec)
            port_id = re.search(r'(?im)^\s*Port\s*ID\s*:\s*(\S+)', nsec)
            port_desc = re.search(r'(?im)^\s*Port\s*description\s*:\s*(\S+)', nsec)
            sys_desc = re.search(r'(?im)^\s*System\s*description\s*:\s*([^\n]+)', nsec)
            mgmt = re.search(r'(?im)^\s*Management\s*address\s*value\s*:\s*(\S+)', nsec)
            if not mgmt:
                mgmt = re.search(r'(?im)^\s*Management\s*address\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})', nsec)
            med = re.search(r'(?im)^\s*Device\s*class\s*:\s*([^\n]+)', nsec)
            if not chassis and not sys_name:
                continue
            model = ""
            if sys_desc:
                m = re.search(r'(?:Switch|Router)\s+([A-Za-z0-9-]+)', sys_desc.group(1))
                model = m.group(1) if m else sys_desc.group(1).strip()
            lldp[port] = {
                "remote_dev": unescape_huawei(sys_name.group(1) if sys_name else chassis.group(1)),
                "remote_port": normalize_port((port_id or port_desc).group(1)) if (port_id or port_desc) else "",
                "remote_ip": mgmt.group(1) if mgmt else "",
                "model": model,
                "chassis_type": chassis_type.group(1).strip() if chassis_type else "",
                "chassis_id": unescape_huawei(chassis.group(1)) if chassis else "",
                "sys_desc": sys_desc.group(1).strip() if sys_desc else "",
                "med_class": med.group(1).strip() if med else "",
                "source": "verbose",
            }
    return lldp


def parse_lldp_brief(raw):
    """解析 'display lldp neighbor brief' 表格 (兜底: 对端设备列 '-' 也算)"""
    brief = {}
    for line in raw.splitlines():
        p = line.split()
        if len(p) >= 3 and re.match(r'^(Eth-Trunk|GE|XGE|10GE|Eth|GigabitEthernet)', p[0]):
            brief[normalize_port(p[0])] = {"dev": unescape_huawei(p[1]), "port": p[2]}
    return brief


def parse_mac(raw):
    """解析 'display mac-address' -> {端口: [{mac, vlan}]}"""
    mac_map = defaultdict(list)
    for line in raw.splitlines():
        m = re.search(r'([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(\d+)\S*\s+(\S+)', line)
        if m:
            mac_map[normalize_port(m.group(3))].append({"mac": m.group(1).lower(), "vlan": m.group(2)})
    return dict(mac_map)


def parse_arp(raw):
    """解析 'display arp' -> {mac: ip} (跳过表头/续行/Total)"""
    arp = {}
    for line in raw.splitlines():
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})', line)
        if m:
            arp[m.group(2).lower()] = m.group(1)
    return arp


_NON_PHYSICAL = r'^(?:Vlanif|NULL|MEth|InLoopBack|Tunnel|Vbdif|MPLS|WAN|Virtual-Template|LoopBack)'


def parse_ifbrief(raw):
    """解析 'display interface brief' -> {端口: up/down} (排除Vlanif/NULL/MEth等逻辑口)"""
    st = {}
    for line in raw.splitlines():
        m = re.match(r'^(\S+)\s+(up|down|\*down|#down)\s+(up|down|\*down|#down)', line)
        if m:
            p = m.group(1)
            if re.match(_NON_PHYSICAL, p, flags=re.IGNORECASE):
                continue
            st[normalize_port(p)] = "up" if m.group(2) == "up" else "down"
    return st


def parse_ifdesc(raw):
    """解析 'display interface description' -> {端口: 描述} (排除逻辑口/缩进成员行)"""
    desc = {}
    for line in raw.splitlines():
        m = re.match(r'^(\S+)\s+(?:up|down|\*down|#down)\s+(?:up|down|\*down|#down)\s*(.*)$', line)
        if m:
            p = m.group(1)
            if re.match(_NON_PHYSICAL, p, flags=re.IGNORECASE):
                continue
            d = unescape_huawei(m.group(2).strip())
            if d:
                desc[normalize_port(p)] = d
    return desc


def parse_gateway(raw):
    """解析默认路由下一跳 (display ip routing-table) -> 网关IP或''"""
    for line in raw.splitlines():
        m = re.match(r'^\s*0\.0\.0\.0/0\s+\S+\s+\d+\s+\d+\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})', line)
        if m:
            return m.group(1)
    return ""


def parse_eth_trunk(raw):
    """解析 'display eth-trunk' -> {trunk: [成员口]}"""
    trunks, cur = {}, None
    for line in raw.splitlines():
        m = re.match(r'^(Eth-Trunk\d+)\s*\'?s state', line)
        if m:
            cur = m.group(1)
            trunks[cur] = []
            continue
        m = re.match(r'^\s*(100GigabitEthernet|40GigabitEthernet|10GigabitEthernet|XGigabitEthernet|GigabitEthernet|Ethernet)(\S+)\s+(Up|Down)\s+\d+', line)
        if m and cur is not None:
            trunks[cur].append(normalize_port(m.group(1) + m.group(2)))
    return trunks


def vendor_of(mac):
    """MAC -> 厂商 (OUI_EXTRA 优先, manuf 兜底)"""
    m = mac.replace("-", "").lower()
    if len(m) >= 6 and m[:6] in OUI_EXTRA:
        return OUI_EXTRA[m[:6]]
    if _MAC_PARSER:
        try:
            colon = ":".join(m[i:i + 2] for i in range(0, 12, 2))
            fn = getattr(_MAC_PARSER, "get_manuf_long", None)
            name = fn(colon) if fn else None
            return name or _MAC_PARSER.get_manuf(colon) or "未知"
        except Exception:
            pass
    return "未知"


def role_of(name, model="", sys_desc=""):
    """按 设备名+型号+描述 判角色"""
    t = f"{name} {model} {sys_desc}".lower()
    if any(k in t for k in ("s6730", "s127", "core", "s7700", "s9700", "s9300")):
        return ROLE_CORE
    if any(k in t for k in ("ac6507", "airengine", "9700s", "wlan", "controller")):
        return ROLE_CTRL
    # 接入交换机: 关键字(switch/router/s57) 或 命名约定(SW-/SW_/-SW/ACC/交换机)
    if any(k in t for k in ("switch", "router", "s57", "acc", "交换机")):
        return ROLE_SW
    if re.search(r'(?:^|[^a-z])sw(?:[^a-z]|$)', name.lower()):
        return ROLE_SW
    return ROLE_END


def _dns_encode_name(name):
    """域名 -> DNS 线格式 (长度前缀标签 + 结尾 0x00)"""
    body = b"".join(bytes([len(p)]) + p.encode("ascii", "ignore") for p in name.split(".") if p)
    return body + b"\x00"


def _dns_read_name(data, off):
    """读取 DNS 名称(支持 0xC0 压缩指针, 限 64 跳防环) -> (名称, 读完后偏移)"""
    labels, end, jumped, hops = [], off, False, 0
    while off < len(data) and hops < 64:
        hops += 1
        ln = data[off]
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            break
        if ln & 0xC0:                       # 压缩指针: 跳转, 并记录本名称的结束位置
            if not jumped:
                end = off + 2
            off = ((ln & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + ln].decode("latin-1", "ignore"))
        off += ln
        if not jumped:
            end = off
    return ".".join(labels), (end if jumped else off)


def _nb_encode_name(stage=b"*"):
    """NetBIOS-NS 名称编码: 16 字节按半字节拆开各 +0x41, 前置长度字节 0x20, 末尾 0x00 终止 -> 共 34 字节"""
    raw = (stage + b" " * 16)[:16]
    nib = b"".join(bytes((b >> 4, b & 0x0F)) for b in raw)
    return b"\x20" + bytes(b + 0x41 for b in nib) + b"\x00"


def _netbios_name(ip, timeout=1.8):
    """NetBIOS 名称查询 (UDP137, NBSTAT 通配) -> 主机名或 ''
    报文 = 12字节头 + 34字节编码名(含终止符) + qtype(0x0021) + qclass(0x0001);
    NBSTAT 应答 RDATA = 1字节名数量 + N*(15字节名 + 1字节后缀 + 2字节标志)。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        pkt = (struct.pack(">HHHHHH", 0xABCD, 0x0010, 1, 0, 0, 0)
               + _nb_encode_name() + struct.pack(">HH", 0x0021, 0x0001))
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(4096)
        if len(data) < 12:
            return ""
        ancount = struct.unpack(">H", data[6:8])[0]
        off = _dns_read_name(data, 12)[1] + 4          # 跳过 question 区
        cands = []
        for _ in range(ancount):
            off = _dns_read_name(data, off)[1]
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata, off = data[off:off + rdlen], off + rdlen
            if rtype != 0x0021 or not rdata:
                continue
            p = 1
            for _ in range(rdata[0]):
                if p + 18 > len(rdata):
                    break
                entry = rdata[p:p + 16]
                flags = struct.unpack(">H", rdata[p + 16:p + 18])[0]
                p += 18
                nm = entry[:15].rstrip(b" \x00").decode("latin-1", "ignore")
                if nm:
                    cands.append((entry[15], bool(flags & 0x8000), nm))
        for suffix, is_group, nm in cands:             # 优先唯一的工作站名(名+0x00)
            if suffix == 0x00 and not is_group:
                return nm
        return cands[0][2] if cands else ""
    except Exception:
        return ""
    finally:
        if s:
            s.close()


def _mdns_name(ip, timeout=1.8):
    """mDNS PTR 反查 (UDP5353, QU位置 1 请求单播应答) -> 主机名或 ''
    置 QU 位后应答单播回查询源端口, 因此无需 bind 5353 / 加入组播组。"""
    s = None
    try:
        rev = ".".join(ip.split(".")[::-1]) + ".in-addr.arpa"
        pkt = (struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
               + _dns_encode_name(rev) + struct.pack(">HH", 12, 0x8001))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, ("224.0.0.251", 5353))
        data, _ = s.recvfrom(4096)
        if len(data) < 12:
            return ""
        ancount = struct.unpack(">H", data[6:8])[0]
        off = _dns_read_name(data, 12)[1] + 4          # 跳过 question 区
        for _ in range(ancount):
            off = _dns_read_name(data, off)[1]
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rstart, off = off, off + rdlen
            if rtype == 12:                            # PTR
                return _dns_read_name(data, rstart)[0].split(".")[0]
        return ""
    except Exception:
        return ""
    finally:
        if s:
            s.close()


def _dns_name(ip):
    """反向 DNS (PTR 记录) -> 短主机名或 '' (内网DNS通常命中率最高)"""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host = host.split(".")[0].strip()
        if host and host != ip:
            return host
    except Exception:
        pass
    return ""


def enrich_hostnames(data):
    """对终端口并发探测主机名 (DNS PTR -> NetBIOS -> mDNS), 存 data['hostnames']={ip:name};
    网络关闭/无响应时静默跳过, 不影响其余功能。"""
    data["hostnames"] = {}
    if not PROBE_HOSTNAME:
        return data
    targets = set()
    for port, macs in data["macs"].items():
        if len(macs) <= TERMINAL_MAC_LIMIT:      # 终端特征: 少量MAC
            for m in macs:
                ip = data["arp"].get(m["mac"], "")
                if ip:
                    targets.add(ip)
    if not targets:
        return data

    def _probe(ip):
        return _dns_name(ip) or _netbios_name(ip) or _mdns_name(ip)

    # 注意: 不能用 with ThreadPoolExecutor(...), 其 __exit__ 会 join 所有任务,
    # 使"总预算"形同虚设; 这里超预算后直接放弃掉队任务。
    ex = _cf.ThreadPoolExecutor(max_workers=24)
    try:
        futs = {ex.submit(_probe, ip): ip for ip in sorted(targets)}
        done, _pending = _cf.wait(futs, timeout=12)     # 全部探测总预算12s
        for f in done:
            ip = futs[f]
            try:
                name = f.result()
            except Exception:
                name = ""
            if name:
                data["hostnames"][ip] = name
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    if data["hostnames"]:
        hit = ", ".join(f"{k}={v}" for k, v in list(data["hostnames"].items())[:12])
        print(f"  💻 主机名探测命中 {len(data['hostnames'])}/{len(targets)}: {hit}" + (" ..." if len(data["hostnames"]) > 12 else ""))
    else:
        print(f"  💻 主机名探测 0/{len(targets)} (目标多无 DNS PTR/NetBIOS/mDNS 响应)")
    return data


def _connect(host):
    """建立华为设备 SSH 连接(统一超时参数)"""
    if not PASSWORD:
        raise RuntimeError("未提供交换机密码: 请设置环境变量 TOPO_PASSWORD, 或改用交互模式/GUI 输入")
    return ConnectHandler(device_type="huawei", host=host, username=USERNAME, password=PASSWORD,
                          conn_timeout=CONN_TIMEOUT, auth_timeout=CONN_TIMEOUT,
                          banner_timeout=CONN_TIMEOUT, system_host_keys=False)


_ARP_CACHE = {}                          # host -> {mac: ip}, 并发扫描时同一来源只拉一次
_ARP_LOCK = threading.Lock()


def _fetch_source_arp(host):
    if host not in _ARP_CACHE:
        with _ARP_LOCK:
            if host not in _ARP_CACHE:
                c = _connect(host)
                try:
                    raw = c.send_command("display arp", read_timeout=120)
                finally:
                    c.disconnect()
                _ARP_CACHE[host] = parse_arp(raw)
    return _ARP_CACHE[host]


def enrich_arp_from_sources(data):
    """借用网关/核心的 ARP 表补全本机 MAC->IP 视角。
    只拉取 display arp 一张表(不递归扫描其他数据); 本机 ARP 优先级最高, 缺失的用网关补。"""
    sources = list(ARP_SOURCES)
    if AUTO_ARP_UPLINK and not sources:
        for rec in data["lldp_verbose"].values():
            ip = rec.get("remote_ip", "")
            if ip and role_of(rec.get("remote_dev", ""), rec.get("model", ""), rec.get("sys_desc", "")) >= ROLE_SW:
                sources.append({"host": ip, "name": rec.get("remote_dev", "")})
                break   # 只借第一台上联设备, 保持轻量
    merged = {}
    for s in sources:
        host, name = s["host"], s.get("name", "")
        try:
            arp = _fetch_source_arp(host)
            merged.update(arp)
            print(f"  📖 借用 {name or host} ARP 表: +{len(arp)} 条")
        except Exception as e:
            print(f"  ⚠ 借用 ARP 失败 {host}: {type(e).__name__}: {str(e)[:70]}")
    if merged:
        merged.update(data["arp"])     # 本机 ARP 覆盖优先
        before = len(data["arp"])
        data["arp"] = merged
        print(f"  🔗 MAC->IP 合并后共 {len(merged)} 条 (本机 {before} + 来源补充 {len(merged) - before})")
    return data


def scan_switch(host, name_hint=""):
    """单台交换机全量采集 (全部只读命令)"""
    conn = _connect(host)
    try:
        prompt = conn.find_prompt()
        # 设备名以设备实际 sysname 为准 (display sysname 在部分 VRP 非法, 用 include 方式)
        name = ""
        try:
            out = conn.send_command("display current-configuration | include sysname", read_timeout=20)
            m = re.search(r'(?im)^\s*sysname\s+(\S+)', out)
            if m and re.fullmatch(r'\S+', m.group(1)):
                name = unescape_huawei(m.group(1))
        except Exception:
            pass
        if not name:
            name = unescape_huawei(name_hint or prompt.strip("<>"))
        conn.send_command("screen-length 0 temporary")
        cmds = [
            ("lldp_verbose", "display lldp neighbor", 120),
            ("lldp_brief_raw", "display lldp neighbor brief", 60),
            ("mac_raw", "display mac-address", 180),
            ("arp_raw", "display arp", 120),
            ("ifbrief", "display interface brief", 60),
            ("ifdesc_raw", "display interface description", 60),
            ("route_raw", "display ip routing-table", 30),
            ("trunk_raw", "display eth-trunk", 60),
        ]
        out, cmd_errors = {}, []
        for key, cmd, tout in cmds:
            try:
                out[key] = conn.send_command(cmd, read_timeout=tout) or ""
            except Exception as e:
                print(f"    ⚠ {name} 命令失败 {cmd}: {e}")
                out[key] = ""
                cmd_errors.append(f"{cmd}({type(e).__name__})")
                continue
            if key in _CRITICAL_CMDS and not out[key].strip():
                print(f"    ⚠ {name} 命令无回显(数据可能不完整): {cmd}")
                cmd_errors.append(f"{cmd}(空回显)")
        return {
            "host": host, "name": name,
            "lldp_verbose": parse_lldp_verbose(out["lldp_verbose"]),
            "lldp_brief": parse_lldp_brief(out["lldp_brief_raw"]),
            "macs": parse_mac(out["mac_raw"]),
            "arp": parse_arp(out["arp_raw"]),
            "ifbrief": parse_ifbrief(out["ifbrief"]),
            "ifdesc": parse_ifdesc(out.get("ifdesc_raw", "")),
            "gateway": parse_gateway(out.get("route_raw", "")),
            "trunks": parse_eth_trunk(out["trunk_raw"]),
            "cmd_errors": cmd_errors,
        }
    finally:
        conn.disconnect()


def merge_brief(data):
    """brief 兜底: verbose 漏掉的口用 brief 补 (如仅出现在 brief 的邻居)"""
    for port, b in data["lldp_brief"].items():
        if port not in data["lldp_verbose"]:
            data["lldp_verbose"][port] = {
                "remote_dev": None if b["dev"] == "-" else b["dev"],
                "remote_port": None if b["port"] == "-" else b["port"],
                "remote_ip": "", "model": "", "chassis_type": "", "chassis_id": "",
                "sys_desc": "", "med_class": "", "source": "brief",
            }


def scan_network(recursive=False):
    """默认单机模式: 仅扫描 TARGET_SWITCH 一台; --recursive 时并发递归发现全网。
    并发: MAX_WORKERS 个SSH worker; ARP来源表经 _ARP_CACHE 只拉一次; MAX_SCAN 防失控。"""
    seen, all_data = set(), []
    lock = threading.Lock()

    def _submit(host):
        with lock:
            if host in seen or len(seen) >= MAX_SCAN:
                return False
            seen.add(host)
        print(f"🔌 连接 {host} ...")
        return True

    def _postprocess(d):
        merge_brief(d)
        enrich_arp_from_sources(d)   # 借用网关/核心 ARP 补全下联设备 IP
        enrich_hostnames(d)          # 终端口主机名探测(DNS PTR/NetBIOS/mDNS)
        n_lldp = len([p for p, r in d["lldp_verbose"].items() if r.get("remote_dev")])
        print(f"  ✓ {d['name']} ({d['host']}) | LLDP邻居 {n_lldp} 口 | 有MAC端口 {len(d['macs'])} | 接口 {len(d['ifbrief'])}")
        errs = d.get("cmd_errors") or []
        if errs:
            print(f"    ⚠ {d['name']} 采集异常 {len(errs)} 项, 报表数据可能不完整: " + "; ".join(errs))

    _submit(TARGET_SWITCH["host"])
    with _cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        pending = {ex.submit(scan_switch, h, ""): h for h in list(seen)}
        while pending:
            done, _ = _cf.wait(pending, return_when=_cf.FIRST_COMPLETED)
            for f in done:
                host = pending.pop(f)
                try:
                    d = f.result()
                except Exception as e:
                    print(f"  ⚠ {host} 扫描失败, 跳过: {type(e).__name__}: {str(e)[:120]}")
                    continue
                with lock:
                    all_data.append(d)
                _postprocess(d)
                if recursive:   # 仅显式开启时, 才用 LLDP 邻居管理IP 递归
                    gw = d.get("gateway", "")
                    myrole = max(role_of(d["name"]), ROLE_SW)
                    for rec in d["lldp_verbose"].values():
                        ip = rec.get("remote_ip", "")
                        if not ip:
                            continue
                        nrole = role_of(rec.get("remote_dev", ""), rec.get("model", ""), rec.get("sys_desc", ""))
                        if gw and nrole > myrole:   # 上联设备: LLDP自报地址常为不可达管理口, 用网关IP入队
                            ip = gw
                        if _submit(ip):
                            pending[ex.submit(scan_switch, ip, "")] = ip
    return all_data


def build_known_ips(all_data):
    """合并缓存与本次扫描: 设备名 -> 真实管理IP (上联口对端IP修正用)"""
    known = {}
    try:
        for d in json.load(open(CACHE_JSON, encoding="utf-8")):
            if d.get("name") and d.get("host"):
                known[d["name"]] = d["host"]
    except Exception:
        pass
    for d in all_data:
        if d.get("name") and d.get("host"):
            known[d["name"]] = d["host"]
    _KNOWN_IPS.clear()
    _KNOWN_IPS.update(known)


def build_records(data):
    """每个物理端口组装完整记录 + 上下联方向判定"""
    my_role = max(role_of(data["name"]), ROLE_SW)   # 能执行交换机命令 => 至少接入交换机
    trunk_of = {}
    for trunk, members in data["trunks"].items():
        for m in members:
            trunk_of[m] = trunk

    ports = {}
    all_ports = set(data["ifbrief"]) | set(data["lldp_verbose"]) | set(data["macs"])
    for port in all_ports:
        rec = {"device": data["name"], "host": data["host"], "port": port,
               "status": data["ifbrief"].get(port, "down"),
               "dir": "", "remote_dev": "", "remote_port": "", "remote_model": "",
               "remote_ip": "", "remote_mac": "", "evidence": "", "mac_count": 0,
               "vlans": "", "terminal": "", "hostname": ""}
        macs = data["macs"].get(port, [])
        rec["mac_count"] = len(macs)
        vlans = sorted({m["vlan"] for m in macs})
        rec["vlans"] = ",".join(vlans)
        vendors = {}
        for m in macs:
            v = vendor_of(m["mac"])
            vendors[v] = vendors.get(v, 0) + 1
        top_vendor = max(vendors, key=vendors.get) if vendors else ""
        # 终端识别: 厂商(未知不显示) + MED中文类别 + [PC], 主机名独立到 hostname 列
        rec["terminal"] = top_vendor if top_vendor and top_vendor != "未知" else ""

        if rec["status"] == "down" and port not in data["lldp_verbose"] and not macs:
            rec["dir"] = "未连接"
            ports[port] = rec
            continue

        lldp = data["lldp_verbose"].get(port)
        if lldp and lldp.get("remote_dev"):
            rec["remote_dev"] = lldp["remote_dev"]
            rec["remote_port"] = lldp["remote_port"] or ""
            rec["remote_model"] = lldp["model"]
            rec["remote_ip"] = lldp["remote_ip"]
            # 对端设备名/端口只填真实值: MAC/非端口名格式一律留空
            if re.fullmatch(r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}", rec["remote_dev"]):
                rec["remote_dev"] = ""
            if not re.match(r"^(?:GE|XGE|10GE|40GE|100GE|Eth-Trunk|Eth|MEth)\d", rec["remote_port"]):
                rec["remote_port"] = ""
            nrole = role_of(lldp["remote_dev"], lldp["model"], lldp["sys_desc"])
            if nrole > my_role:
                rec["dir"] = "上联"
            elif nrole < my_role:
                rec["dir"] = "下联"
            else:
                rec["dir"] = "平级/互联"
            rec["evidence"] = f"LLDP({lldp.get('source','')})"
            if lldp.get("med_class"):
                med_cn = {"EndPoint Class I": "终端", "EndPoint Class II": "终端(多功能)",
                          "EndPoint Class III": "IP电话"}.get(lldp["med_class"], lldp["med_class"])
                rec["terminal"] = (rec["terminal"] + " " + med_cn).strip()
        else:
            ifdesc = (data.get("ifdesc") or {}).get(port, "")
            if len(macs) >= 10 or len(vlans) > 1:
                rec["dir"] = "上联/汇聚"
                rec["evidence"] = f"MAC多设备({len(macs)}MAC/{len(vlans)}VLAN)"
                rec["remote_dev"] = f"描述:{ifdesc}" if ifdesc else "未知(未开LLDP)"
            elif port in trunk_of:
                rec["dir"] = "汇聚下联"
                rec["evidence"] = f"Eth-Trunk({trunk_of[port]})"
                rec["remote_dev"] = f"描述:{ifdesc}" if ifdesc else "未知(未开LLDP)"
            elif macs:
                rec["dir"] = "下联终端"
                rec["evidence"] = "MAC" + ("+描述" if ifdesc else "")
                if ifdesc:
                    rec["remote_dev"] = f"描述:{ifdesc}"
                else:
                    # 非LLDP终端口身份推断: 多IP=>多接口设备(网关/防火墙/HA); .1/.254=>疑似网关
                    ips = {data["arp"].get(m["mac"]) for m in macs if data["arp"].get(m["mac"])}
                    if len(ips) >= 2:
                        rec["remote_dev"] = "多接口设备(疑似网关/防火墙/HA)"
                        vs = sorted({vendor_of(m["mac"]) for m in macs} - {"未知"})
                        rec["terminal"] = ("多接口:" + "/".join(vs)) if vs else "多接口设备"
                    else:
                        ip0 = next(iter(ips)) if ips else ""
                        hint = "疑似网关" if ip0 and re.search(r"\.(1|254)$", ip0) else ""
                        rec["remote_dev"] = "未知终端[未开LLDP]" + (f"/{hint}" if hint else "")
            else:
                rec["dir"] = "未知"
                rec["evidence"] = "-"
        # 邻居管理IP: ①LLDP 管理地址(已填) ②ARP/MAC 兜底 ③无则 N/A
        if not rec["remote_ip"]:
            cands = set()
            lldp_mac = ""
            if lldp and lldp.get("chassis_id") and re.fullmatch(r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}", lldp["chassis_id"]):
                lldp_mac = lldp["chassis_id"].lower()
            if lldp and lldp.get("remote_dev"):      # LLDP 邻居无管理IP: 查其 Chassis MAC
                if lldp_mac and lldp_mac in data["arp"]:
                    cands.add(data["arp"][lldp_mac])
                for mac in macs:
                    if mac["mac"] in data["arp"] and (not lldp_mac or mac["mac"] == lldp_mac):
                        cands.add(data["arp"][mac["mac"]])
            elif len(macs) <= TERMINAL_MAC_LIMIT:    # 纯终端口: FDB MAC -> ARP 反查
                for mac in macs:
                    if mac["mac"] in data["arp"]:
                        cands.add(data["arp"][mac["mac"]])
            rec["remote_ip"] = "; ".join(sorted(cands)) if cands else "N/A"
        # 对端MAC: 只取直连设备自身的 MAC (LLDP Chassis/Port ID; 无LLDP终端取端口学到的MAC)
        if lldp and lldp.get("remote_dev"):
            rm = ""
            if re.fullmatch(r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}", lldp.get("chassis_id", "")):
                rm = lldp["chassis_id"].lower()
            elif re.fullmatch(r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}", lldp.get("remote_port", "")):
                rm = lldp["remote_port"].lower()
            rec["remote_mac"] = rm
        elif macs:
            rec["remote_mac"] = "; ".join(m["mac"] for m in macs)
        else:
            rec["remote_mac"] = ""
        # 终端识别增强: [PC] 品牌标注; 主机名独立到 hostname 列
        _pc_kw = ("GIGA", "技嘉", "DELL", "戴尔", "LENOVO", "联想", "HP", "惠普",
                  "ASUS", "华硕", "MSI", "微星", "ACER", "宏碁", "APPLE", "苹果",
                  "INTEL", "英特尔", "MICRO-STAR", "HONOR", "荣耀", "XIAOMI", "小米")
        if any(k in rec["terminal"].upper() for k in _pc_kw):
            rec["terminal"] = (rec["terminal"] + " [PC]").strip()
        hn = ""
        if rec["remote_ip"] not in ("", "N/A"):
            ip0 = rec["remote_ip"].split(";")[0].strip()
            hn = (data.get("hostnames") or {}).get(ip0, "")
        if not hn and lldp and lldp.get("chassis_type", "").lower().startswith("locally") and lldp.get("remote_dev"):
            hn = lldp["remote_dev"]                      # LLDP Chassis ID 即主机名
        rec["hostname"] = hn if hn and not re.fullmatch(r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}", hn) else ""
        # 上联口对端管理IP修正: 优先用扫描/缓存到的对端设备真实管理IP,
        # 没有才用本机网关兜底 (LLDP自报地址可能是 MEth带外口, 如核心报 192.168.1.253)
        if rec["dir"] == "上联":
            real = _KNOWN_IPS.get(rec["remote_dev"], "")
            if real:
                rec["remote_ip"] = real
            elif data.get("gateway"):
                gw = data["gateway"]
                if rec["remote_ip"] in ("", "N/A"):
                    rec["remote_ip"] = gw
                elif gw and gw != rec["remote_ip"] and "LLDP报" not in rec["remote_ip"]:
                    rec["remote_ip"] = f"{gw}(LLDP报:{rec['remote_ip']})"
        ports[port] = rec
    return ports


def build_links(all_data):
    """全网链路表: LLDP 双向/单向确认"""
    edges, dev_name = {}, {}
    for d in all_data:
        dev_name[d["host"]] = d["name"]
        for port, r in d["lldp_verbose"].items():
            if not r.get("remote_dev"):
                continue
            edges[(d["name"], port)] = {"remote": r["remote_dev"], "rport": r["remote_port"] or ""}
    links = []
    for (dev, port), v in edges.items():
        rev = edges.get((v["remote"], v["rport"]))
        status = "双向确认" if rev else "单向(对端未扫描)"
        links.append({"devA": dev, "portA": port, "devB": v["remote"],
                      "portB": v["rport"], "status": status, "evidence": "LLDP"})
    return links


def natural(p):
    return [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', p)]


def _init_console():
    """Windows 控制台/管道默认 GBK, 放宽编码错误, 避免 emoji 输出抛 UnicodeEncodeError 闪退"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


def write_reports(all_data):
    rows, mac_rows = [], []
    for d in all_data:
        recs = build_records(d)
        err_txt = "; ".join(d.get("cmd_errors") or [])   # 设备级采集异常, 逐行带上便于筛
        for port in sorted(recs, key=natural):
            r = recs[port]
            rows.append([r["device"], r["host"], port, r["status"], r["dir"],
                         r["remote_dev"], r["remote_port"], r["remote_model"],
                         r["remote_ip"], r["remote_mac"], r["evidence"], r["mac_count"],
                         r["vlans"], r["terminal"], r["hostname"], err_txt])
            for m in d["macs"].get(port, []):
                mac_rows.append([r["device"], port, m["mac"], m["vlan"],
                                 d["arp"].get(m["mac"], ""), vendor_of(m["mac"])])
    links = build_links(all_data)

    def _safe_write(path, fn):
        try:
            fn()
            return True
        except PermissionError:
            print(f"  ⚠ 写入失败 {path}: 文件被占用(可能已在 Excel 中打开), 已跳过该文件")
            return False

    def _write_csv(path, header, body):
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(body)

    # 缓存优先写, 保证 --offline 可用
    _safe_write(CACHE_JSON, lambda: json.dump(all_data, open(CACHE_JSON, "w", encoding="utf-8"),
                                              ensure_ascii=False, indent=1))
    _safe_write(OUTPUT_CSV, lambda: _write_csv(OUTPUT_CSV,
        ["设备名", "管理IP", "端口", "状态", "方向", "对端设备", "对端端口",
         "对端型号", "对端管理IP", "对端MAC", "链路证据", "MAC数量", "VLAN", "终端识别", "主机名",
         "采集异常"], rows))
    _safe_write(MAC_DETAIL_CSV, lambda: _write_csv(MAC_DETAIL_CSV,
        ["设备名", "端口", "MAC", "VLAN", "IP", "厂商"], mac_rows))
    ok_links = _safe_write(LINKS_CSV, lambda: _write_csv(LINKS_CSV,
        ["设备A", "端口A", "设备B", "端口B", "确认状态", "证据"],
        [[l["devA"], l["portA"], l["devB"], l["portB"], l["status"], l["evidence"]] for l in links]))

    print(f"\n📁 已导出: {OUTPUT_CSV} ({len(rows)} 端口) / {MAC_DETAIL_CSV} ({len(mac_rows)} MAC) / {LINKS_CSV} ({len(links)} 链路)")
    return links


def console_summary(all_data, links):
    for d in all_data:
        recs = build_records(d)
        up = [r for r in recs.values() if r["dir"] == "上联"]
        down_lldp = [r for r in recs.values() if r["dir"] in ("下联", "平级/互联")]
        term = [r for r in recs.values() if r["dir"] == "下联终端"]
        agg = [r for r in recs.values() if r["dir"] in ("上联/汇聚", "汇聚下联")]
        print(f"\n{'='*80}\n📟 {d['name']} ({d['host']})\n{'='*80}")
        for r in up:
            print(f"  ▲上联  {r['port']:<12} → {r['remote_dev']} {r['remote_port']} [{r['remote_model']}] ({r['remote_ip']})")
        for r in down_lldp:
            tag = "▼下联" if r["dir"] == "下联" else "◈互联"
            print(f"  {tag}  {r['port']:<12} → {r['remote_dev']} {r['remote_port']} [{r['remote_model']}] ({r['remote_ip']})")
        for r in agg:
            print(f"  ⚡汇聚  {r['port']:<12} → {r['remote_dev']} ({r['mac_count']}MAC {r['vlans']}VLAN)")
        if term:
            def _t(r):
                name = r["terminal"].split("x")[0] if r["terminal"] else "?"
                return f"{r['port']}({name}:{r['remote_ip']})" if r["remote_ip"] not in ("", "N/A") else f"{r['port']}({name})"
            print(f"  ●终端  {len(term)} 个口: " + ", ".join(_t(r) for r in term[:14]) + (" ..." if len(term) > 14 else ""))
    bi = [l for l in links if l["status"] == "双向确认"]
    print(f"\n📡 LLDP 链路 {len(links)} 条 (双向 {len(bi)} / 单向 {len(links)-len(bi)}):")
    for l in links:
        print(f"    {l['devA']}:{l['portA']} ↔ {l['devB']}:{l['portB']} [{l['status']}]")
    bad = [(d["name"], d.get("cmd_errors") or []) for d in all_data if d.get("cmd_errors")]
    if bad:
        print(f"\n⚠ 数据完整性: {len(bad)}/{len(all_data)} 台设备存在采集异常, 相关端口数据可能缺失")
        for nm, errs in bad:
            print(f"    {nm}: " + "; ".join(errs))


def query_ip(all_data, ip):
    """按 IP 反查设备所在交换机端口 (IP->MAC->FDB端口)"""
    hit = False
    for d in all_data:
        macs = sorted({m for m, i in d["arp"].items() if i == ip})
        if not macs:
            continue
        recs = build_records(d)
        for mac in macs:
            for port, mlist in d["macs"].items():
                for m in mlist:
                    if m["mac"] == mac:
                        hit = True
                        r = recs.get(port, {})
                        ctx = f"方向={r.get('dir','?')}"
                        if r.get("remote_dev"):
                            ctx += f" 对端={r['remote_dev']} {r.get('remote_port','')}"
                        print(f"  {ip} → {mac} → {d['name']} ({d['host']}) {port} [VLAN {m['vlan']}] {ctx}")
    if not hit:
        print(f"  未找到 {ip}: 该 IP 的 MAC 不在已扫描设备的 MAC 表中")
        print(f"  (可能设备离线/ARP老化; 可先在网关上 ping {ip} 刷新 ARP 后重扫)")


def query_port(all_data, q):
    q = normalize_port(q)
    hit = False
    for d in all_data:
        recs = build_records(d)
        if q not in recs:
            continue
        hit = True
        r = recs[q]
        print(f"\n{'='*72}\n🔍 端口 {q} @ {d['name']} ({d['host']})\n{'='*72}")
        print(f"  状态: {r['status']} | 方向: {r['dir']} | 证据: {r['evidence']}")
        if r["remote_dev"]:
            print(f"  直接对端: {r['remote_dev']} {r['remote_port']} [{r['remote_model']}] 管理IP: {r['remote_ip']}")
        if r["dir"] == "上联" and r["remote_dev"]:
            print(f"  ▲ 上联链路: 本口 {q} → {r['remote_dev']} {r['remote_port']}")
            for d2 in all_data:
                if d2["name"] == r["remote_dev"]:
                    ups2 = [x for x in build_records(d2).values() if x["dir"] == "上联"]
                    if ups2:
                        for u in ups2:
                            print(f"     ↳ {r['remote_dev']} 的上联: {u['port']} → {u['remote_dev']} {u['remote_port']}")
                    else:
                        print(f"     ↳ {r['remote_dev']} 无更上层 LLDP 邻居 (可能直连出口/防火墙)")
        if r["dir"] == "下联" and r["remote_dev"]:
            print(f"  ▼ 下联链路: 本口 {q} → {r['remote_dev']} {r['remote_port']}")
            for d2 in all_data:
                if d2["name"] == r["remote_dev"]:
                    t = [x for x in build_records(d2).values() if x["dir"] == "下联终端"]
                    print(f"     ↳ {r['remote_dev']} 下接终端 {len(t)} 口, 例: " + ", ".join(f"{x['port']}({x['terminal'].split('x')[0]})" for x in t[:8]))
        if r["mac_count"]:
            arp = d["arp"]
            print(f"  下联设备明细 ({r['mac_count']} MAC / {r['vlans']} VLAN):")
            for mac in d["macs"].get(q, [])[:10]:
                ip = arp.get(mac["mac"], "-")
                print(f"     - {mac['mac']} VLAN:{mac['vlan']} IP:{ip} {vendor_of(mac['mac'])}")
            if r["mac_count"] > 10:
                print(f"     ... 其余 {r['mac_count'] - 10} 条见 CSV")
        elif r["dir"] == "未连接":
            print("  端口未连接设备")
    if not hit:
        print(f"未在任何已扫描设备上找到端口 {q}")
        print("可查询的端口示例: GE0/0/49 (接入交换机上联口), XGE1/0/2 (核心侧对应口), GE0/0/8 (PC)")


def main():
    _init_console()
    ap = argparse.ArgumentParser(description="全网交换机端口上下联拓扑探测")
    ap.add_argument("--query", metavar="端口", help="查询指定端口的上下联链路")
    ap.add_argument("--query-ip", metavar="IP", help="按IP反查设备所在交换机端口")
    ap.add_argument("--offline", action="store_true", help="从缓存读取, 不重新扫描")
    ap.add_argument("--recursive", action="store_true", help="全网递归扫描(默认单机模式)")
    args = ap.parse_args()

    # 交互模式: 不带任何参数启动(如双击exe) -> 提示输入IP/账号/密码
    interactive = not (args.query or args.query_ip or args.offline or args.recursive)
    if interactive:
        global USERNAME, PASSWORD, TARGET_SWITCH
        print("=" * 50)
        print("        网络拓扑扫描工具")
        print("  单台查询/全网扫描/批量报表")
        print("=" * 50)
        ip = input("请输入交换机 IP: ").strip()
        if not ip:
            print("未输入 IP, 退出。")
            input("按回车键退出...")
            sys.exit(1)
        user = input("请输入用户名 (回车=admin): ").strip() or "admin"
        try:
            import getpass
            pwd = getpass.getpass("请输入密码: ")
        except Exception:
            pwd = input("请输入密码: ")
        rec = input("是否全网递归扫描? (y/N): ").strip().lower() == "y"
        USERNAME, PASSWORD, TARGET_SWITCH = user, pwd, {"host": ip}
        args.recursive = rec
        print()

    if args.offline:
        try:
            all_data = json.load(open(CACHE_JSON, encoding="utf-8"))
            print(f"✅ 已从缓存加载 {len(all_data)} 台设备 ({CACHE_JSON})")
        except Exception as e:
            print(f"❌ 缓存读取失败: {e}, 请先运行一次完整扫描"); sys.exit(1)
    else:
        mode = "全网递归" if args.recursive else "单机"
        print(f"🔍 交换机拓扑扫描开始 [{mode}模式, 目标 {TARGET_SWITCH['host']}] ...")
        all_data = scan_network(recursive=args.recursive)
        if not all_data:
            print("❌ 没有成功扫描到任何设备"); sys.exit(1)
    build_known_ips(all_data)
    if not args.offline:
        links = write_reports(all_data)
        console_summary(all_data, links)

    if args.query_ip:
        print(f"\n🔍 按 IP 反查物理端口: {args.query_ip}")
        query_ip(all_data, args.query_ip)
    if args.query:
        query_port(all_data, args.query)
    elif args.offline and not args.query_ip:
        print("提示: 使用 --query <端口> 或 --query-ip <IP> 查询, 例如 --query GE0/0/49 / --query-ip 10.175.200.240")

    if interactive:                       # 防闪退: 交互模式结束后暂停
        input("\n扫描完成, 按回车键退出...")


if __name__ == "__main__":
    main()
