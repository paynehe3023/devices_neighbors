# -*- coding: utf-8 -*-
"""一次性探针: 拉取交换机真实回显, 保存到 raw_output/ 供格式分析 (只读命令)"""
import os
from netmiko import ConnectHandler

SWITCH_IP = os.environ.get("TOPO_HOST", "10.175.10.1")
USERNAME = os.environ.get("TOPO_USERNAME", "admin")
PASSWORD = os.environ.get("TOPO_PASSWORD", "")

device_info = {
    "device_type": "huawei",
    "host": SWITCH_IP,
    "username": USERNAME,
    "password": PASSWORD,
    "conn_timeout": 30,
    "auth_timeout": 30,
    "banner_timeout": 30,
    "system_host_keys": False,
}

os.makedirs("raw_output", exist_ok=True)

commands = [
    ("lldp_neighbor_brief", "display lldp neighbor brief"),
    ("lldp_neighbor", "display lldp neighbor"),
    ("mac_address", "display mac-address"),
    ("arp", "display arp"),
    ("version", "display version"),
]

conn = ConnectHandler(**device_info)
print("connected:", conn.find_prompt())
conn.send_command("screen-length 0 temporary")

for name, cmd in commands:
    try:
        out = conn.send_command(cmd, read_timeout=120, strip_command=False)
        with open(f"raw_output/{name}.txt", "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[{name}] {len(out)} chars -> raw_output/{name}.txt")
    except Exception as e:
        print(f"[{name}] FAILED: {e}")

conn.disconnect()
print("done")
