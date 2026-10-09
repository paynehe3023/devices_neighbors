# -*- coding: utf-8 -*-
"""探针3: 扫描核心交换机 CoreSW-INTERNET-01 (10.175.10.254)"""
import os
from netmiko import ConnectHandler

device_info = {
    "device_type": "huawei",
    "host": os.environ.get("TOPO_HOST", "10.175.10.254"),
    "username": os.environ.get("TOPO_USERNAME", "admin"),
    "password": os.environ.get("TOPO_PASSWORD", ""),
    "conn_timeout": 30, "auth_timeout": 30, "banner_timeout": 30,
    "system_host_keys": False,
}
commands = [
    ("core_lldp_neighbor_brief", "display lldp neighbor brief"),
    ("core_lldp_neighbor", "display lldp neighbor"),
    ("core_mac_address", "display mac-address"),
    ("core_arp", "display arp"),
    ("core_interface_brief", "display interface brief"),
]
conn = ConnectHandler(**device_info)
conn.send_command("screen-length 0 temporary")
for name, cmd in commands:
    try:
        out = conn.send_command(cmd, read_timeout=180, strip_command=False)
        open(f"raw_output/{name}.txt", "w", encoding="utf-8").write(out)
        print(f"[{name}] {len(out)} chars")
    except Exception as e:
        print(f"[{name}] FAILED: {e}")
conn.disconnect()
print("done")
