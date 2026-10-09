# -*- coding: utf-8 -*-
"""探针2: 拉接口描述/链路状态/eth-trunk/lldp 邻居明细补全"""
import os
from netmiko import ConnectHandler

device_info = {
    "device_type": "huawei",
    "host": os.environ.get("TOPO_HOST", "10.175.10.1"),
    "username": os.environ.get("TOPO_USERNAME", "admin"),
    "password": os.environ.get("TOPO_PASSWORD", ""),
    "conn_timeout": 30, "auth_timeout": 30, "banner_timeout": 30,
    "system_host_keys": False,
}
commands = [
    ("interface_brief", "display interface brief"),
    ("interface_desc", "display interface description"),
    ("eth_trunk", "display eth-trunk"),
]
conn = ConnectHandler(**device_info)
conn.send_command("screen-length 0 temporary")
for name, cmd in commands:
    try:
        out = conn.send_command(cmd, read_timeout=120, strip_command=False)
        open(f"raw_output/{name}.txt", "w", encoding="utf-8").write(out)
        print(f"[{name}] {len(out)} chars")
    except Exception as e:
        print(f"[{name}] FAILED: {e}")
conn.disconnect()
print("done")
