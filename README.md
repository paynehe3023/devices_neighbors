# 网络拓扑扫描工具

基于 SSH / Netmiko 的交换机端口拓扑探测与终端资产盘点工具，提供 CustomTkinter 图形界面和命令行两种使用方式。

当前版本：`v1.0.7`

## 功能

- LLDP 轨：识别上联/下联交换机、路由器、AP 等网络设备，解析对端设备名、对端端口和管理 IP。
- MAC 轨：对未开启或不支持 LLDP 的终端，提取端口绑定的 MAC、VLAN 和 OUI 厂商信息。
- 全网递归：默认只扫描指定交换机，开启递归后自动发现并扫描邻居交换机。
- 端口查询：按交换机端口查看上下联链路，或按 IP 反查设备所在交换机和物理端口。
- 报表导出：生成端口拓扑、MAC 明细和链路关系 CSV。
- 图形界面：支持单台扫描、全网扫描、CSV 批量扫描、回车快捷扫描、随时停止扫描和在线更新检查。

## 环境要求

- Windows 10/11
- Python 3.10 或更高版本
- 目标交换机已开启 SSH，且当前主机可以访问交换机管理地址
- 建议使用有只读权限的交换机账号

## 安装

```powershell
git clone https://github.com/paynehe3023/devices_neighbors.git
cd devices_neighbors
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install netmiko textfsm manuf customtkinter pyinstaller
```

## 图形界面

启动：

```powershell
.\.venv\Scripts\python.exe gui_main.py
```

使用步骤：

1. 输入交换机 IP、用户名和密码。
2. 按回车或点击“单台扫描”。
3. 点击“全网扫描”递归发现邻居交换机。
4. 扫描过程中可点击“停止扫描”；已经完成的设备结果会保留。
5. 使用“按 IP 反查”或“按端口查询”定位链路。
6. 点击“导出 CSV 报表”导出当前结果。

“关于”窗口可以手动检查更新。程序启动后也会静默检查 `version.json`，发现新版本时会在“关于”按钮左上角显示红点。

## 命令行

```powershell
# 单台扫描
.\.venv\Scripts\python.exe get_port_neighbors.py

# 全网递归扫描
.\.venv\Scripts\python.exe get_port_neighbors.py --recursive

# 扫描后查询端口
.\.venv\Scripts\python.exe get_port_neighbors.py --query GE0/0/49

# 按 IP 反查
.\.venv\Scripts\python.exe get_port_neighbors.py --query-ip 10.0.0.100

# 使用上次缓存查询，不重新扫描
.\.venv\Scripts\python.exe get_port_neighbors.py --query-ip 10.0.0.100 --offline
```

凭据可以通过环境变量注入，避免写入脚本：

```powershell
$env:TOPO_USERNAME = "admin"
$env:TOPO_PASSWORD = "your-password"
```

## 输出文件

运行扫描后会在项目目录生成：

- `port_topology.csv`：端口、状态、方向、对端设备和终端识别结果。
- `mac_detail.csv`：端口 MAC 明细、VLAN 和厂商信息。
- `network_links.csv`：设备之间的链路关系。
- `topology_cache.json`：最近一次扫描缓存，用于 `--offline` 查询。

以上文件包含内网资产信息，默认已加入 `.gitignore`，不要提交到公开仓库。

## 更新机制

程序通过仓库根目录的 `version.json` 检查最新版本：

```json
{
  "version": "1.0.7",
  "download_url": "https://github.com/paynehe3023/devices_neighbors/releases/latest/download/network-topology-scanner.exe",
  "notes": "更新说明",
  "published_at": "2026-10-13",
  "sha256": "..."
}
```

发布新版本时需要：

1. 修改 `get_port_neighbors.py` 中的 `APP_VERSION`。
2. 同步修改 `version_info.txt` 和 `version.json`。
3. 重新打包并计算 exe 的 SHA256，写回 `version.json`。
4. 将 `version.json` 推送到 GitHub `main` 分支。
5. 在 GitHub Release 上传 exe，附件名必须为 `network-topology-scanner.exe`。

## 打包

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --clean --noconfirm "网络拓扑扫描工具.spec"
```

打包结果：

```text
dist\network-topology-scanner.exe
```

## 安全说明

本工具会通过 SSH 登录交换机并读取端口、LLDP、MAC、ARP 等网络信息。请仅在获得授权的网络和设备上使用。
