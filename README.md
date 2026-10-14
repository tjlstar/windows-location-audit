# Windows Location & Network Exposure Audit v3.4

只读的 Windows 地区与网络出口检查工具，汇总 Windows 区域设置、语言、时区、代理、VPN/TUN、DNS、公网 IPv4/IPv6 和可选定位结果。HTML 页面将“是否符合指定国家”与“两个测试结果是否一致”分开显示，方便定位差异。

## 快速开始

需要 Windows 11 和 Windows PowerShell 5.1，或兼容的 Windows PowerShell 7 环境；联网出口检查使用 `curl.exe`。

普通用户只需运行 `WindowsLocationAudit_v3_4.ps1`。在脚本所在目录打开 PowerShell，执行完整检查：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\WindowsLocationAudit_v3_4.ps1" -Online -WindowsLocation
```

检查完成后，TXT 和 HTML 默认保存在**脚本所在目录**，并自动打开 HTML，无需添加 `-OpenBrowserProbe`：

- `WindowsLocationAudit_v3_4_日期_时间.txt`：Windows 设置及网络诊断详情。
- `BrowserLocationProbe_v3_4_日期_时间.html`：已包含 PowerShell 地区结果的浏览器检查页面。

页面打开后，点击 **运行浏览器全部检查**，补入浏览器出口、WebRTC 和定位结果。浏览器定位需要权限；拒绝定位或检测失败会显示为未验证。

如果自动打开的不是你想测试的浏览器，请用目标浏览器手动打开生成的 HTML。

## 常用运行方式

只检查本机设置，不启用脚本的联网和定位测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\WindowsLocationAudit_v3_4.ps1"
```

联网检查并减少报告中的个人标识：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\WindowsLocationAudit_v3_4.ps1" -Online -ShareSafe
```

静默生成报告，不自动打开浏览器：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\WindowsLocationAudit_v3_4.ps1" -Online -NoBrowserProbe
```

自定义报告目录（目录需要事先存在）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\WindowsLocationAudit_v3_4.ps1" -Online -OutputDirectory "D:\Reports"
```

| 参数 | 作用 |
| --- | --- |
| `-Online` | 启用公网出口、IP 定位、Fake-IP 和 DNS 抽样检查。 |
| `-WindowsLocation` | 请求 Windows 定位服务，并比较有效定位与 IP 近似位置。 |
| `-ShareSafe` | 减少 TXT 和初始 HTML 中的 IP、代理及其他个人标识。 |
| `-OutputDirectory` | 指定报告目录；默认使用脚本目录，与当前工作目录无关。 |
| `-NoBrowserProbe` | 禁止自动打开 HTML，优先于 `-OpenBrowserProbe`。 |
| `-OpenBrowserProbe` | 保留的兼容参数，默认已启用，无需显式添加。 |

## 页面中的两种对比

### 1. 与基准国家对比

使用 **基准国家 / 地区** 下拉菜单，选择你希望各项信号呈现的国家。支持主要亚洲、欧洲、美洲国家及其他本机 .NET 地区数据可识别的国家/地区。

默认的 **自动** 模式先使用 PowerShell 参考出口国家，获得浏览器出口数据后使用浏览器出口国家。基准不固定为美国。

手动选择后，Windows 区域、语言地区、各网络出口、DNS 和 WebRTC 国家等项目会立即重新判断，显示“符合基准 / 不符合基准”。无需重跑检测，后续浏览器检测也不会覆盖手动选择。

例如，Windows 地区是加拿大：选择加拿大时符合基准，改选美国时不符合基准。

### 2. 两个测试结果互相对比

这张表直接比较检测 A 和检测 B，**不使用下拉菜单中的国家**，所以切换国家不会改变结论。包括：

- PowerShell 直连 IPv4 与 IPv6、直连与系统代理、环境代理与系统代理的国家。
- DNS 抽样地区与 PowerShell 参考出口国家。
- 浏览器与系统代理、浏览器 IPv4 与 IPv6、WebRTC 与 HTTP 出口的国家。
- Windows 或浏览器时区与 IP 时区，以及浏览器时区与 Windows 时区。
- Windows 或网页定位与 IP 近似位置的距离。

例如，IPv4 出口是美国、IPv6 出口是日本，两者始终“不一致”，与用户选择的基准国家无关。

时区比较的是当前 UTC 偏移（包含夏令时）；定位按距离是否超过 300 km 提示差异，不能用这两项直接判定国家。仅 IP 地址不同、但国家相同，不会作为地区差异标红。

两张表分别统计并将差异项目置顶。红色表示不符合基准或两项结果不同，黄色表示证据不足，灰色表示未测试或无法比较。

TXT 中的一致性表仍使用 PowerShell 自动选择的参考出口；HTML 下拉菜单只改变页面和后续导出的汇总，不会改写已生成的 TXT。

## 保存浏览器结果与 DNS 检查

浏览器测试结果最初只存在于当前页面。完成后点击 **保存汇总 HTML（隐藏 IP 和坐标）**，保存两张表、手动选择的基准国家及浏览器结果，下次打开保存文件可恢复。导出文件名为 `WindowsBrowserRegionSummary.html`，保存位置由浏览器下载设置决定；它不会直接覆盖脚本生成的原始 HTML。

原始详情中也可以使用 **Save redacted JSON** 或 **Save full JSON** 导出数据。完整 JSON 可能包含公网 IP 和精确定位坐标，应私人保存。脱敏导出仍保留语言、时区等信息，分享前请自行检查。

脚本只抽样检测系统 DNS。请使用正在检查的浏览器，自行打开 [BrowserLeaks DNS 泄露测试](https://browserleaks.com/dns)，进行更完整的浏览器 DNS 检查。页面不会自动运行该网站的测试。

浏览器 DNS-over-HTTPS（DoH）可能与系统 DNS 使用不同路径。DNS 国家与 HTTPS 出口国家不同，可能来自正常的远程解析、Anycast 或代理策略，并不直接证明泄露。

## 检查范围与结论限制

PowerShell 检查 Windows 版本、设备 GeoID、当前地区、时区、语言与输入法、定位权限和策略、网卡与路由、Windows VPN、系统/环境代理、DNS 配置，以及可选的公网与定位测试。地区映射包含离线内置表，并自动从本机 .NET 数据补充；无法识别的值保持未知。

浏览器检查网页实际可见的语言、格式、时区、IPv4/IPv6/Cloudflare 出口、WebRTC 和可选定位。两边部分项目重叠，是为了发现应用实际请求路径的差异。`curl --noproxy` 可绕过应用层代理，但无法绕过 TUN 路由。

IP 定位数据库的一致性标记：

| 标记 | 含义 |
| --- | --- |
| `AGREE` | 至少两个可用来源给出的国家一致。 |
| `SINGLE_SOURCE` | 只有一个来源，尚未交叉验证。 |
| `DISAGREE` | 来源意见不同；无严格多数时国家保持未知。 |
| `NO_DATA` | 没有可用的国家定位数据。 |

IPv6 检测失败不等于 IPv6 已关闭，也不直接证明安全或泄露。IP 定位是近似数据；语言、时区和 Windows 存储地区都是独立信号，不能证明真实物理位置或历史安装位置。

Microsoft 账户注册国家需要用户手动核对，脚本不读取账户凭据、令牌或私人资料。

## 网络访问与隐私

默认不启用脚本的公网 IP/DNS 测试。`-Online` 会访问 ipify、Cloudflare、ipwho.is、ipinfo.io、ip-api.com，以及 Akamai/Google DNS 诊断域名和测试域名。ip-api.com 免费端点使用 HTTP。

`-WindowsLocation` 可能使 Windows 使用在线定位服务。TXT 不记录精确设备坐标。浏览器页面没有外部 JavaScript，仅在点击检查按钮后访问测试服务；WebRTC 使用公开 STUN 服务，网页定位可能使用操作系统或浏览器的在线定位服务。

`-ShareSafe` 处理脚本输出及初始嵌入数据，不会阻止浏览器在点击后获取 IP 和定位。使用脱敏 HTML/JSON 导出减少这些标识，但不能保证完全匿名。

脚本不修改 Windows 区域、代理、路由、策略或安全服务；会写入本地报告，并按参数执行联网、定位和浏览器打开操作。

## 开发验证与文件说明

普通用户只需要主脚本。`tests` 目录是开发回归检查，不是运行依赖，也不需要逐个运行。

当前实现已通过 Windows PowerShell 5.1 和 PowerShell 7.6 的离线回归验证，包括实际 `powershell.exe -File` 启动、默认输出目录及地区映射；网页逻辑和下拉菜单交互也已验证。联网和定位结果仍取决于实际网络、代理策略、服务可用性及浏览器权限。

开发者可选运行（网页逻辑测试需要 Node.js）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tests\AuditRegression.ps1"
node.exe ".\tests\BrowserRegression.cjs"
```

可自由分享和修改；不提供保证。
