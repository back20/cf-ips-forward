## Go-IPs-Forward - 高性能 Cloudflare CDN 测速和代理工具

**Go-IPs-Forward** 是一款使用 Golang 编写的强大工具，用于测试 Cloudflare CDN 的 IP 地址延迟，并根据测速结果自动选择最佳 IP，为每个 Cloudflare 数据中心启动本地代理，将流量转发到最佳 IP。

添加多另外的go文件,需要在工程中执行
go: to add module requirements and sums:      
        go mod tidy

ip.txt 来源于使用https://github.com/cmliu/CFnat-Windows-GUI中的生成ip缓存的缓存信息

生成addapi.txt用于记录成优选文件,
  内容由生成的记录TIA,ALG,AAE,ORN,LAD,EZE,COR,NQN,EVN,ADL,BNE,CBR,HBA,MEL,PER,SYD,VIE,LLK,GYD,BAH,CGP,DAC,JSR,BGI,MSQ,BRU,PBH,LPB,GBE,QWJ,ARU,BEL,CNF,BNU,BSB,CFC,VCP,CAW,XAP,CGB,CWB,FLN,FOR,GYN,ITJ,JOI,JDO,MAO,PMW,POA,REC,RAO,GIG,SSA,SJP,SJK,GRU,SOD,NVT,UDI,VIX,BWN,SOF,OUA,PNH,YYC,YVR,YWG,YHZ,YOW,YYZ,YUL,YXE,ARI,SCL,BAQ,BOG,MDE,FIH,SJO,ABJ,ASK,ZAG,LCA,PRG,CPH,JIB,STI,SDQ,GYE,UIO,CAI,TLL,SUV,HEL,BOD,LYS,MRS,CDG,PPT,TBS,TXL,DUS,FRA,HAM,MUC,STR,ACC,ATH,SKG,GND,GUM,GUA,GEO,TGU,HKG,BUD,KEF,AMD,BLR,BBI,IXC,MAA,HYD,CNN,KNU,COK,CCU,BOM,NAG,DEL,PAT,DPS,CGK,JOG,BGW,BSR,EBL,NJF,XNH,ISU,ORK,DUB,HFA,TLV,MXP,PMO,FCO,KIN,FUK,OKA,KIX,NRT,AMM,AKX,ALA,NQZ,MBA,NBO,ICN,KWI,VTE,RIX,BEY,VNO,LUX,MFM,TNR,JHB,KUL,KCH,MLE,MRU,GDL,MEX,QRO,KIV,ULN,MPM,MDL,RGN,WDH,KTM,AMS,NOU,AKL,CHC,LOS,SKP,OSL,MCT,ISB,KHI,LHE,ZDM,PTY,ASU,LIM,CGY,CEB,MNL,CRK,WAW,LIS,SJU,DOH,RUN,OTP,KJA,DME,LED,KLD,SVX,KGL,DMM,JED,RUH,DKR,BEG,SIN,BTS,CPT,DUR,JNB,BCN,MAD,CMB,PBM,GOT,ARN,GVA,ZRH,KHH,TPE,DAR,BKK,CNX,URT,POS,TUN,IST,ADB,EBB,KBP,DXB,EDI,LHR,MAN,MGM,ANC,PHX,LAX,SMF,SAN,SFO,SJC,DEN,JAX,MIA,TLH,TPA,ATL,HNL,ORD,IND,BGR,BOS,DTW,MSP,MCI,STL,OMA,LAS,EWR,ABQ,BUF,CLT,RDU,CLE,CMH,OKC,PDX,PHL,PIT,FSD,MEM,BNA,AUS,DFW,IAH,MFE,SAT,SLC,IAD,ORF,RIC,SEA,TAS,DAD,HAN,SGN,HRE中的记录进行生成,然后再和
  https://addressesapi.090227.xyz/ct
  https://addressesapi.090227.xyz/cmcc
  https://addressesapi.090227.xyz/cmcc-ipv6
  https://ipdb.api.030101.xyz/?type=bestproxy&country=true
  https://ipdb.api.030101.xyz/?type=bestcf&country=true
  https://addressesapi.090227.xyz/CloudFlareYes
  https://addressesapi.090227.xyz/ip.164746.xyz

  中的优选ip记录合并一起生成.


**功能特性:**

- **批量 IP 测速:** 支持从文件读取多个 IP 地址和端口，并使用 Cloudflare 的 speed.cloudflare.com/cdn-cgi/trace 接口进行测速。
- **CIDR 支持:** 支持 CIDR 格式的 IP 地址，可以随机选择一部分 IP 进行测试，或测试所有 IP。
- **TLS 支持:** 可以选择是否启用 TLS 进行测速。
- **延迟筛选:** 可以设置最大延迟阈值，筛选出延迟低于阈值的 IP。
- **数据中心筛选:** 可以选择只测试特定数据中心的 IP。
- **结果排序:** 将测速结果按数据中心分组，并按延迟排序，保留延迟最低的指定数量 (topDD) 的 IP。
- **CSV 输出:** 将测速结果保存到 CSV 文件，包含 IP 地址、端口、数据中心、地区、城市和延迟等信息。
- **自动代理:** 根据测速结果自动选择最佳 IP，为每个 Cloudflare 数据中心启动一个本地代理，监听指定端口并将流量转发到最佳 IP。
- **动态更新:** 定期测试 IP 延迟，并更新每个数据中心对应的最佳 IP，保证代理的性能。
- **监控面板:**  实时显示每个数据中心的代理端口、城市、IP 地址和端口等信息，以及程序运行时长和当前时间。
- **每个数据中心固定代理端口：** 为每个 Cloudflare 数据中心分配一个固定的本地代理端口，方便用户配置代理规则。


**使用方法:**

1. **安装 Golang:** 确保你的系统已经安装了 Golang。
2. **下载代码:** 从 GitHub 上克隆代码仓库：
    ```
    git clone https://github.com/don0023/Go-IPs-Forward.git
    ```
3. **准备 IP 列表文件:** 创建一个名为 `ip.txt` 的文件，每行包含一个 IP 地址或 IP 段 (CIDR 格式)，可以指定端口，例如：
    ```
    1.1.1.1 853
    8.8.8.8 443 853
    172.67.171.0/24
    2606:4700:4700::1111 443
    ```
    **说明:**

    - 如果不指定端口，程序会使用默认端口 (可以通过 `-port` 参数指定，默认为 443)。
    - 可以为同一个 IP 地址指定多个端口，例如 `8.8.8.8 443 853`。

4. **编译运行:** 进入代码目录，执行以下命令编译并运行程序：
    ```
    go build
    ./Go-IPs-Forward -file ip.txt -outfile result.csv -max 100 -colo sjc,hkg -dd 20 -min 20
    ```
    **参数说明:**
    - `-file`: IP 列表文件名称 (默认为 ip.txt)。
    - `-outfile`: 输出文件名称 (默认为 result.csv)。
    - `-port`: 默认端口 (默认为 443)。
    - `-max`: 并发请求最大协程数 (默认为 100)。
    - `-tls`: 是否启用 TLS (默认为 true)。
    - `-allip`: 是否测试所有 IP (ipv4网段内所有ip,ipv6依然为默认数量随机) (默认为 false)。
    - `-ips`: 每个IP段随机测试的 IP 数量 (默认为 5)。
    - `-ping`: 仅测试延迟，不进行速度测试 (默认为 false)。
    - `-ms`: 指定测速最大延迟 (ms), 默认 300。
    - `-colo`: 指定数据中心 (多个用逗号分隔,  例如: sjc,hkg)。
    - `-dd`: 每个数据中心输出延迟最低的 IP 数量 (默认为 20)。
    - `-min`: 更新间隔 (分钟) (默认为 20 分钟)。

5. **查看结果:** 程序运行完成后，测速结果会保存到 `result.csv` 文件中，可以使用 Excel 或其他工具打开查看。
6. **使用代理:** 程序会为每个 Cloudflare 数据中心启动一个本地代理，监听一个固定的端口，端口号从 10000 开始递增。例如，如果 `locations.json` 文件中第一个数据中心的 IATA 代码为 `sjc`，则程序会为 `sjc` 数据中心启动一个本地代理，监听端口 10000，第二个数据中心 `hkg` 监听端口 10001，以此类推。可以使用代理软件 (例如: v2rayN) 将流量转发到这些端口，从而使用最佳 IP 访问 Cloudflare CDN。


**注意事项:**

- 程序需要访问网络，请确保你的网络环境正常。
- 程序会占用一定的 CPU 和内存资源，请根据你的系统配置调整参数。
- 程序会创建多个监听端口，请确保这些端口没有被其他程序占用。


**免责声明:**

本程序仅供学习和研究使用，请勿用于非法用途。


**鸣谢:**

本程序基于以下项目开发：

- [Cloudflare-IP-SpeedTest](https://github.com/badafans/Cloudflare-IP-SpeedTest)
- [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared)


**许可证:**

[MIT License](LICENSE)
