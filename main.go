package main

import (
    "bufio"
    "bytes"
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "math/rand"
    "net"
    "net/http"
    "os"
    "os/exec"
    "regexp"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"
)

const (
    requestURL  = "speed.cloudflare.com/cdn-cgi/trace" // 请求trace URL
    timeout     = 1 * time.Second                      // 超时时间
    maxDuration = 2 * time.Second                      // 最大持续时间
    basePort    = 10000                                // 端口号基数
)

var (
    File         = flag.String("file", "ip.txt", "IP地址及端口文件名称")                      // IP地址及端口文件名称
    outFile      = flag.String("outfile", "result.csv", "输出文件名称")                                   // 输出文件名称
    defaultPort  = flag.Int("port", 443, "测速默认端口")                                                  // 端口
    maxThreads   = flag.Int("max", 100, "并发请求最大协程数")                                            // 最大协程数
    enableTLS    = flag.Bool("tls", true, "是否启用TLS")                                            // TLS是否启用
    testAllIPs   = flag.Bool("allip", false, "是否测试所有 IP (ipv4网段内所有ip,ipv6依然为默认数量随机)")      // 是否测试所有 IP
    ips          = flag.Int("ips", 5, "每个IP段随机生成的IP数量(默认5)")                              //每个IP段随机测试IP数
    pingOnly    = flag.Bool("ping", false, "仅测试延迟，不进行转发")                               // 仅测试延迟
    maxLatency = flag.Int("ms", 300, "指定测速最大延迟(ms), 默认300")                         // 新增变量
    colo       = flag.String("colo", "", "指定数据中心(多个用逗号分隔,例如:sjc,hkg)")          // 新增变量
    topDD       = flag.Int("dd", 20, "每个数据中心输出延迟最低的IP数量(默认20)")                 // 新增变量
    updateInterval = flag.Int("min", 20, "更新间隔（分钟），默认为 20 分钟") // 新增更新间隔变量
)

type result struct {
    ip          string        // IP地址
    ports       []int        // 端口
    dataCenter  string        // 数据中心
    region      string        // 地区
    city        string        // 城市
    latency     string        // 延迟
    tcpDuration time.Duration // TCP请求延迟
}

type location struct {
    Iata   string  `json:"iata"`
    Lat    float64 `json:"lat"`
    Lon    float64 `json:"lon"`
    Cca2   string  `json:"cca2"`
    Region string  `json:"region"`
    City   string  `json:"city"`
}

type ipPort struct {
    ip   string
    port int
}

type ForwardRule struct {
    SourcePort int
    Targets    []Target
    mu         sync.RWMutex
    bestTarget *Target
}

type Target struct {
    IP         string
    Datacenter string
    Port       int
}

// 尝试提升文件描述符的上限
func increaseMaxOpenFiles() {
    fmt.Println("正在尝试提升文件描述符的上限...")
    cmd := exec.Command("bash", "-c", "ulimit -n 10000")
    _, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Printf("提升文件描述符上限时出现错误: %v\n", err)
    } else {
        fmt.Printf("文件描述符上限已提升!\n")
    }
}

// 从文件中读取IP地址和端口
func readIPs(File string, testAllIPs bool, ips int) (map[ipPort][]int, error) {
    file, err := os.Open(File)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    ipPortsMap := make(map[ipPort][]int)
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.Fields(line) // 使用空格分割

        if len(parts) == 0 {
            continue // 跳过空行
        }

        ipStr := parts[0]
        // 检查是否为 CIDR 格式的 IP 地址
        if strings.Contains(ipStr, "/") {
            ip, ipNet, err := net.ParseCIDR(ipStr)
            if err != nil {
                fmt.Printf("无法解析 CIDR 格式的 IP: %v\n", err)
                continue
            }

            if testAllIPs {
                if ipNet.IP.To4() != nil { // IPv4 地址段，测试所有 IP
                    for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
                        ports := make([]int, 0)
                        if len(parts) > 1 { // 包含端口
                            for _, portStr := range parts[1:] {
                                port, err := strconv.Atoi(portStr)
                                if err != nil {
                                    fmt.Printf("跳过端口格式错误的行: %s\n", line)
                                    continue
                                }
                                ports = append(ports, port)
                            }
                        } else {
                            ports = append(ports, *defaultPort)
                        }
                        ipPortKey := ipPort{ip.String(), *defaultPort}
                        if len(parts) > 1 {
                            for _, portStr := range parts[1:] {
                                port, err := strconv.Atoi(portStr)
                                if err != nil {
                                    fmt.Printf("跳过端口格式错误的行: %s\n", line)
                                    continue
                                }
                                ipPortKey = ipPort{ip.String(), port}
                                ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], port)
                            }
                        } else {
                            ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], *defaultPort)
                        }
                    }
                } else if ipNet.IP.To16() != nil { // IPv6 地址段，限制测试数量
                    ones, _ := ipNet.Mask.Size() // 获取掩码长度
                    selectedIPs := make(map[string]bool)

                    for len(selectedIPs) < ips { // 使用 ips 变量
                        randIP := make(net.IP, net.IPv6len)
                        copy(randIP, ipNet.IP)

                        // 生成随机数并填充到地址中
                        for i := ones / 8; i < net.IPv6len; i++ {
                            randIP[i] = byte(rand.Intn(65536))
                        }

                        if ipNet.Contains(randIP) {
                            selectedIPs[randIP.String()] = true
                        }
                    }

                    // 只保留选中的 IP
                    for ipStr := range selectedIPs {
                        ports := make([]int, 0)
                        if len(parts) > 1 {
                            for _, portStr := range parts[1:] {
                                port, err := strconv.Atoi(portStr)
                                if err != nil {
                                    fmt.Printf("跳过端口格式错误的行: %s\n", line)
                                    continue
                                }
                                ports = append(ports, port)
                            }
                        } else {
                            ports = append(ports, *defaultPort)
                        }
                        ipPortKey := ipPort{ipStr, *defaultPort}
                        if len(parts) > 1 {
                            for _, portStr := range parts[1:] {
                                port, err := strconv.Atoi(portStr)
                                if err != nil {
                                    fmt.Printf("跳过端口格式错误的行: %s\n", line)
                                    continue
                                }
                                ipPortKey = ipPort{ipStr, port}
                                ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], port)
                            }
                        } else {
                            ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], *defaultPort)
                        }
                    }
                }
            } else {
                // 随机选择 IP
                selectedIPs := make(map[string]bool)

                if ipNet.IP.To4() != nil { // IPv4 地址段
                    ones, bits := ipNet.Mask.Size()
                    size := 1 << (bits - ones)

                    for len(selectedIPs) < ips && len(selectedIPs) < size {
                        randIP := make(net.IP, len(ip))
                        copy(randIP, ip)
                        for j := len(ip) - 1; j >= 0; j-- {
                            randIP[j] += byte(rand.Intn(256))
                            if randIP[j] > 0 {
                                break
                            }
                        }

                        if ipNet.Contains(randIP) {
                            selectedIPs[randIP.String()] = true
                        }
                    }
                } else if ipNet.IP.To16() != nil { // IPv6 地址段
                    ones, _ := ipNet.Mask.Size() // 获取掩码长度

                    for len(selectedIPs) < ips { // 使用 ips 变量
                        randIP := make(net.IP, net.IPv6len)
                        copy(randIP, ipNet.IP)

                        // 生成随机数并填充到地址中
                        for i := ones / 8; i < net.IPv6len; i++ {
                            randIP[i] = byte(rand.Intn(256))
                        }

                        if ipNet.Contains(randIP) {
                            selectedIPs[randIP.String()] = true
                        }
                    }
                }

                // 只保留选中的 IP
                for ipStr := range selectedIPs {
                    ports := make([]int, 0)
                    if len(parts) > 1 {
                        for _, portStr := range parts[1:] {
                            port, err := strconv.Atoi(portStr)
                            if err != nil {
                                fmt.Printf("跳过端口格式错误的行: %s\n", line)
                                continue
                            }
                            ports = append(ports, port)
                        }
                    } else {
                        ports = append(ports, *defaultPort)
                    }
                    ipPortKey := ipPort{ipStr, *defaultPort}
                    if len(parts) > 1 {
                        for _, portStr := range parts[1:] {
                            port, err := strconv.Atoi(portStr)
                            if err != nil {
                                fmt.Printf("跳过端口格式错误的行: %s\n", line)
                                continue
                            }
                            ipPortKey = ipPort{ipStr, port}
                            ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], port)
                        }
                    } else {
                        ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], *defaultPort)
                    }
                }
            }
        } else {
            // 检查 IP 地址类型
            if net.ParseIP(ipStr) == nil {
                fmt.Printf("跳过无效的 IP 地址: %s\n", ipStr)
                continue
            }

            ports := make([]int, 0)
            if len(parts) > 1 { // 包含端口
                for _, portStr := range parts[1:] {
                    port, err := strconv.Atoi(portStr)
                    if err != nil {
                        fmt.Printf("跳过端口格式错误的行: %s\n", line)
                        continue
                    }
                    ports = append(ports, port)
                }
            } else {
                ports = append(ports, *defaultPort)
            }
            ipPortKey := ipPort{ipStr, *defaultPort}
            if len(parts) > 1 {
                for _, portStr := range parts[1:] {
                    port, err := strconv.Atoi(portStr)
                    if err != nil {
                        fmt.Printf("跳过端口格式错误的行: %s\n", line)
                        continue
                    }
                    ipPortKey = ipPort{ipStr, port}
                    ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], port)
                }
            } else {
                ipPortsMap[ipPortKey] = append(ipPortsMap[ipPortKey], *defaultPort)
            }
        }
    }
    return ipPortsMap, scanner.Err()
}

// inc函数实现ip地址自增
func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

var locationMap map[string]location // 在全局声明 locationMap

// 定义一个独立的函数用于测速并将结果保存到 CSV 文件
func runSpeedTestAndSaveResults(outFile string) {
    fmt.Println("开始测速...")
    ipPortsMap, err := readIPs(*File, *testAllIPs, *ips)
    if err != nil {
        fmt.Printf("无法从文件中读取 IP 和端口: %v\n", err)
        return
    }

    var results []result
    var wg sync.WaitGroup
    resultChan := make(chan result, len(ipPortsMap))

    thread := make(chan struct{}, *maxThreads)

    var count int
    total := 0
    for _, ports := range ipPortsMap {
        total += len(ports)
    }
    wg.Add(total)

    for ipPortKey, ports := range ipPortsMap {
        for _, port := range ports {
            thread <- struct{}{}
            go func(ip string, port int) {
                defer func() {
                    <-thread
                    wg.Done()
                    count++
                    percentage := float64(count) / float64(total) * 100
                    fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", count, total, percentage)
                    if count == total {
                        fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\n", count, total, percentage)
                    }
                }()

                dialer := &net.Dialer{
                    Timeout:   timeout,
                    KeepAlive: 0,
                }
                start := time.Now()
                conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port))) // 使用 port
                if err != nil {
                    return
                }
                defer conn.Close()

                tcpDuration := time.Since(start)
                start = time.Now()

                client := http.Client{
                    Transport: &http.Transport{
                        Dial: func(network, addr string) (net.Conn, error) {
                            return conn, nil
                        },
                    },
                    Timeout: timeout,
                }

                var protocol string
                if *enableTLS {
                    protocol = "https://"
                } else {
                    protocol = "http://"
                }
                requestURL := protocol + requestURL

                req, _ := http.NewRequest("GET", requestURL, nil)

                // 添加用户代理
                req.Header.Set("User-Agent", "Mozilla/5.0")
                req.Close = true
                resp, err := client.Do(req)
                if err != nil {
                    return
                }

                duration := time.Since(start)
                if duration > maxDuration {
                    return
                }

                buf := &bytes.Buffer{}
                // 创建一个读取操作的超时
                timeout := time.After(maxDuration)
                // 使用一个 goroutine 来读取响应体
                done := make(chan bool)
                go func() {
                    _, err := io.Copy(buf, resp.Body)
                    done <- true
                    if err != nil {
                        return
                    }
                }()
                // 等待读取操作完成或者超时
                select {
                case <-done:
                    // 读取操作完成
                case <-timeout:
                    // 读取操作超时
                    return
                }

                body := buf
                if err != nil {
                    return
                }

                if strings.Contains(body.String(), "uag=Mozilla/5.0") {
                    if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(body.String()); len(matches) > 1 {
                        dataCenter := matches[1]
                        loc, ok := locationMap[dataCenter]
                        if ok {
                            fmt.Printf("发现有效IP %s 端口 %d 位置信息 %s 延迟 %d 毫秒\n", ip, port, loc.City, tcpDuration.Milliseconds()) // 添加端口信息
                            resultChan <- result{ip, []int{port}, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d", tcpDuration.Milliseconds()), tcpDuration}
                        } else {
                            fmt.Printf("发现有效IP %s 端口 %d 位置信息未知 延迟 %d 毫秒\n", ip, port, tcpDuration.Milliseconds()) // 添加端口信息
                            resultChan <- result{ip, []int{port}, dataCenter, "", "", fmt.Sprintf("%d", tcpDuration.Milliseconds()), tcpDuration}
                        }
                    }
                }
            }(ipPortKey.ip, port)
        }
    }

    wg.Wait()
    close(resultChan)

    for res := range resultChan {
        results = append(results, res)
    }
    saveResultsToFile(results, outFile)
    fmt.Println("测速完成，结果已保存到", outFile)
}

func main() {
    flag.Parse()
    osType := runtime.GOOS
    if osType == "linux" {
        increaseMaxOpenFiles()
    }

    var locations []location
    if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
        fmt.Println("本地 locations.json 不存在\n正在从 https://speed.cloudflare.com/locations 下载 locations.json")
        resp, err := http.Get("https://speed.cloudflare.com/locations")
        if err != nil {
            fmt.Printf("无法从URL中获取JSON: %v\n", err)
            return
        }

        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            fmt.Printf("无法读取响应体: %v\n", err)
            return
        }

        err = json.Unmarshal(body, &locations)
        if err != nil {
            fmt.Printf("无法解析JSON: %v\n", err)
            return
        }
        file, err := os.Create("locations.json")
        if err != nil {
            fmt.Printf("无法创建文件: %v\n", err)
            return
        }
        defer file.Close()

        _, err = file.Write(body)
        if err != nil {
            fmt.Printf("无法写入文件: %v\n", err)
            return
        }
    } else {
        fmt.Println("本地 locations.json 已存在,无需重新下载")
        file, err := os.Open("locations.json")
        if err != nil {
            fmt.Printf("无法打开文件: %v\n", err)
            return
        }
        defer file.Close()

        body, err := ioutil.ReadAll(file)
        if err != nil {
            fmt.Printf("无法读取文件: %v\n", err)
            return
        }

        err = json.Unmarshal(body, &locations)
        if err != nil {
            fmt.Printf("无法解析JSON: %v\n", err)
            return
        }
    }

    locationMap = make(map[string]location) // 在 main 函数中初始化 locationMap
    for _, loc := range locations {
        locationMap[loc.Iata] = loc
    }



    // 首次测速并将结果保存到 CSV 文件
    runSpeedTestAndSaveResults(*outFile)


    // ... 读取转发规则，启动转发程序，启动监控面板 ...

    rules, err := readRulesFromCSV(*outFile, locations) // 传递 locations 变量
    if err != nil {
        log.Fatalf("Error reading rules: %v", err)
    }

    forwardingRules := make(map[string]*ForwardRule)
	for datacenter, rule := range rules {
		forwardingRules[datacenter] = rule
		go startForwarding(datacenter, rule, forwardingRules)
	}

    // 启动监控面板更新
    go displayMonitoringPanel(forwardingRules)


    // 启动定时更新规则的协程
    go func() {
        ticker := time.NewTicker(time.Duration(*updateInterval) * time.Minute) // 使用 updateInterval 变量设置定时器
        defer ticker.Stop()

        for {
            <-ticker.C
            runSpeedTestAndSaveResults(*outFile) // 重新测速并覆盖 CSV 文件

            // 重新读取 CSV 文件，更新转发规则 Target 列表
            newRules, err := readRulesFromCSV(*outFile, locations)
            if err != nil {
                log.Printf("Error reading updated rules: %v", err)
                continue
            }

            // 更新转发规则
            for datacenter, rule := range forwardingRules {
                if newRule, ok := newRules[datacenter]; ok {
                    rule.mu.Lock()
                    rule.Targets = newRule.Targets
                    rule.mu.Unlock()
                }
            }

            fmt.Println("转发规则已更新")
        }
    }()

    select {}
}

// 保存结果到文件的函数
func saveResultsToFile(results []result, outFile string) {
    file, err := os.Create(outFile)
    if err != nil {
        fmt.Printf("无法创建文件: %v\n", err)
        return
    }
    defer file.Close()

    writer := csv.NewWriter(file)

    // 始终使用包含下载速度的列名
    writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市", "网络延迟(ms)"})

    // 使用map存储每个数据中心的延迟结果，用于后续筛选
    coloResults := make(map[string][]result)
    for _, res := range results {
        latency, _ := strconv.Atoi(res.latency)
        if latency <= *maxLatency {
            if *colo != "" {
                coloList := strings.Split(*colo, ",")
                if !containsIgnoreCase(coloList, res.dataCenter) {
                    continue
                }
            }
            coloResults[res.dataCenter] = append(coloResults[res.dataCenter], res)
        }
    }

    // 遍历每个数据中心的的结果，并筛选出前topDD个延迟最低的IP
    for _, results := range coloResults {
        sort.Slice(results, func(i, j int) bool {
            latencyI, _ := strconv.Atoi(results[i].latency)
            latencyJ, _ := strconv.Atoi(results[j].latency)
            return latencyI < latencyJ
        })
        // 只保留前topDD个结果
        results = results[:min(*topDD, len(results))]

        for _, res := range results {
            writer.Write([]string{res.ip, strconv.Itoa(res.ports[0]), strconv.FormatBool(*enableTLS), res.dataCenter, res.region, res.city, res.latency})
        }
    }

    writer.Flush()
}

// 新增函数：判断字符串切片是否包含某个字符串，忽略大小写
func containsIgnoreCase(s []string, e string) bool {
    for _, a := range s {
        if strings.EqualFold(a, e) {
            return true
        }
    }
    return false
}

// 新增函数：返回两个整数中的较小值
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func readRulesFromCSV(filename string, locations []location) (map[string]*ForwardRule, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    reader := csv.NewReader(file)
    records, err := reader.ReadAll()
    if err != nil {
        return nil, err
    }

    rules := make(map[string]*ForwardRule)
    coloIndex := make(map[string]int)
    for i, loc := range locations {
        coloIndex[loc.Iata] = i + basePort
    }

    for _, record := range records[1:] { // Skip header
        ip := record[0]
        datacenter := record[3] // 数据中心列索引
        portStr := record[1]    // 端口列索引

        port, err := strconv.Atoi(portStr)
        if err != nil {
            log.Printf("Invalid port for IP %s: %v", ip, err)
            continue
        }
        sourcePort, ok := coloIndex[datacenter]
        if !ok {
            // 处理数据中心未找到的情况
            log.Printf("Data center %s not found in locations.json", datacenter)
            continue // 跳过此行
        }

        target := Target{
            IP:         ip,
            Datacenter: datacenter,
            Port:       port,
        }

        if rule, ok := rules[datacenter]; ok {
            rule.Targets = append(rule.Targets, target)
        } else {
            rules[datacenter] = &ForwardRule{
                SourcePort: sourcePort,
                Targets:    []Target{target},
            }
        }
    }

    return rules, nil
}

func startForwarding(datacenter string, rule *ForwardRule, forwardingRules map[string]*ForwardRule) {
    forwardingRulesMutex := sync.RWMutex{} // 定义 forwardingRulesMutex
    go updateBestTarget(rule, forwardingRules, &forwardingRulesMutex) // 删除 datacenter 参数

    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", rule.SourcePort))
    if err != nil {
        log.Printf("Error listening on port %d for %s: %v", rule.SourcePort, datacenter, err)
        return
    }
    defer listener.Close()

    log.Printf("Forwarding from :%d for datacenter %s", rule.SourcePort, datacenter)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Error accepting connection for %s: %v", datacenter, err)
            continue
        }

        go handleConnection(conn, rule)
    }
}


func updateBestTarget(rule *ForwardRule, forwardingRules map[string]*ForwardRule, forwardingRulesMutex *sync.RWMutex) {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        bestTarget := selectTarget(rule.Targets)
        rule.mu.Lock()
        forwardingRulesMutex.Lock()
        rule.bestTarget = &bestTarget
        forwardingRules[rule.bestTarget.Datacenter] = rule
        forwardingRulesMutex.Unlock()
        rule.mu.Unlock()
        <-ticker.C
    }
}

func measureLatency(ip string, port int) time.Duration {
    start := time.Now()
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 5*time.Second) // 使用 net.JoinHostPort 构建地址
    if err != nil {
        return time.Hour // Return a high latency if the connection fails
    }
    defer conn.Close()
    return time.Since(start)
}

func selectTarget(targets []Target) Target {
    var bestTarget Target
    lowestLatency := time.Hour

    for _, target := range targets {
        latency := measureLatency(target.IP, target.Port)
        if latency < lowestLatency {
            lowestLatency = latency
            bestTarget = target
        }
    }

    return bestTarget
}


func handleConnection(source net.Conn, rule *ForwardRule) {
    defer source.Close()

    // 每次处理连接时都获取最新的最佳目标
    rule.mu.RLock()
    target := rule.bestTarget
    rule.mu.RUnlock()

    if target == nil {
        log.Printf("No available target")
        return
    }

    // 使用 net.JoinHostPort() 构建目标地址
    targetAddress := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))

    destination, err := net.Dial("tcp", targetAddress)
    if err != nil {
        log.Printf("Error connecting to target %s: %v", targetAddress, err)
        return
    }
    defer destination.Close()

    // 使用 io.Copy 进行双向数据传输
    go func() {
        _, err := io.Copy(destination, source)
        if err != nil {
            log.Printf("Error copying data from source to target: %v", err)
        }
    }()

    _, err = io.Copy(source, destination)
    if err != nil {
        log.Printf("Error copying data from target to source: %v", err)
    }
}

func displayMonitoringPanel(forwardingRules map[string]*ForwardRule) {
    startTime := time.Now() // 记录程序启动时间

    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for {
        <-ticker.C
        fmt.Printf("\033[H\033[2J") // 清屏

        // 构建转发规则切片，并排序
        rules := make([]*ForwardRule, 0, len(forwardingRules))
        for _, rule := range forwardingRules {
            rules = append(rules, rule)
        }
        sort.Slice(rules, func(i, j int) bool {
            return rules[i].SourcePort < rules[j].SourcePort
        })

        // 找到城市名称的最大长度
        maxCityLength := 0
        for _, rule := range rules {
            if rule.bestTarget != nil {
                loc, ok := locationMap[rule.bestTarget.Datacenter]
                if ok {
                    if len(loc.City) > maxCityLength {
                        maxCityLength = len(loc.City)
                    }
                }
            }
        }

        fmt.Println("                               代理信息")
        fmt.Println("----------------------------------------------------------------------")
        for _, rule := range rules { // 遍历所有转发规则
            if rule.bestTarget != nil { // 如果最佳目标存在
                loc, ok := locationMap[rule.bestTarget.Datacenter]
                if ok {
                    // 计算城市名后面的空格数
                    cityPadding := maxCityLength - len(loc.City)
                    if cityPadding < 0 {
                        cityPadding = 0
                    }
                    cityPaddingStr := strings.Repeat(" ", cityPadding)

                    // 使用 %s 格式化字符串输出 IP 地址
                    fmt.Printf("数据中心:%s 代理端口:%d 城市:%s%s IP:%s 端口: %d\n", rule.bestTarget.Datacenter, rule.SourcePort, loc.City, cityPaddingStr, rule.bestTarget.IP, rule.bestTarget.Port)
                } else {
                    // 计算城市名后面的空格数
                    cityPadding := maxCityLength - len("未知")
                    if cityPadding < 0 {
                        cityPadding = 0
                    }
                    cityPaddingStr := strings.Repeat(" ", cityPadding)

                    // 使用 %s 格式化字符串输出 IP 地址
                    fmt.Printf("数据中心:%s 代理端口:%d 城市:未知%s IP:%s 端口: %d\n", rule.bestTarget.Datacenter, rule.SourcePort, cityPaddingStr, rule.bestTarget.IP, rule.bestTarget.Port)
                }
            }
        }

        // 计算运行时长
        elapsed := time.Since(startTime)
        elapsedStr := formatDuration(elapsed)

        // 获取当前时间
        currentTime := time.Now().Format("2006-01-02 15:04:05")

        fmt.Println("----------------------------------------------------------------------")
        fmt.Printf("运行时长:%s\t\t当前时间:%s\n", elapsedStr, currentTime)
        fmt.Println("----------------------------------------------------------------------")
    }
}

// 格式化时长
func formatDuration(d time.Duration) string {
    d = d.Round(time.Second)
    h := d / time.Hour
    d -= h * time.Hour
    m := d / time.Minute
    d -= m * time.Minute
    s := d / time.Second
    return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
