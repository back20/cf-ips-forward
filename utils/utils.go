package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloudsoda/go-smb2"
)

const (
	requestURL       = "https://speed.cloudflare.com/cdn-cgi/trace" // 请求trace URL
	locationsJsonUrl = "https://speed.cloudflare.com/locations"     // location.json下载 URL
)

// 位置信息结构体
type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

var locationMap map[string]location // IP位置数据

// isIPv4 判断IP是否为IPv4地址
func isIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // 解析失败，不是有效IP地址
	}
	return ip.To4() != nil // 如果是IPv4，To4() 会返回非空值
}

// 读取机场信息
func readLocationData() {
	var locations []location
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("正在从 " + locationsJsonUrl + " 下载 locations.json")

		resp, err := http.Get(locationsJsonUrl)
		if err != nil {
			fmt.Printf("下载失败: %v\n", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
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
		fmt.Println("\033[32m成功下载并创建 location.json\033[0m")
	} else {
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开文件: %v\n", err)
			return
		}
		defer file.Close()

		body, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("无法读取文件: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
		// 读取位置数据并存入变量
		locationMap = make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}
		// fmt.Println("读取到 loacations 机场位置数据")
	}
}

// Remove duplicates from the slice
func removeDuplicates(records []string) []string {
	uniqueMap := make(map[string]bool)
	var uniqueRecords []string

	for _, record := range records {
		if !uniqueMap[record] {
			uniqueMap[record] = true
			uniqueRecords = append(uniqueRecords, record)
		}
	}
	return uniqueRecords
}

// Filter records by a default limit per location
func filterByLocationWithLimit(records []string, defaultLimit int) []string {

	// Seed the random generator
	rand.Seed(time.Now().UnixNano())

	// Create an array of indices based on the length of records
	indices := make([]int, len(records))
	for i := 0; i < len(records); i++ {
		indices[i] = i
	}

	// Shuffle the indices array
	rand.Shuffle(len(indices), func(i, j int) {
		indices[i], indices[j] = indices[j], indices[i]
	})

	// Print records in the order of the shuffled indices
	result := []string{}
	locationCount := make(map[string]int)

	for _, idx := range indices {
		record := records[idx]
		if record == "" {
			continue
		}
		tempStr := strings.ReplaceAll(record, "速☘️", "")
		tempStr = strings.ReplaceAll(tempStr, "☘️", "")
		location := "#" + strings.Split(tempStr, "#")[1]

		// Only add if the location count has not reached the default limit
		if locationCount[location] < defaultLimit {
			result = append(result, record)
			locationCount[location]++
		}
	}

	return result
}

// 优选的订阅地址处理
func processLinesSubs() []string {

	urls := []string{
		"https://sub.443888.xyz/vless",
		"https://vless.durl.nyc.mn/zrf",
		"https://happy.1949.buzz/vless",
	}

	// results := make(map[string]bool)
	// results := make(map[string]string) // Corrected to map[string]string
	ch := make(chan string)

	var wg sync.WaitGroup

	// Start goroutines for each URL
	for _, url := range urls {
		wg.Add(1)
		go fetchDataSub(url, ch, &wg)
	}

	// Close the channel when all goroutines are done
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect results from the channel into a slice
	var results []string
	for result := range ch {
		results = append(results, result)
	}
	return results
}

func UuDownmain(sTeam []string) {

	readLocationData()

	sTeam2 := processLinesSubs()

	sTeam3 := processLinesUrls()

	// 处理本地优选的日志
	results := processLocLog()

	var mergedTeam []string
	mergedTeam = append(mergedTeam, sTeam...)
	mergedTeam = append(mergedTeam, sTeam2...)
	mergedTeam = append(mergedTeam, sTeam3...)

	// 处理传递过来的值,和url下载得到的值
	results2 := processLinesConcurrently(mergedTeam)

	// 去重
	uniqueRecords := removeDuplicates(results2)

	// Define the default limit for each location
	defaultLimit := 8

	// 每种记录取4条
	gResult := filterByLocationWithLimit(uniqueRecords, defaultLimit)

	// 排序
	sort.Slice(gResult, func(i, j int) bool {
		return strings.Split(gResult[i], "#")[1] < strings.Split(gResult[j], "#")[1]
	})

	// Write to output file
	file, err := os.Create("cf-ips.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// results = append(results, "")
	_, err = writer.WriteString("1q502u2312.zicp.fun:1236#US-圣何塞☘️跳板机(更新用)\n1q502u2312.zicp.fun:1235#GB-伦敦☘️跳板机(更新用)\n")
	if err != nil {
		log.Fatalf("Failed to write header to file: %v", err)
	}

	for _, res := range results {
		// t := strings.Replace(originalConfig, "127.0.0.1", ip.IP.String(), 1)
		_, err := writer.WriteString(res + "\n") // 每个 IP 地址换行
		if err != nil {
			log.Fatalf("Failed to write IP to file: %v", err)
		}
	}

	for _, res := range gResult {
		// t := strings.Replace(originalConfig, "127.0.0.1", ip.IP.String(), 1)
		_, err := writer.WriteString(res + "\n") // 每个 IP 地址换行
		if err != nil {
			log.Fatalf("Failed to write IP to file: %v", err)
		}
	}

	// 写入表头作为一行字符串
	header := "104.17.0.0#☘️IPV4默认\n[2606:4700::]#☘️IPV6默认\n"
	_, err = writer.WriteString(header)
	if err != nil {
		log.Fatalf("Failed to write header to file: %v", err)
	}

	writer.Flush()

	fmt.Println("Results written to output.txt")
}

func processLinesUrls() []string {

	urls := []string{
		"https://192.168.0.98/addapi.txt",
		"https://addressesapi.090227.xyz/ct",
		"https://addressesapi.090227.xyz/cmcc",
		"https://addressesapi.090227.xyz/cmcc-ipv6",
		"https://ipdb.api.030101.xyz/?type=bestproxy&country=true",
		"https://ipdb.api.030101.xyz/?type=bestcf&country=true",
		"https://addressesapi.090227.xyz/CloudFlareYes",
		"https://addressesapi.090227.xyz/ip.164746.xyz",
	}

	// results := make(map[string]bool)
	// results := make(map[string]string) // Corrected to map[string]string
	ch := make(chan string)

	var wg sync.WaitGroup

	// Start goroutines for each URL
	for _, url := range urls {
		wg.Add(1)
		go fetchData(url, ch, &wg)
	}

	// Close the channel when all goroutines are done
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect results from the channel into a slice
	var results []string
	for result := range ch {
		results = append(results, result)
	}
	return results
}

func processLinesConcurrently(lines []string) []string {
	var wg sync.WaitGroup
	ch := make(chan string)
	for _, line := range lines {
		wg.Add(1)
		go func(line string) {
			defer wg.Done()
			result := checkDataCenterCoco(line, getPort(line), "")
			ch <- result
		}(line)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect results from the channel
	var results []string
	for result := range ch {
		results = append(results, result) // Append each result to the results slice
	}
	return results
}

func getPort(input string) string {
	// Split the input by the first '#' character to ignore the name part
	parts := strings.Split(input, "#")
	address := parts[0] // Get the part before the '#'

	// Check if there's a colon in the address (i.e., the format "host:port")
	if strings.Contains(address, ":") {
		// Split the address by ':' to get the port
		hostnamePort := strings.Split(address, ":")
		return hostnamePort[1] // Return the port part
	}
	// If no port specified, return the default port 443
	return "443"
}

func fetchDataSub(url string, ch chan<- string, wg *sync.WaitGroup) {

	fmt.Printf("开始处理远程地址 %s 下载线程\n", url)

	defer wg.Done()

	// 忽略证书错误
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Make a GET request with a custom User-Agent header to mimic a browser
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set the User-Agent header to a browser-like value
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	// Send the request using the client
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response from %s: %v\n", url, err)
		return
	}

	// Convert the body []byte to a string
	bodyStr := string(body)
	if strings.Contains(bodyStr, "://") || strings.Contains(bodyStr, "#") {
		fmt.Println("URL or fragment found in the response body.")
	} else {
		// Decode the base64 string
		decodedBytes, err := base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			log.Fatalf("Error decoding base64 string: %v", err)
		}

		// Convert decoded bytes to string
		bodyStr = string(decodedBytes)
	}

	lines := strings.Split(string(bodyStr), "\n")
	for _, line := range lines {
		if line != "" {
			formattedResult := parseVless(line)
			// formattedResult := checkDataCenterCoco(line, "443", "") // Assuming port 80
			ch <- formattedResult
		}
	}
}

func parseVless(vlessURL string) string {
	// Parse the URL

	if strings.Contains(vlessURL, "://") {
		// 其它的协议处理
		parsedURL, err := url.Parse(vlessURL)
		if err != nil {
			panic(err)
		}

		// Extract the host and port
		host := parsedURL.Hostname() // This gives the IP or domain
		port := parsedURL.Port()     // This gives the port

		// Extract the name (from the fragment after the #)
		fragment := parsedURL.Fragment
		// name := strings.Split(fragment, "-")[1] // Assuming the name is after the first '-'

		// Format the result as "ip:port#name"
		result := fmt.Sprintf("%s:%s#%s", host, port, fragment)
		return result
	}

	return vlessURL
}

// Function to fetch data from a URL with a wait group to synchronize
func fetchData(url string, ch chan<- string, wg *sync.WaitGroup) {

	fmt.Printf("开始处理远程地址 %s 下载线程\n", url)

	defer wg.Done()

	// 忽略证书错误
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error fetching data from %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response from %s: %v\n", url, err)
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if line != "" {
			ch <- line
			/*
				if url == "https://192.168.0.98/addapi.txt" {
					formattedResult := checkDataCenterCoco(line, "443", "速☘️") // Assuming port 80
					ch <- formattedResult
				} else {
					formattedResult := checkDataCenterCoco(line, "443", "") // Assuming port 80
					ch <- formattedResult
				}*/
			// ch <- line // Send each line to the channel
		}
	}
}

func extractIP(input string) string {
	// Check if input contains a port by looking for ":"
	if strings.Contains(input, ":") {
		// If it's IPv6 with square brackets (e.g., [2606:4700::]:443)
		if strings.HasPrefix(input, "[") && strings.Contains(input, "]:") {
			// Remove brackets and split by ":"
			return input[1:strings.Index(input, "]")]
		}
		// For IPv4 (e.g., 104.19.32.12:443) or IPv6 without brackets
		return strings.Split(input, ":")[0]
	}

	// If there's no port, return the input as is
	return input
}

func checkDataCenterCoco(line string, port string, icon string) string {

	parts := strings.Split(line, "#")

	// 需要再进行:端口号去除
	address := extractIP(parts[0])

	if net.ParseIP(address) == nil {
		// If not a valid IP address, return the line
		return line
	}

	if address == "127.0.0.1" {
		return ""
	}

	// ipv4逻辑
	client := http.Client{
		Transport: &http.Transport{
			// 使用 DialContext 函数
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(address, port))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 阻止重定向
		},
		Timeout: 30 * time.Second,
	}

	req, _ := http.NewRequest(http.MethodHead, requestURL, nil)

	// 添加用户代理
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		// fmt.Print("x")
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		// fmt.Print("x")
		return ""
	}

	// 获取机场三字码，数据中心位置
	var colo string
	if resp.Header.Get("Server") == "cloudflare" {
		str := resp.Header.Get("CF-RAY") // 示例 cf-ray: 7bd32409eda7b020-SJC
		colo = regexp.MustCompile(`[A-Z]{3}`).FindString(str)
	} else {
		str := resp.Header.Get("x-amz-cf-pop") // 示例 X-Amz-Cf-Pop: SIN52-P1
		colo = regexp.MustCompile(`[A-Z]{3}`).FindString(str)
	}

	var retStr string
	loc, ok := locationMap[colo]
	if ok {
		// fmt.Print(".")
		retStr = address + ":" + port + "#" + loc.Cca2 + "-" + loc.City + icon
	}
	// fmt.Print("x")
	return retStr
}

func CopyFileSmb() {
	// 设置SMB连接参数
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "yousheng",     // SMB用户名
			Password: "hySheng0501.", // SMB密码
		},
	}

	// 连接到SMB服务器
	s, err := d.Dial(context.Background(), "192.168.0.98:445")
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	// 挂载共享文件夹
	fs, err := s.Mount("web")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	// 重命名文件
	err = fs.Rename("cf-ips/cf-ips.txt", "cf-ips/cf-ips.txt"+time.Now().Format("20060102150405"))
	if err != nil {
		log.Fatalf("无法重命名文件: %v", err)
	}

	// 打开本地文件
	localFilePath := "cf-ips.txt" // 替换为本地文件路径
	localFile, err := os.Open(localFilePath)
	if err != nil {
		panic(err)
	}
	defer localFile.Close()

	// 在共享目录中创建文件
	remoteFilePath := "cf-ips/cf-ips.txt" // 替换为共享文件夹中的目标文件路径
	remoteFile, err := fs.Create(remoteFilePath)
	if err != nil {
		panic(err)
	}
	defer remoteFile.Close()

	// 将本地文件内容复制到共享文件夹中的文件
	_, err = io.Copy(remoteFile, localFile)
	if err != nil {
		panic(err)
	}

	fmt.Println("文件已成功传输到共享文件夹！")
}

const blockSize = 4096 // 每次读取的块大小（可以根据文件大小调整）

func processLocLog() []string {

	var logdir string // 先声明变量

	osType := runtime.GOOS
	if osType == "linux" {
		logdir = "/mnt/pve/nvme/public/cfnat/logs" // 给 logdir 赋值
	} else {
		logdir = "./logs" // 给 logdir 赋值
	}

	// Collect results from the channel into a slice
	var results []string

	// return results

	// 获取目录下所有的文件
	files, err := filepath.Glob(filepath.Join(logdir, "*"))
	if err != nil {
		fmt.Println("Error listing files:", err)
		return results
	}

	// 遍历目录下的文件
	for _, logFile := range files {

		// 打开日志文件
		file, err := os.Open(logFile)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return results
		}
		defer file.Close()

		// 获取文件大小
		stat, err := file.Stat()
		if err != nil {
			fmt.Println("Error getting file info:", err)
			return results
		}
		fileSize := stat.Size()

		// 正则表达式匹配 "选择最佳连接: 地址: [IPv6]:port 延迟: XX ms" 的格式
		// re := regexp.MustCompile(`选择最佳连接: 地址: \[([a-fA-F0-9:]+)\]:\d+ 延迟: \d+ ms`)
		re := regexp.MustCompile(`选择最佳连接: 地址: \[?([a-fA-F0-9:.]+)\]?:\d+ 延迟: \d+ ms`)

		// 正则表达式匹配 "开始状态检查，目标地址: 127.0.0.1:1234" 的格式
		// statusCheckRE := regexp.MustCompile(`开始状态检查，目标地址: ([a-fA-F0-9:.]+):(\d+)`)
		postRe := regexp.MustCompile(`开始状态检查，目标地址: 127\.0\.0\.1:(\d+)`)

		var lastMatch string
		var lastPort string
		buffer := make([]byte, blockSize)
		remaining := []byte{}

		// 从文件末尾向前读取块
		for offset := fileSize; offset > 0; {
			// 计算本次读取的块大小
			if offset < blockSize {
				buffer = make([]byte, offset)
			}
			offset -= int64(len(buffer))

			// 设置文件指针位置并读取块
			_, err := file.Seek(offset, 0)
			if err != nil {
				fmt.Println("Error seeking file:", err)
				return results
			}
			_, err = file.Read(buffer)
			if err != nil {
				fmt.Println("Error reading file:", err)
				return results
			}

			// 把当前块和剩余的字节拼接，然后按行分割
			chunk := append(buffer, remaining...)
			lines := bytes.Split(chunk, []byte("\n"))

			// 记录最前面不完整的行（在下一次块中处理）
			remaining = lines[0]
			lines = lines[1:]

			// 倒序遍历当前块中的行
			for i := len(lines) - 1; i >= 0; i-- {
				line := string(lines[i])

				// 先核查端口
				statusCheckMatch := postRe.FindStringSubmatch(line)
				if len(statusCheckMatch) > 1 {
					lastPort = statusCheckMatch[1]
				}

				// 查找匹配的地址,如果地址找到,但端口未找到继续找
				match := re.FindStringSubmatch(line)
				if len(match) > 1 {
					if match[1] == "127.0.0.1" {
						continue
					}
					if lastPort == "" {
						continue
					}
					lastMatch = match[1]
					break // 找到最后一个匹配后立即停止
				}
			}

			if lastMatch != "" {
				break // 找到匹配后停止进一步读取块
			}
		}

		// 输出最后匹配的地址
		if lastMatch != "" {
			fmt.Println("最后出现的IPv6地址:", lastMatch)
		} else {
			fmt.Println("未找到符合条件的IPv6地址")
		}

		// 获取文件的基本名称（包括扩展名）
		fileName := filepath.Base(logFile)

		// 去掉扩展名
		dataCenter := strings.TrimSuffix(fileName, filepath.Ext(fileName))
		fmt.Printf("发现有效文件名 %s", dataCenter)

		loc, ok := locationMap[strings.ToUpper(dataCenter)]
		if ok {
			fmt.Printf("发现有效IP %s", loc.City)
			if strings.Contains(lastMatch, ":") {
				results = append(results, "["+lastMatch+"]#"+loc.Cca2+"-"+loc.City+"☘️")
			} else {
				results = append(results, ""+lastMatch+"#"+loc.Cca2+"-"+loc.City+"☘️")
			}
			// fmt.Printf("发现有效IP %s 端口 %d 位置信息 %s 延迟 %d 毫秒\n", ip, port, loc.City, tcpDuration.Milliseconds()) // 添加端口信息
			// resultChan <- result{ip, []int{port}, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d", tcpDuration.Milliseconds()), tcpDuration}
		}
	}

	return results
}

func getIpv6() string {
	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error retrieving network interfaces:", err)
		return ""
	}

	var ipv6Addresses []string

	// 遍历每个网络接口
	for _, iface := range interfaces {
		// 获取接口上的所有地址
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("Error retrieving addresses for interface %s: %v\n", iface.Name, err)
			continue
		}

		// 遍历接口的每个地址
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				fmt.Println("Error parsing address:", err)
				continue
			}

			// 检查是否为 IPv6 地址，并排除本地地址 (::1) 和 fe80 开头的地址
			if ip.To16() != nil && ip.To4() == nil && ip.String() != "::1" && !strings.HasPrefix(ip.String(), "fe80") {
				ipv6Addresses = append(ipv6Addresses, ip.String())
			}
		}
	}

	var ipv6 string

	// 输出所有非本地 IPv6 地址
	if len(ipv6Addresses) > 0 {
		fmt.Println("本机的 IPv6 地址:")
		for _, v6 := range ipv6Addresses {
			fmt.Println(v6)
			ipv6 = v6
			break
		}
	} else {
		fmt.Println("未找到非本地的 IPv6 地址")
	}
	return ipv6
}
