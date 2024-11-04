package utils

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
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

func UuDownmain(sTeam []string) {

	readLocationData()

	// 处理传递过来的值
	results := processLinesConcurrently(sTeam)

	results2 := processLinesUrls()

	// Write to output file
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, res := range results {
		// t := strings.Replace(originalConfig, "127.0.0.1", ip.IP.String(), 1)
		_, err := writer.WriteString(res + "\n") // 每个 IP 地址换行
		if err != nil {
			log.Fatalf("Failed to write IP to file: %v", err)
		}
	}

	for _, res := range results2 {
		// t := strings.Replace(originalConfig, "127.0.0.1", ip.IP.String(), 1)
		_, err := writer.WriteString(res + "\n") // 每个 IP 地址换行
		if err != nil {
			log.Fatalf("Failed to write IP to file: %v", err)
		}
	}

	writer.Flush()

	fmt.Println("Results written to output.txt")
}

func processLinesUrls() []string {

	urls := []string{
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
			result := checkDataCenterCoco(line, "443", "☘️")
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

// Function to fetch data from a URL with a wait group to synchronize
func fetchData(url string, ch chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := http.Get(url)
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

			formattedResult := checkDataCenterCoco(line, "443", "") // Assuming port 80
			ch <- formattedResult

			// ch <- line // Send each line to the channel
		}
	}
}

func checkDataCenterCoco(line string, port string, icon string) string {

	parts := strings.Split(line, "#")

	if !isIPv4(parts[0]) {
		return line
	}

	// ipv4逻辑
	client := http.Client{
		Transport: &http.Transport{
			// 使用 DialContext 函数
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(parts[0], port))
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
		return line
	}
	if resp.StatusCode != http.StatusOK {
		// fmt.Print("x")
		return line
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

	loc, ok := locationMap[colo]
	if ok {
		// fmt.Print(".")
		return parts[0] + "#" + icon + loc.Cca2 + " - " + loc.City
	}
	// fmt.Print("x")
	return line
}
