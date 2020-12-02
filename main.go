package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/axgle/mahonia"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type probeArgs []string
var iplist []string
var ipPortMap map[string][]string
var mux sync.Mutex

func (p *probeArgs) Set(val string) error {
	*p = append(*p, val)
	return nil
}

func (p probeArgs) String() string {
	return strings.Join(p, ",")
}

func raw_connect(url string) bool {
    timeout := time.Second
    reURI := regexp.MustCompile("[0-9]+.[0-9]+.[0-9]+.[0-9]+:[0-9]+")
	uri := reURI.FindAllString(url, -1)
    conn, _ := net.DialTimeout("tcp", uri[0], timeout)
    if conn != nil {
        conn.Close()
        return true
    } else {
       	return false
    }
}

func isListening(client *http.Client, url, method string) bool {

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return false
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	if resp != nil {
		mux.Lock()
		printInfo(req, resp, err, true)
		mux.Unlock()
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	} else {
		if raw_connect(url) {
			mux.Lock()
			printInfo(req, resp, err, true)
			mux.Unlock()
		} else {
			mux.Lock()
			printInfo(req, resp, err, false)
			mux.Unlock()
		}
	}

	if err != nil {
		return false
	}

	return true
}

func cidr2ip(ipcir string) []string {
	var iplist []string

	ip := ipcir
	if nil != net.ParseIP(ip) {
		iplist = append(iplist,ip)
		return iplist
	} else {
		_, ipv4Net, err := net.ParseCIDR(ip)

		if err != nil {
			log.Fatal("input ipcidr is error!\n")
		}

		// convert IPNet struct mask and address to uint32
		// network is BigEndian
		mask := binary.BigEndian.Uint32(ipv4Net.Mask)
		start := binary.BigEndian.Uint32(ipv4Net.IP)

		// find the final address
		finish := (start & mask) | (mask ^ 0xffffffff)

		// loop through addresses as uint32
		for i := start; i <= finish; i++ {
			// convert back to net.IP
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)
			iplist = append(iplist, ip.String())
		}
		return iplist
	}
}

func printInfo(req *http.Request, resp *http.Response, err error, open bool) {
	//converts a  string from UTF-8 to gbk encoding
	hasTitle := false
	sysType := runtime.GOOS
	enc := mahonia.NewEncoder("gbk")

	// Print the URI
	reIP := regexp.MustCompile("[0-9]+.[0-9]+.[0-9]+.[0-9]+")
	requestIP := reIP.FindAllString(req.URL.String(), -1)
	fmt.Printf("%s,", requestIP[0])
	// Print the URL
	fmt.Printf("%s,", req.URL)
	
	if resp != nil {
		// Print the title (If has one)
		z := html.NewTokenizer(resp.Body)
		for {
			tt := z.Next()
			if tt == html.ErrorToken { break }
			t := z.Token()

			if t.Type == html.StartTagToken && t.Data == "title" {
				if z.Next() == html.TextToken {
				title := strings.TrimSpace(z.Token().Data)
				// If the OS is windows, use gbk instead of utf-8
				if sysType == "windows"{
						fmt.Printf("%s,", enc.ConvertString(title))
					} else {
						fmt.Printf("%s,", title)
					}
					hasTitle = true
					break
				}
			}
		}
		if !hasTitle {
			fmt.Printf("notitle,")
		}
		// Print the HTTP status
		reStatus := regexp.MustCompile("[0-9]+")
		status := reStatus.FindAllString(resp.Status, -1)
		fmt.Print(status[0] + ",")
		// Print the content length
		fmt.Print(strconv.FormatInt(resp.ContentLength, 10) + ",")
	} else {
		// Should has no data here
		fmt.Print(",,,")
	}

	if open {
		fmt.Print("open")
	} else {
		fmt.Print("close")
	}
	
	fmt.Printf("\n")
}

func main() {

	// Modify the default usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage:\n")
		fmt.Fprintf(os.Stderr, "  Scan a single IP:\n\techo [IP] | ./[ProgramName] [options]\n")
		fmt.Fprintf(os.Stderr, "  Scan all IPs within a segment:\n\techo [IPSegment] | ./[ProgramName] [options]\n")
		fmt.Fprintf(os.Stderr, "  Scan IPs from a file:\n\tcat [FileName] | ./[ProgramName] [options]\n")

		fmt.Fprintf(os.Stderr, "\nParameters:\n")
		flag.PrintDefaults()
	}

	// concurrency flag
	var concurrency int
	flag.IntVar(&concurrency, "c", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")

	// probe flags
	var probes probeArgs
	flag.Var(&probes, "p", "add additional probe (port1,port2,...) or large/xlarge, use probe 80 and 443 if not set")

	// skip default probes flag
	var skipDefault bool
	flag.BoolVar(&skipDefault, "s", false, "\nalso scan default probes (http:80 and https:443)")

	// timeout flag
	var to int
	flag.IntVar(&to, "t", 2500, "timeout (milliseconds)")

	// HTTP method to use
	var method string
	flag.StringVar(&method, "method", "GET", "HTTP method to use")

	// prefer https
	var preferHTTPS bool
	flag.BoolVar(&preferHTTPS, "prefer-https", false, "only try plain HTTP if HTTPS fails")

	flag.Parse()

	// make an actual time.Duration out of the timeout
	timeout := time.Duration(to * 1000000)

	var tr = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}

	// domain/port pairs are initially sent on the httpsURLs channel.
	// If they are listening and the --prefer-https flag is set then
	// no HTTP check is performed; otherwise they're put onto the httpURLs
	// channel for an HTTP check.
	httpsURLs := make(chan string)
	httpURLs := make(chan string)
	output := make(chan string)
	ipPortMap = make(map[string][]string)

	// HTTPS workers
	var httpsWG sync.WaitGroup
	for i := 0; i < concurrency/2; i++ {
		httpsWG.Add(1)

		go func() {
			for url := range httpsURLs {
				// always try HTTPS first
				withProto := "https://" + url
				if isListening(client, withProto, method) {
					output <- withProto

					// skip trying HTTP if --prefer-https is set
					if preferHTTPS {
						continue
					}
				}

				httpURLs <- url
			}

			httpsWG.Done()
		}()
	}

	// HTTP workers
	var httpWG sync.WaitGroup
	for i := 0; i < concurrency/2; i++ {
		httpWG.Add(1)

		go func() {
			for url := range httpURLs {
				withProto := "http://" + url
				if isListening(client, withProto, method) {
					output <- withProto
					continue
				}
			}

			httpWG.Done()
		}()
	}

	// Close the httpURLs channel when the HTTPS workers are done
	go func() {
		httpsWG.Wait()
		close(httpURLs)
	}()

	// Output worker
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for o := range output {
			if strings.Count(o, ":") == 1 {
				iplist = append(iplist, o)
			} else if strings.Count(o, ":") == 2 {
				posplit := strings.Split(o,":")
				ipPortMap[posplit[0]+":"+posplit[1]] = append(ipPortMap[posplit[0]+":"+posplit[1]], posplit[2])
			}
		}
		outputWG.Done()
	}()

	// Close the output channel when the HTTP workers are done
	go func() {
		httpWG.Wait()
		close(output)
	}()

	// accept domains on stdin
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		ipstring := sc.Text()

		// Fetch into individual ip
		var domain string
		iprawlist := cidr2ip(ipstring)

		for _, ip := range iprawlist {
			domain = strings.ToLower(ip)

			// submit standard port checks
			if skipDefault && len(probes) != 0{
				httpsURLs <- domain
			}

			// Adding port templates
			xlarge := []string{"22", "80", "443", "81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}
			large := []string{"22", "80", "443", "81", "591", "2082", "2087", "2095", "2096", "3000", "8000", "8001", "8008", "8080", "8083", "8443", "8834", "8888"}

			// Use 80 and 443 if no other ports are set
			if len(probes) == 0 {
				httpsURLs <- fmt.Sprintf("%s:%s", domain, "80")
				httpsURLs <- fmt.Sprintf("%s:%s", domain, "443")
			}
			// submit any additional proto:port probes
			for _, p := range probes {
				switch p {
				case "xlarge":
					for _, port := range xlarge {
						httpsURLs <- fmt.Sprintf("%s:%s", domain, port)
					}
				case "large":
					for _, port := range large {
						httpsURLs <- fmt.Sprintf("%s:%s", domain, port)
					}
				default:
					ports := strings.Split(p, ",")
					for _, port := range ports {
						//"https" will imply an http check as well unless the --prefer-https flag is set
						httpsURLs <- fmt.Sprintf("%s:%s", domain, port)
					}
				}
			}
		}
	}

	// once we've sent all the URLs off we can close the
	// input/httpsURLs channel. The workers will finish what they're
	// doing and then call 'Done' on the WaitGroup
	close(httpsURLs)

	// check there were no errors reading stdin (unlikely)
	if err := sc.Err(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
	}

	// Wait until the output waitgroup is done
	outputWG.Wait()

}
