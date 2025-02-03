package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"

	// "runtime"
	// "time"

	"github.com/oschwald/maxminddb-golang"
)

type Checker struct {
	readers map[string]*maxminddb.Reader
}

func NewChecker() (*Checker, error) {
	files := map[string]string{
		"proxy":      "./proxy.mmdb",
		"vpn":        "./enumerated-vpn.mmdb",
		"tor":        "./tor.mmdb",
		"crawler":    "./crawler.mmdb",
		"abuser":     "./abuser.mmdb",
		"Hostingv4":  "./HostingRangesIPv4.mmdb",
		"Hostingv6":  "./HostingRangesIPv6.mmdb",
		"Locationv4": "./location.mmdb",
		"Locationv6": "./location6.mmdb",
		"Company":    "./company.mmdb",
	}

	readers := make(map[string]*maxminddb.Reader)
	for key, file := range files {
		reader, err := maxminddb.Open(file)
		if err != nil {
			return nil, err
		}
		readers[key] = reader
	}

	return &Checker{readers: readers}, nil
}

func (c *Checker) Close() {
	for _, reader := range c.readers {
		reader.Close()
	}
}

type LocationData struct {
	Timezone string `json:"timezone"`
}

type CompanyData struct {
	Type string `json:"type"`
}

func (c *Checker) handleCheck(w http.ResponseWriter, r *http.Request) {
	// start := time.Now()

	// Проверяем API ключ
	const apiKey = "dj2k3hd8js9f" // захардкоженный ключ

	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "API key is required", http.StatusUnauthorized)
		return
	}
	if key != apiKey {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	ipStr := r.URL.Query().Get("q")
	if ipStr == "" {
		http.Error(w, "No IP provided", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	// Создаем упорядоченный результат
	orderedResult := struct {
		IP         string        `json:"ip"`
		Proxy      bool          `json:"proxy"`
		VPN        bool          `json:"vpn"`
		Tor        bool          `json:"tor"`
		Crawler    bool          `json:"crawler"`
		Abuser     bool          `json:"abuser"`
		Datacenter bool          `json:"datacenter"`
		Location   *LocationData `json:"location"`
		Company    *CompanyData  `json:"company"`

		// Debug      map[string]interface{} `json:"_debug"`
	}{
		IP: ipStr,
	}

	// Заполняем булевы поля
	checkKeys := []string{"proxy", "vpn", "tor", "crawler", "abuser"}
	for _, key := range checkKeys {
		if reader, ok := c.readers[key]; ok {
			var data interface{}
			err := reader.Lookup(ip, &data)
			switch key {
			case "proxy":
				orderedResult.Proxy = err == nil && data != nil
			case "vpn":
				orderedResult.VPN = err == nil && data != nil
			case "tor":
				orderedResult.Tor = err == nil && data != nil
			case "crawler":
				orderedResult.Crawler = err == nil && data != nil
			case "abuser":
				orderedResult.Abuser = err == nil && data != nil
			}
		}
	}

	// Отдельная проверка для датацентров
	if reader, ok := c.readers["Hostingv4"]; ok {
		var data interface{}
		err := reader.Lookup(ip, &data)
		orderedResult.Datacenter = err == nil && data != nil
	}
	if !orderedResult.Datacenter { // проверяем v6 только если v4 не нашел
		if reader, ok := c.readers["Hostingv6"]; ok {
			var data interface{}
			err := reader.Lookup(ip, &data)
			orderedResult.Datacenter = err == nil && data != nil
		}
	}

	// Получаем данные о локации
	locationKey := "Locationv4"
	if ip.To4() == nil {
		locationKey = "Locationv6"
	}
	if reader, ok := c.readers[locationKey]; ok {
		var rawData map[string]interface{}
		err := reader.Lookup(ip, &rawData)
		if err == nil {
			if tz, ok := rawData["timezone"].(string); ok {
				orderedResult.Location = &LocationData{Timezone: tz}
			}
		}
	}

	// Получаем данные о компании
	if reader, ok := c.readers["Company"]; ok {
		var rawData map[string]interface{}
		err := reader.Lookup(ip, &rawData)
		if err == nil {
			if typ, ok := rawData["type"].(string); ok {
				orderedResult.Company = &CompanyData{Type: typ}
			}
		}
	}

	// Добавляем дебаг информацию
	// 	var m runtime.MemStats
	// 	runtime.ReadMemStats(&m)
	// 	orderedResult.Debug = map[string]interface{}{
	// 		"lookup_time_ms": float64(time.Since(start).Microseconds()) / 1000.0,
	// 		"goroutines":     runtime.NumGoroutine(),
	// 		"memory_kb":      m.Alloc / 1024,
	// 	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orderedResult)
}

func main() {
	checker, err := NewChecker()
	if err != nil {
		log.Fatal(err)
	}
	defer checker.Close()

	http.HandleFunc("/", checker.handleCheck)
	log.Fatal(http.ListenAndServe(":3899", nil))
}
