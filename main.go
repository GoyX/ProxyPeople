package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type stats struct{ Down, Up int64 }

var (
	start   = time.Now()
	mu      sync.Mutex
	cache   stats
	cacheAt time.Time
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func hx(s string, n int) string {
	x := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", x)[:n]
}

func deriveUUID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var private = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"}

// Telegram data-center ranges (used only when TELEGRAM_ONLY=1)
var telegram = []string{"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
	"91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22", "91.105.192.0/23",
	"185.76.151.0/24", "95.161.64.0/20", "2001:b28:f23d::/48", "2001:b28:f23f::/48",
	"2001:67c:4e8::/48", "2a0a:f280::/32"}

type m = map[string]any

func buildConfig(port int, id, wsPath string, only bool) []byte {
	clients := []m{{"id": id, "email": "u"}}
	rules := []m{
		{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		{"type": "field", "ip": private, "outboundTag": "block"},
		{"type": "field", "port": "25", "outboundTag": "block"},
	}
	if only {
		rules = append(rules,
			m{"type": "field", "ip": telegram, "outboundTag": "direct"},
			m{"type": "field", "network": "tcp,udp", "outboundTag": "block"})
	}
	cfg := m{
		"log":    m{"loglevel": "warning"},
		"stats":  m{},
		"api":    m{"tag": "api", "services": []string{"StatsService"}},
		"policy": m{"system": m{"statsInboundUplink": true, "statsInboundDownlink": true}},
		"inbounds": []m{
			{"tag": "in", "listen": "0.0.0.0", "port": port, "protocol": "vless",
				"settings": m{"clients": clients, "decryption": "none",
					"fallbacks": []m{{"path": wsPath, "dest": 10001}, {"dest": 8080}}},
				"streamSettings": m{"network": "tcp"}},
			{"tag": "ws", "listen": "127.0.0.1", "port": 10001, "protocol": "vless",
				"settings":       m{"clients": clients, "decryption": "none"},
				"streamSettings": m{"network": "ws", "wsSettings": m{"path": wsPath}}},
			{"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
				"settings": m{"address": "127.0.0.1"}},
		},
		"outbounds": []m{
			{"tag": "direct", "protocol": "freedom", "settings": m{"domainStrategy": "UseIPv4"}},
			{"tag": "block", "protocol": "blackhole"},
		},
		"routing": m{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	b, _ := json.Marshal(cfg)
	return b
}

func getStats() stats {
	mu.Lock()
	defer mu.Unlock()
	if time.Since(cacheAt) < 2*time.Second {
		return cache
	}
	out, err := exec.Command("/xray", "api", "statsquery", "-s", "127.0.0.1:10085").Output()
	if err != nil {
		return cache
	}
	var r struct {
		Stat []struct {
			Name  string
			Value json.Number
		}
	}
	if json.Unmarshal(out, &r) != nil {
		return cache
	}
	var s stats
	for _, e := range r.Stat {
		v, _ := e.Value.Int64()
		switch e.Name {
		case "inbound>>>ws>>>traffic>>>downlink":
			s.Down = v
		case "inbound>>>ws>>>traffic>>>uplink":
			s.Up = v
		}
	}
	cache, cacheAt = s, time.Now()
	return s
}

const page = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Proxy</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--mut:#777;--bar:#e5e5e5;--acc:#2a7de1}
@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mut:#999;--bar:#333}}
body{font:16px system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:640px;margin:2rem auto;padding:0 1rem}
code,textarea{font:13px ui-monospace,monospace}
textarea{width:100%;height:5.5rem;background:transparent;color:inherit;border:1px solid var(--bar);border-radius:6px;padding:.5rem;box-sizing:border-box}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;cursor:pointer}
.bar{height:12px;background:var(--bar);border-radius:6px;overflow:hidden;margin:.4rem 0}
.bar i{display:block;height:100%;background:var(--acc);width:0}
.g{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin:1rem 0}
.g b{display:block;font-size:1.3rem}.g span,small{color:var(--mut)}
</style>
<h2>Proxy status</h2>
<p>Import this link into a VLESS client (v2rayNG, Hiddify, NekoBox, v2rayN):</p>
<textarea id=l readonly>{{LINK}}</textarea>
<p><button onclick="navigator.clipboard.writeText(l.value);this.textContent='Copied'">Copy link</button></p>
<div class=g>
<div><span>Downloaded</span><b id=d>-</b></div>
<div><span>Uploaded</span><b id=u>-</b></div>
<div><span>Uptime</span><b id=t>-</b></div>
</div>
<div>Monthly quota (download side): <b id=p>-</b></div>
<div class=bar><i id=b></i></div>
<small>Counters reset when the service restarts or sleeps. Render's dashboard shows the authoritative monthly bandwidth.</small>
<script>
const Q={{QUOTA}}*1e9,$=i=>document.getElementById(i);
function f(x){const a=['B','KB','MB','GB','TB'];let i=0;while(x>=1000&&i<4){x/=1000;i++}return x.toFixed(i?2:0)+' '+a[i]}
function up(s){const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h+'h '+m+'m'}
async function tick(){try{const d=await(await fetch(location.pathname.replace(/\/$/,'')+'/json')).json();
$('d').textContent=f(d.down);$('u').textContent=f(d.up);$('t').textContent=up(d.uptime);
const p=Math.min(100,d.down/Q*100);$('p').textContent=p.toFixed(2)+'%';$('b').style.width=p+'%'}catch(e){}}
tick();setInterval(tick,3000);
</script>`

func main() {
	port := 10000
	if p := os.Getenv("PORT"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	seed := env("SECRET", env("RENDER_SERVICE_ID", func() string { h, _ := os.Hostname(); return h }()))
	id := deriveUUID(seed)
	wsPath := "/" + hx(id+"ws", 12)
	token := hx(id+"status", 20)
	only := os.Getenv("TELEGRAM_ONLY") == "1"
	quota := env("QUOTA_GB", "100")
	hostEnv := os.Getenv("RENDER_EXTERNAL_HOSTNAME")

	if err := os.WriteFile("/tmp/config.json", buildConfig(port, id, wsPath, only), 0o600); err != nil {
		log.Fatal(err)
	}

	link := func(host string) string {
		return fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s#Render-Proxy",
			id, host, host, host, url.QueryEscape(wsPath))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok"))
	})
	base := "/s/" + token
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		host := hostEnv
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		strings.NewReplacer("{{LINK}}", link(host), "{{QUOTA}}", quota).WriteString(w, page)
	})
	mux.HandleFunc(base+"/json", func(w http.ResponseWriter, r *http.Request) {
		s := getStats()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"down":%d,"up":%d,"uptime":%d}`, s.Down, s.Up, int(time.Since(start).Seconds()))
	})
	go func() { log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux)) }()

	if hostEnv != "" {
		log.Printf("STATUS PAGE + LINK: https://%s%s", hostEnv, base)
	} else {
		log.Printf("STATUS PAGE path: %s", base)
	}

	// Keep the free instance awake (self-ping through Render's public URL)
	if u := os.Getenv("RENDER_EXTERNAL_URL"); u != "" && env("KEEPALIVE", "1") == "1" {
		go func() {
			for {
				time.Sleep(10 * time.Minute)
				if resp, err := http.Get(u); err == nil {
					resp.Body.Close()
				}
			}
		}()
	}

	cmd := exec.Command("/xray", "run", "-c", "/tmp/config.json")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	log.Fatal(cmd.Wait())
}
