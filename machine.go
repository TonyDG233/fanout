package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// machineTokenEnv 设置后启用固定路径的机器接口。
// 不设置时整个接口完全不存在，管理面行为与旧版本一致。
const machineTokenEnv = "FANOUT_MACHINE_TOKEN"

const (
	// machineMinTokenLen 太短的 token 容易被本机其他进程猜中，直接拒绝启用。
	machineMinTokenLen = 16
	// machineRateLimit/machineRateWindow 是每个 token 的调用频率上限。
	machineRateLimit  = 30
	machineRateWindow = time.Minute
	// machineMaxBodyBytes 是本接口接受的请求体上限；端点本身只读 query，
	// 限长是为了不让任何人往管理进程里灌大包。
	machineMaxBodyBytes = 4 << 10
	// machineMaxProvisionCount 挡住一次开几百条隧道的误操作。
	machineMaxProvisionCount = 50
	// machinePrefix 是机器接口的固定前缀，不依赖随机 basepath。
	machinePrefix = "/api/machine/"
)

// machineAPI 是机器接口依赖的最小 Manager 能力集。
//
// 只声明真正用到的方法，测试可以塞一个假实现，
// 不必为了跑接口校验去拉起真实隧道。
type machineAPI interface {
	Tunnels() []*Tunnel
	Nodes() ([]Node, time.Time)
	Start(node Node) (*Tunnel, error)
	Stop(slot int) error
	Swap(slot int) error
	Provision(req ProvisionRequest) (*Job, error)
	// BackendName 返回 "3x-ui" / "native" / "xray-cf-lite"，不可用时为空串。
	BackendName() string
}

// BackendName 返回当前节点链接后端的类型，供机器接口状态展示。
func (m *Manager) BackendName() string {
	p, err := openPanel()
	if err != nil {
		return ""
	}
	return p.Kind()
}

// machineExit 是机器接口里的一条出口。
//
// 与只读接口的区别：这里明确带 socks_url（含 SOCKS5 用户/口令），
// 因为宿主上的出口管理器要靠它接管出口；除此之外不暴露 .ovpn、
// Node.Config、state.json 或任何其他凭据。只读接口 /api/readonly/*
// 继续保持不返回凭据，两者不要混用。
type machineExit struct {
	Slot        int    `json:"slot"`
	Port        int    `json:"port"`
	Status      string `json:"status"`
	ExitIP      string `json:"exit_ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Suspect     bool   `json:"suspect"`
	SocksURL    string `json:"socks_url"`
}

type machineCounts struct {
	Total   int `json:"total"`
	Up      int `json:"up"`
	Suspect int `json:"suspect"`
}

type machineStatusResponse struct {
	Exits   []machineExit `json:"exits"`
	Counts  machineCounts `json:"counts"`
	Backend string        `json:"backend"`
}

// machineRateLimiter 是固定窗口计数器。只有一个 token 会生效，
// 所以一个实例就等于"每 token 每窗口"的额度。
type machineRateLimiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	now         func() time.Time
	windowStart time.Time
	count       int
}

func newRateLimiter(limit int, window time.Duration, now func() time.Time) *machineRateLimiter {
	return &machineRateLimiter{limit: limit, window: window, now: now}
}

// allow 记一次调用。超限时同时返回还要等多久，方便写 Retry-After。
func (l *machineRateLimiter) allow() (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if l.windowStart.IsZero() || now.Sub(l.windowStart) >= l.window {
		l.windowStart = now
		l.count = 0
	}
	if l.count >= l.limit {
		wait := l.window - now.Sub(l.windowStart)
		if wait <= 0 {
			wait = time.Second
		}
		return false, wait
	}
	l.count++
	return true, 0
}

// machineTokenFromEnv 读取并校验机器接口 token。
// 未设置返回空串（接口不启用）；设置但太短属于配置错误，直接报错。
func machineTokenFromEnv(getenv func(string) string) (string, error) {
	tok := strings.TrimSpace(getenv(machineTokenEnv))
	if tok == "" {
		return "", nil
	}
	if n := utf8.RuneCountInString(tok); n < machineMinTokenLen {
		return "", fmt.Errorf("%s 至少需要 %d 个字符，当前只有 %d 个，拒绝启用机器接口",
			machineTokenEnv, machineMinTokenLen, n)
	}
	return tok, nil
}

// machineHandler 把机器接口包在管理面外面：固定路径、仅 loopback、
// Bearer token、每 token 限流。token 为空时接口整体不存在（404），
// 不会因为误挂载而出现免鉴权入口。
func machineHandler(next http.Handler, m machineAPI, token string) http.Handler {
	if token == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, machinePrefix) {
				machineJSON(w, http.StatusNotFound, map[string]string{"error": "机器接口未启用"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	return newMachineHandler(next, m, token, newRateLimiter(machineRateLimit, machineRateWindow, time.Now))
}

func newMachineHandler(next http.Handler, m machineAPI, token string, rl *machineRateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, machinePrefix) {
			next.ServeHTTP(w, r)
			return
		}

		action := strings.TrimPrefix(r.URL.Path, machinePrefix)
		remote := r.RemoteAddr

		// 内部错误统一收敛成 JSON 500，避免 panic 把连接直接切断、
		// 让管理器只拿到 EOF 却不知道发生了什么。
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("机器接口内部错误: 动作=%s 详情=%v", sanitizeAudit(action), rec)
				machineJSON(w, http.StatusInternalServerError, map[string]string{"error": "内部错误"})
			}
		}()

		if !isLoopbackRequest(r) {
			machineAudit(remote, action, "", http.StatusForbidden)
			machineJSON(w, http.StatusForbidden, map[string]string{"error": "只允许本机访问"})
			return
		}

		// 限流放在鉴权之前：本机进程拿错 token 反复试也要被计数，
		// 否则限流只保护"猜对了的人"。
		if ok, wait := rl.allow(); !ok {
			sec := int(wait.Seconds())
			if sec < 1 {
				sec = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(sec))
			machineAudit(remote, action, "", http.StatusTooManyRequests)
			machineJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":       "请求过于频繁",
				"retry_after": sec,
			})
			return
		}

		if !tokenMatches(bearerToken(r), token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="fanout-machine"`)
			machineAudit(remote, action, "", http.StatusUnauthorized)
			machineJSON(w, http.StatusUnauthorized, map[string]string{"error": "token 无效"})
			return
		}

		route, ok := machineRoutes()[r.URL.Path]
		if !ok {
			machineAudit(remote, action, "", http.StatusNotFound)
			machineJSON(w, http.StatusNotFound, map[string]string{"error": "未知的机器接口端点"})
			return
		}
		if r.Method != route.method {
			w.Header().Set("Allow", route.method)
			machineAudit(remote, action, "", http.StatusMethodNotAllowed)
			machineJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "只允许 " + route.method,
			})
			return
		}

		if r.Method == http.MethodPost && !machineReadBody(w, r) {
			machineAudit(remote, action, "body", http.StatusBadRequest)
			return
		}

		code, body, target := route.handle(m, r)
		machineAudit(remote, action, target, code)
		machineJSON(w, code, body)
	})
}

// machineRoute 把路径、方法与处理函数绑在一起，方法不允许时才好给出 Allow。
type machineRoute struct {
	method string
	handle func(m machineAPI, r *http.Request) (int, any, string)
}

func machineRoutes() map[string]machineRoute {
	return map[string]machineRoute{
		"/api/machine/status":    {http.MethodGet, machineStatus},
		"/api/machine/provision": {http.MethodPost, machineProvision},
		"/api/machine/swap":      {http.MethodPost, machineSwap},
		"/api/machine/stop":      {http.MethodPost, machineStop},
		"/api/machine/start":     {http.MethodPost, machineStart},
	}
}

// machineReadBody 把请求体读空并限长。端点只用 query 参数，
// 读掉是为了让超长请求体在进入业务逻辑之前就被挡住。
func machineReadBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, machineMaxBodyBytes)
	defer r.Body.Close()
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			machineJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("请求体不能超过 %d 字节", machineMaxBodyBytes),
			})
			return false
		}
		machineJSON(w, http.StatusBadRequest, map[string]string{"error": "读取请求体失败"})
		return false
	}
	return true
}

func machineStatus(m machineAPI, _ *http.Request) (int, any, string) {
	host := hostPublicIP()
	view := machineStatusView(m, host)
	return http.StatusOK, view, fmt.Sprintf("total=%d up=%d suspect=%d",
		view.Counts.Total, view.Counts.Up, view.Counts.Suspect)
}

// machineStatusView 组装状态响应。host 为空时退回 loopback，
// 至少让管理器拼出一个结构合法的 socks_url。
func machineStatusView(m machineAPI, host string) machineStatusResponse {
	if host == "" {
		host = "127.0.0.1"
	}
	tunnels := m.Tunnels()
	resp := machineStatusResponse{
		Exits:   make([]machineExit, 0, len(tunnels)),
		Backend: m.BackendName(),
	}
	for _, t := range tunnels {
		resp.Exits = append(resp.Exits, machineExit{
			Slot:        t.Slot,
			Port:        t.Port,
			Status:      t.Status,
			ExitIP:      t.ExitIP,
			Country:     nodeLabel(t.Node),
			CountryCode: t.Node.CountryCode,
			Suspect:     t.isSuspect(),
			SocksURL:    socksURL(host, t.Port, t.credential()),
		})
	}
	resp.Counts.Total = len(resp.Exits)
	for _, e := range resp.Exits {
		if e.Status == "up" {
			resp.Counts.Up++
		}
		if e.Suspect {
			resp.Counts.Suspect++
		}
	}
	return resp
}

func machineProvision(m machineAPI, r *http.Request) (int, any, string) {
	q := r.URL.Query()
	target := "region=" + sanitizeAudit(q.Get("region"))

	count, err := strconv.Atoi(strings.TrimSpace(q.Get("count")))
	if err != nil || count < 1 || count > machineMaxProvisionCount {
		return http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("count 必须是 1 到 %d 之间的整数", machineMaxProvisionCount),
		}, target
	}

	region, err := normalizeMachineRegion(q.Get("region"))
	if err != nil {
		return http.StatusBadRequest, map[string]string{"error": err.Error()}, target
	}

	tpl := 0
	if s := strings.TrimSpace(q.Get("template")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return http.StatusBadRequest, map[string]string{"error": "template 必须是非负整数"}, target
		}
		tpl = n
	}
	// xray-cf-lite 模式下节点由它自己管，template 传了也没有意义。
	if m.BackendName() == "xray-cf-lite" {
		tpl = 0
	}

	job, err := m.Provision(ProvisionRequest{Region: region, Count: count, TemplateID: tpl})
	if err != nil {
		return http.StatusBadRequest, map[string]string{"error": err.Error()}, target
	}
	return http.StatusOK, map[string]string{"job": job.ID()}, target
}

func machineSwap(m machineAPI, r *http.Request) (int, any, string) {
	slot, raw, err := machineSlot(r)
	if err != nil {
		return http.StatusBadRequest, map[string]string{"error": err.Error()}, "slot=" + raw
	}
	target := "slot=" + raw

	if !machineHasSlot(m, slot) {
		return http.StatusNotFound, map[string]string{"error": slotMissing(slot)}, target
	}
	if err := m.Swap(slot); err != nil {
		// 竞态下隧道可能刚好被停掉，这时按不存在返回更准确。
		if !machineHasSlot(m, slot) {
			return http.StatusNotFound, map[string]string{"error": slotMissing(slot)}, target
		}
		return http.StatusBadRequest, map[string]string{"error": err.Error()}, target
	}
	return http.StatusOK, map[string]any{"ok": true, "slot": slot}, target
}

func machineStop(m machineAPI, r *http.Request) (int, any, string) {
	slot, raw, err := machineSlot(r)
	if err != nil {
		return http.StatusBadRequest, map[string]string{"error": err.Error()}, "slot=" + raw
	}
	target := "slot=" + raw

	if !machineHasSlot(m, slot) {
		return http.StatusNotFound, map[string]string{"error": slotMissing(slot)}, target
	}
	if err := m.Stop(slot); err != nil {
		return http.StatusInternalServerError, map[string]string{"error": err.Error()}, target
	}
	return http.StatusOK, map[string]any{"ok": true, "slot": slot}, target
}

// machineStart 按节点主机名开一条新出口。
//
// 槽位由 Manager 自动分配（第一个空闲槽位），所以这里没有 slot 参数：
// 停掉的隧道已经释放槽位，用旧 slot 启动是不存在的语义。管理器要补节点
// 就传 host，拿到返回的 slot 后再用 swap/stop 管它。
func machineStart(m machineAPI, r *http.Request) (int, any, string) {
	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	if host == "" {
		if strings.TrimSpace(q.Get("slot")) != "" {
			return http.StatusBadRequest, map[string]string{
				"error": "start 按 host 启动，槽位由服务端自动分配；不要传 slot",
			}, "host="
		}
		return http.StatusBadRequest, map[string]string{"error": "缺少 host 参数"}, "host="
	}
	target := "host=" + sanitizeAudit(host)

	nodes, _ := m.Nodes()
	var picked Node
	found := false
	for _, n := range nodes {
		if n.HostName == host {
			picked, found = n, true
			break
		}
	}
	if !found {
		return http.StatusNotFound, map[string]string{"error": "节点不存在，可能列表已过期"}, target
	}

	t, err := m.Start(picked)
	if err != nil {
		return http.StatusBadRequest, map[string]string{"error": err.Error()}, target
	}
	resp := map[string]any{"ok": true, "host": host}
	if t != nil {
		resp["slot"] = t.Slot
		resp["port"] = t.Port
	}
	return http.StatusOK, resp, target
}

// machineSlot 解析必填的 slot 查询参数。slot 从 1 开始。
func machineSlot(r *http.Request) (int, string, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("slot"))
	slot, err := strconv.Atoi(raw)
	if err != nil || slot < 1 {
		return 0, sanitizeAudit(raw), fmt.Errorf("slot 参数无效")
	}
	return slot, strconv.Itoa(slot), nil
}

func machineHasSlot(m machineAPI, slot int) bool {
	for _, t := range m.Tunnels() {
		if t.Slot == slot {
			return true
		}
	}
	return false
}

func slotMissing(slot int) string {
	return fmt.Sprintf("槽位 %d 没有运行中的隧道", slot)
}

// normalizeMachineRegion 归一地区码：空表示不限，其余必须是两位字母。
// 非 ASCII 或超长输入直接拒绝，免得把奇怪的值带进日志和供应链。
func normalizeMachineRegion(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return "", nil
	}
	if len(s) != 2 {
		return "", fmt.Errorf("region 必须是两位国家码，例如 JP")
	}
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return "", fmt.Errorf("region 必须是两位国家码，例如 JP")
		}
	}
	return s, nil
}

func machineJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, code, v)
}

// machineAudit 记一条审计日志：时间由 log 包补，内容只有来源、动作、
// 目标和结果。token、请求头与响应体一律不落日志。
func machineAudit(remote, action, target string, code int) {
	if target == "" {
		target = "-"
	}
	log.Printf("机器接口 来源=%s 动作=%s 目标=%s 结果=%d",
		sanitizeAudit(remote), sanitizeAudit(action), sanitizeAudit(target), code)
}

// sanitizeAudit 去掉控制字符并限长，避免外部输入把日志行拆成多条。
func sanitizeAudit(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
