package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const machineTestToken = "0123456789abcdef" // 刚好 16 个字符

// fakeMachine 只实现机器接口用到的 Manager 方法，避免单测碰真实隧道。
type fakeMachine struct {
	tunnels []*Tunnel
	nodes   []Node
	backend string
	jobs    JobStore

	started     []Node
	stopped     []int
	swapped     []int
	provisioned []ProvisionRequest

	startErr     error
	stopErr      error
	swapErr      error
	provisionErr error
}

func (f *fakeMachine) Tunnels() []*Tunnel { return f.tunnels }

func (f *fakeMachine) Nodes() ([]Node, time.Time) { return f.nodes, time.Time{} }

func (f *fakeMachine) Start(node Node) (*Tunnel, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.started = append(f.started, node)
	return &Tunnel{Slot: 5, Port: 1200, Node: node}, nil
}

func (f *fakeMachine) Stop(slot int) error {
	if f.stopErr != nil {
		return f.stopErr
	}
	f.stopped = append(f.stopped, slot)
	return nil
}

func (f *fakeMachine) Swap(slot int) error {
	if f.swapErr != nil {
		return f.swapErr
	}
	f.swapped = append(f.swapped, slot)
	return nil
}

func (f *fakeMachine) Provision(req ProvisionRequest) (*Job, error) {
	if f.provisionErr != nil {
		return nil, f.provisionErr
	}
	f.provisioned = append(f.provisioned, req)
	return f.jobs.New("测试作业", []string{"出口"}), nil
}

func (f *fakeMachine) BackendName() string { return f.backend }

func newFakeMachine() *fakeMachine {
	f := &fakeMachine{
		backend: "native",
		tunnels: []*Tunnel{
			{
				Slot: 1, Port: 1080, Status: "up", ExitIP: "203.0.113.9",
				Node: Node{HostName: "node-1", Country: "Japan", CountryCode: "JP",
					Config: "client\nremote 1.2.3.4 1194\nsecret-config-line"},
				Cred: SocksCred{User: "fo-u1", Pass: "p1"},
			},
			{
				Slot: 2, Port: 1081, Status: "starting",
				Node: Node{HostName: "node-2", Country: "Korea", CountryCode: "KR"},
				Cred: SocksCred{User: "fo-u2", Pass: "p2"},
			},
		},
		nodes: []Node{{HostName: "node-1"}, {HostName: "node-2"}},
	}
	f.tunnels[1].markSuspect()
	return f
}

func machineRequest(method, target, token, remote, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	if remote == "" {
		remote = "127.0.0.1:5000"
	}
	r.RemoteAddr = remote
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func serveMachine(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func passthrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("next"))
	})
}

func TestMachineTokenFromEnv(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		want    string
		wantErr bool
	}{
		{"未设置", "", "", false},
		{"空串", "   ", "", false},
		{"太短", "0123456789abcde", "", true}, // 15
		{"多字节但字符不够", strings.Repeat("密", 6), "", true},
		{"刚好 16", "0123456789abcdef", "0123456789abcdef", false},
		{"两端空格被裁掉", "  fedcba9876543210  ", "fedcba9876543210", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := machineTokenFromEnv(func(string) string { return c.env })
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v，期望错误=%v", err, c.wantErr)
			}
			if got != c.want {
				t.Errorf("token = %q，期望 %q", got, c.want)
			}
		})
	}
}

func TestMachineRateLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	rl := newRateLimiter(2, time.Minute, func() time.Time { return now })

	if ok, _ := rl.allow(); !ok {
		t.Fatal("第 1 次应放行")
	}
	if ok, _ := rl.allow(); !ok {
		t.Fatal("第 2 次应放行")
	}
	ok, wait := rl.allow()
	if ok {
		t.Fatal("第 3 次应被限流")
	}
	if wait != time.Minute {
		t.Errorf("等待时间 = %v，期望 1m", wait)
	}

	now = now.Add(time.Minute)
	if ok, _ := rl.allow(); !ok {
		t.Error("新窗口应重新放行")
	}
}

func TestMachineHandlerAuthAndLoopback(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	if w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", "", "", "")); w.Code != http.StatusUnauthorized {
		t.Errorf("无 token 状态码 = %d，期望 401", w.Code)
	}
	if w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", "wrong-token", "", "")); w.Code != http.StatusUnauthorized {
		t.Errorf("错误 token 状态码 = %d，期望 401", w.Code)
	}
	if w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", machineTestToken, "192.0.2.10:1234", "")); w.Code != http.StatusForbidden {
		t.Errorf("非 loopback 状态码 = %d，期望 403", w.Code)
	}
	if w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", machineTestToken, "[::1]:1234", "")); w.Code != http.StatusOK {
		t.Errorf("IPv6 loopback 状态码 = %d，期望 200", w.Code)
	}
}

func TestMachineEmptyTokenNeverAuthenticates(t *testing.T) {
	h := machineHandler(passthrough(), newFakeMachine(), "")
	if w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", "", "", "")); w.Code != http.StatusNotFound {
		t.Errorf("空 token 挂载时状态码 = %d，期望 404", w.Code)
	}
	if w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", "whatever", "", "")); w.Code != http.StatusNotFound {
		t.Errorf("空 token 挂载时带任意 token 状态码 = %d，期望 404", w.Code)
	}
	w := serveMachine(h, machineRequest(http.MethodGet, "/api/tunnels", "", "", ""))
	if w.Body.String() != "next" {
		t.Errorf("非机器路径应原样交给内层 handler，实际 %q", w.Body.String())
	}
}

func TestMachineHandlerMethods(t *testing.T) {
	h := machineHandler(passthrough(), newFakeMachine(), machineTestToken)

	w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/provision?count=1", machineTestToken, "", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET provision 状态码 = %d，期望 405", w.Code)
	}
	if got := w.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow = %q，期望 POST", got)
	}

	w = serveMachine(h, machineRequest(http.MethodPost, "/api/machine/status", machineTestToken, "", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status 状态码 = %d，期望 405", w.Code)
	}
	if got := w.Header().Get("Allow"); got != http.MethodGet {
		t.Errorf("Allow = %q，期望 GET", got)
	}

	if w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/nope", machineTestToken, "", "")); w.Code != http.StatusNotFound {
		t.Errorf("未知端点状态码 = %d，期望 404", w.Code)
	}
}

func TestMachineStatusShape(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	setPublicIPOverride("203.0.113.10")
	t.Cleanup(func() { setPublicIPOverride("") })

	w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", machineTestToken, "", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", w.Code)
	}

	var got machineStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if got.Backend != "native" {
		t.Errorf("backend = %q，期望 native", got.Backend)
	}
	if got.Counts != (machineCounts{Total: 2, Up: 1, Suspect: 1}) {
		t.Errorf("counts = %+v，期望 total=2 up=1 suspect=1", got.Counts)
	}
	if len(got.Exits) != 2 {
		t.Fatalf("出口数量 = %d，期望 2", len(got.Exits))
	}
	first := got.Exits[0]
	if first.Slot != 1 || first.Port != 1080 || first.Status != "up" ||
		first.ExitIP != "203.0.113.9" || first.CountryCode != "JP" ||
		first.Suspect || !strings.Contains(first.Country, "日本") {
		t.Errorf("第一条出口字段不符: %+v", first)
	}
	if first.SocksURL != "socks5://fo-u1:p1@203.0.113.10:1080" {
		t.Errorf("socks_url = %q，期望带上 SOCKS5 凭据与公网地址", first.SocksURL)
	}
	if !got.Exits[1].Suspect {
		t.Error("被标记的出口应返回 suspect=true")
	}

	body := w.Body.String()
	for _, forbidden := range []string{
		"socks_user", "socks_pass", "secret-config-line", "remote 1.2.3.4",
		"<ca>", ".ovpn", "state.json", "password",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("机器状态泄露了敏感内容 %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, "fo-u1") || !strings.Contains(body, "p1") {
		t.Errorf("机器接口应返回 socks_url 里的凭据，实际 %s", body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q，期望 no-store", w.Header().Get("Cache-Control"))
	}
}

func TestMachineRateLimitHTTP(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	setPublicIPOverride("203.0.113.10")
	t.Cleanup(func() { setPublicIPOverride("") })

	for i := 0; i < machineRateLimit; i++ {
		w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", machineTestToken, "", ""))
		if w.Code != http.StatusOK {
			t.Fatalf("第 %d 次状态码 = %d，期望 200", i+1, w.Code)
		}
	}
	w := serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", machineTestToken, "", ""))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("超限状态码 = %d，期望 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 应带 Retry-After")
	}
	var resp struct {
		Error      string `json:"error"`
		RetryAfter int    `json:"retry_after"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("429 响应不是 JSON: %v", err)
	}
	if resp.RetryAfter < 1 || resp.Error == "" {
		t.Errorf("429 响应缺少 retry_after/error: %+v", resp)
	}
}

func TestMachineProvisionValidation(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	bad := []string{
		"/api/machine/provision",
		"/api/machine/provision?count=abc",
		"/api/machine/provision?count=0",
		"/api/machine/provision?count=51",
		"/api/machine/provision?count=1&region=J",
		"/api/machine/provision?count=1&region=JPN",
		"/api/machine/provision?count=1&region=j1",
		"/api/machine/provision?count=1&template=abc",
		"/api/machine/provision?count=1&template=-2",
	}
	for _, target := range bad {
		w := serveMachine(h, machineRequest(http.MethodPost, target, machineTestToken, "", ""))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s 状态码 = %d，期望 400", target, w.Code)
		}
	}
	if len(f.provisioned) != 0 {
		t.Errorf("参数不合法时不应调用 Provision，实际 %d 次", len(f.provisioned))
	}

	w := serveMachine(h, machineRequest(http.MethodPost,
		"/api/machine/provision?count=2&region=jp&template=7", machineTestToken, "", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("合法 provision 状态码 = %d，期望 200: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Job string `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Job == "" {
		t.Fatalf("provision 应返回 job: err=%v body=%s", err, w.Body.String())
	}
	if len(f.provisioned) != 1 {
		t.Fatalf("Provision 调用次数 = %d，期望 1", len(f.provisioned))
	}
	req := f.provisioned[0]
	if req.Region != "JP" || req.Count != 2 || req.TemplateID != 7 {
		t.Errorf("Provision 参数 = %+v，期望 JP/2/7", req)
	}
}

func TestMachineProvisionIgnoresTemplateInXCL(t *testing.T) {
	f := newFakeMachine()
	f.backend = "xray-cf-lite"
	h := machineHandler(passthrough(), f, machineTestToken)

	w := serveMachine(h, machineRequest(http.MethodPost,
		"/api/machine/provision?count=1&template=9", machineTestToken, "", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200: %s", w.Code, w.Body.String())
	}
	if len(f.provisioned) != 1 || f.provisioned[0].TemplateID != 0 {
		t.Errorf("xray-cf-lite 下 template 应被忽略，实际 %+v", f.provisioned)
	}
}

func TestMachineSwapAndStop(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	bad := []string{
		"/api/machine/swap",
		"/api/machine/swap?slot=abc",
		"/api/machine/swap?slot=0",
		"/api/machine/stop",
		"/api/machine/stop?slot=-1",
	}
	for _, target := range bad {
		w := serveMachine(h, machineRequest(http.MethodPost, target, machineTestToken, "", ""))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s 状态码 = %d，期望 400", target, w.Code)
		}
	}

	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/swap?slot=99", machineTestToken, "", "")); w.Code != http.StatusNotFound {
		t.Errorf("swap 不存在的槽位状态码 = %d，期望 404", w.Code)
	}
	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/stop?slot=99", machineTestToken, "", "")); w.Code != http.StatusNotFound {
		t.Errorf("stop 不存在的槽位状态码 = %d，期望 404", w.Code)
	}

	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/swap?slot=1", machineTestToken, "", "")); w.Code != http.StatusOK {
		t.Errorf("swap 状态码 = %d，期望 200: %s", w.Code, w.Body.String())
	}
	if len(f.swapped) != 1 || f.swapped[0] != 1 {
		t.Errorf("Swap 调用记录 = %v，期望 [1]", f.swapped)
	}

	f.swapErr = errMachineTest
	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/swap?slot=1", machineTestToken, "", "")); w.Code != http.StatusBadRequest {
		t.Errorf("Swap 业务失败状态码 = %d，期望 400", w.Code)
	}
	f.swapErr = nil

	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/stop?slot=1", machineTestToken, "", "")); w.Code != http.StatusOK {
		t.Errorf("stop 状态码 = %d，期望 200: %s", w.Code, w.Body.String())
	}
	if len(f.stopped) != 1 || f.stopped[0] != 1 {
		t.Errorf("Stop 调用记录 = %v，期望 [1]", f.stopped)
	}

	f.stopErr = errMachineTest
	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/stop?slot=1", machineTestToken, "", "")); w.Code != http.StatusInternalServerError {
		t.Errorf("Stop 内部失败状态码 = %d，期望 500", w.Code)
	}
}

func TestMachineStart(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/start", machineTestToken, "", "")); w.Code != http.StatusBadRequest {
		t.Errorf("缺 host 状态码 = %d，期望 400", w.Code)
	}
	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/start?slot=1", machineTestToken, "", "")); w.Code != http.StatusBadRequest {
		t.Errorf("只给 slot 状态码 = %d，期望 400", w.Code)
	}
	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/start?host=ghost", machineTestToken, "", "")); w.Code != http.StatusNotFound {
		t.Errorf("未知节点状态码 = %d，期望 404", w.Code)
	}

	w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/start?host=node-1", machineTestToken, "", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("start 状态码 = %d，期望 200: %s", w.Code, w.Body.String())
	}
	if len(f.started) != 1 || f.started[0].HostName != "node-1" {
		t.Errorf("Start 调用记录 = %+v，期望 node-1", f.started)
	}
	var resp struct {
		OK   bool `json:"ok"`
		Slot int  `json:"slot"`
		Port int  `json:"port"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("start 响应解析失败: %v", err)
	}
	if !resp.OK || resp.Slot != 5 || resp.Port != 1200 {
		t.Errorf("start 响应 = %+v，期望 ok/slot=5/port=1200", resp)
	}

	f.startErr = errMachineTest
	if w := serveMachine(h, machineRequest(http.MethodPost, "/api/machine/start?host=node-1", machineTestToken, "", "")); w.Code != http.StatusBadRequest {
		t.Errorf("Start 业务失败状态码 = %d，期望 400", w.Code)
	}
}

func TestMachineBodyLimit(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	body := strings.Repeat("x", machineMaxBodyBytes+1)
	w := serveMachine(h, machineRequest(http.MethodPost,
		"/api/machine/provision?count=1", machineTestToken, "", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("超长请求体状态码 = %d，期望 400", w.Code)
	}
	if len(f.provisioned) != 0 {
		t.Error("请求体超限时不应进入业务逻辑")
	}
}

func TestMachineAuditLogHasNoToken(t *testing.T) {
	f := newFakeMachine()
	h := machineHandler(passthrough(), f, machineTestToken)

	var buf bytes.Buffer
	oldOut := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	})

	setPublicIPOverride("203.0.113.10")
	t.Cleanup(func() { setPublicIPOverride("") })

	serveMachine(h, machineRequest(http.MethodGet, "/api/machine/status", machineTestToken, "", ""))
	serveMachine(h, machineRequest(http.MethodPost, "/api/machine/swap?slot=99", machineTestToken, "", ""))

	out := buf.String()
	for _, want := range []string{"机器接口", "动作=status", "结果=200", "动作=swap", "结果=404"} {
		if !strings.Contains(out, want) {
			t.Errorf("审计日志缺少 %q: %s", want, out)
		}
	}
	if strings.Contains(out, machineTestToken) {
		t.Errorf("审计日志泄露了 token: %s", out)
	}
	if strings.Contains(out, "Authorization") {
		t.Errorf("审计日志不应记录请求头: %s", out)
	}
}

var errMachineTest = &machineTestError{}

type machineTestError struct{}

func (e *machineTestError) Error() string { return "测试错误" }
