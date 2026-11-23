package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newReadonlyTestManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(4, t.TempDir())
	m.tunnels[1] = &Tunnel{
		Slot: 1, Port: 1080, Status: "up", ExitIP: "203.0.113.9",
		Node: Node{HostName: "node-1", Country: "Japan", CountryCode: "JP"},
		Cred: SocksCred{User: "secret-user", Pass: "secret-pass"},
	}
	m.tunnels[2] = &Tunnel{
		Slot: 2, Port: 1081, Status: "starting",
		Node: Node{HostName: "node-2", Country: "Korea", CountryCode: "KR"},
		Cred: SocksCred{User: "u2", Pass: "p2"},
	}
	m.tunnels[2].markSuspect()
	return m
}

func TestReadonlyTunnelsShape(t *testing.T) {
	m := newReadonlyTestManager(t)
	got := readonlyTunnels(m)

	if len(got) != 2 {
		t.Fatalf("出口数量 = %d，期望 2", len(got))
	}
	first := got[0]
	if first.Slot != 1 || first.Port != 1080 || first.Status != "up" ||
		first.ExitIP != "203.0.113.9" || first.CountryCode != "JP" || first.Suspect {
		t.Errorf("第一条出口字段不符: %+v", first)
	}
	if !strings.Contains(first.Country, "日本") {
		t.Errorf("country 应为中文标签，实际 %q", first.Country)
	}
	if !got[1].Suspect {
		t.Errorf("被标记的出口应返回 suspect=true")
	}

	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	for _, forbidden := range []string{
		"socks_user", "socks_pass", "secret-user", "secret-pass",
		"password", "config", "cred", "ovpn",
	} {
		if strings.Contains(string(blob), forbidden) {
			t.Errorf("只读载荷泄露了敏感字段 %q: %s", forbidden, blob)
		}
	}
}

func TestReadonlyHealth(t *testing.T) {
	m := newReadonlyTestManager(t)
	got := readonlyHealth(m)
	if got.Count != 2 || got.Up != 1 || got.Suspect != 1 {
		t.Errorf("health = %+v，期望 count=2 up=1 suspect=1", got)
	}
	if got.OK {
		t.Errorf("存在非 up 与 suspect 出口时 ok 必须为 false")
	}

	empty := NewManager(4, t.TempDir())
	if h := readonlyHealth(empty); h.OK || h.Count != 0 {
		t.Errorf("没有出口时 ok 必须为 false，实际 %+v", h)
	}
}

func TestTokenAndLoopbackHelpers(t *testing.T) {
	if !tokenMatches("s3cret", "s3cret") {
		t.Error("相同 token 应匹配")
	}
	if tokenMatches("s3cret", "s3cre") || tokenMatches("", "s3cret") {
		t.Error("不同 token 不应匹配")
	}

	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:5000", true},
		{"[::1]:5000", true},
		{"127.0.0.2:5000", true},
		{"192.0.2.10:5000", false},
		{"[2001:db8::1]:5000", false},
		{"garbage", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/readonly/health", nil)
		r.RemoteAddr = c.addr
		if got := isLoopbackRequest(r); got != c.want {
			t.Errorf("isLoopbackRequest(%q) = %v，期望 %v", c.addr, got, c.want)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc")
	if got := bearerToken(r); got != "abc" {
		t.Errorf("bearerToken = %q，期望 abc", got)
	}
	r.Header.Set("Authorization", "Basic abc")
	if got := bearerToken(r); got != "" {
		t.Errorf("非 Bearer 头应返回空，实际 %q", got)
	}
}

func TestReadonlyHandler(t *testing.T) {
	m := newReadonlyTestManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("next"))
	})
	h := readonlyHandler(next, m, "s3cret")

	get := func(target, token, remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := get("/api/readonly/tunnels", "s3cret", "127.0.0.1:5000"); w.Code != http.StatusOK {
		t.Errorf("合法请求状态码 = %d，期望 200", w.Code)
	} else if !strings.Contains(w.Body.String(), `"slot":1`) {
		t.Errorf("响应缺少出口数据: %s", w.Body.String())
	}

	if w := get("/api/readonly/health", "s3cret", "[::1]:5000"); w.Code != http.StatusOK {
		t.Errorf("IPv6 loopback 状态码 = %d，期望 200", w.Code)
	}

	if w := get("/api/readonly/health", "wrong", "127.0.0.1:5000"); w.Code != http.StatusUnauthorized {
		t.Errorf("错误 token 状态码 = %d，期望 401", w.Code)
	}
	if w := get("/api/readonly/health", "s3cret", "192.0.2.10:5000"); w.Code != http.StatusForbidden {
		t.Errorf("非本机来源状态码 = %d，期望 403", w.Code)
	}
	if w := get("/api/readonly/unknown", "s3cret", "127.0.0.1:5000"); w.Code != http.StatusNotFound {
		t.Errorf("未知端点状态码 = %d，期望 404", w.Code)
	}

	post := httptest.NewRequest(http.MethodPost, "/api/readonly/tunnels", nil)
	post.RemoteAddr = "127.0.0.1:5000"
	post.Header.Set("Authorization", "Bearer s3cret")
	pw := httptest.NewRecorder()
	h.ServeHTTP(pw, post)
	if pw.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST 状态码 = %d，期望 405", pw.Code)
	}

	if w := get("/api/tunnels", "s3cret", "127.0.0.1:5000"); w.Body.String() != "next" {
		t.Errorf("非只读路径应原样交给内层 handler，实际 %q", w.Body.String())
	}
}
