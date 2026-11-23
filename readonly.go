package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

// readonlyTokenEnv 设置后启用固定路径的只读出口 API。
// 不设置时整个只读通道完全不存在，行为与旧版本一致。
const readonlyTokenEnv = "FANOUT_READONLY_TOKEN"

// readonlyTunnel 是只读接口里的一条出口。
//
// 刻意不复用 Tunnel / Exit：那两个结构带 SOCKS5 凭据和 .ovpn 配置，
// 不能出现在免登录通道上。这里只暴露外部管理器做账号绑定所需的字段。
type readonlyTunnel struct {
	Slot        int    `json:"slot"`
	Port        int    `json:"port"`
	Status      string `json:"status"`
	ExitIP      string `json:"exit_ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Suspect     bool   `json:"suspect"`
}

type readonlyTunnelsResponse []readonlyTunnel

// readonlyHealthResponse 是给外部管理器做探活的聚合结果。
// ok 为 true 表示：至少有一条出口、全部处于 up、且没有 suspect。
type readonlyHealthResponse struct {
	OK      bool `json:"ok"`
	Count   int  `json:"count"`
	Up      int  `json:"up"`
	Suspect int  `json:"suspect"`
}

// readonlyTunnels 返回与 /api/tunnels 同形的数组，但只保留只读字段。
func readonlyTunnels(m *Manager) readonlyTunnelsResponse {
	tunnels := m.Tunnels()
	out := make(readonlyTunnelsResponse, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, readonlyTunnel{
			Slot:        t.Slot,
			Port:        t.Port,
			Status:      t.Status,
			ExitIP:      t.ExitIP,
			Country:     nodeLabel(t.Node),
			CountryCode: t.Node.CountryCode,
			Suspect:     t.isSuspect(),
		})
	}
	return out
}

func readonlyHealth(m *Manager) readonlyHealthResponse {
	resp := readonlyHealthResponse{OK: true}
	for _, t := range readonlyTunnels(m) {
		resp.Count++
		if t.Status == "up" {
			resp.Up++
		} else {
			resp.OK = false
		}
		if t.Suspect {
			resp.Suspect++
			resp.OK = false
		}
	}
	if resp.Count == 0 {
		resp.OK = false
	}
	return resp
}

// tokenMatches 用恒定时间比较 token，避免按响应时间逐字符猜。
// 先各自哈希，长度不同也不会提前返回。want 为空表示未启用，永不放行。
func tokenMatches(got, want string) bool {
	if want == "" {
		return false
	}
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

// isLoopbackRequest 判断请求是否来自本机。只认 RemoteAddr，不采信
// X-Forwarded-For 之类可伪造的头。
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// bearerToken 取 Authorization: Bearer <token> 里的 token。
func bearerToken(r *http.Request) string {
	const prefix = "bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// readonlyHandler 在随机 basepath 与 12h 会话之外，提供一个固定路径的
// 只读出口通道，供宿主上的外部出口管理器调用。
//
// 仍然挂在原管理端口上，不新增监听；只有 token 非空时才会包上这一层，
// 且只接受 loopback 来源、只允许 GET。
func readonlyHandler(next http.Handler, m *Manager, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/readonly/") {
			next.ServeHTTP(w, r)
			return
		}
		if !isLoopbackRequest(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "只允许本机访问"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只允许 GET"})
			return
		}
		if !tokenMatches(bearerToken(r), token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="fanout-readonly"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token 无效"})
			return
		}

		switch r.URL.Path {
		case "/api/readonly/tunnels":
			writeJSON(w, http.StatusOK, readonlyTunnels(m))
		case "/api/readonly/health":
			writeJSON(w, http.StatusOK, readonlyHealth(m))
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知的只读端点"})
		}
	})
}
