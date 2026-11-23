package main

import (
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	healthInterval = 10 * time.Second
	healthFailures = 2 // 连续失败几次才判定掉线，避免网络抖动误杀
	healthTimeout  = 6 * time.Second

	// ipGuardModeEnv 控制探测到出口 IP 变化（或探测失败）后的动作。
	ipGuardModeEnv = "FANOUT_IP_GUARD_MODE"
)

// ipGuardMode 决定健康探测发现问题后要不要动隧道。
//
// mark（默认）：只把出口标记为 suspect，绝不杀进程、拆 netns、换节点。
// 外部出口管理器要靠出口 IP 给账号做粘性绑定，fanout 不能背着它换 IP。
// reconnect：旧行为，连续 healthFailures 次探测不上就换节点重连。
type ipGuardMode string

const (
	ipGuardMark      ipGuardMode = "mark"
	ipGuardReconnect ipGuardMode = "reconnect"
)

// parseIPGuardMode 解析 FANOUT_IP_GUARD_MODE。空值按默认的 mark 处理；
// 无法识别的取值也回落到 mark，并用 ok=false 让调用方提示配置有误。
// 纯函数，便于单测。
func parseIPGuardMode(raw string) (mode ipGuardMode, ok bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(ipGuardMark):
		return ipGuardMark, true
	case string(ipGuardReconnect):
		return ipGuardReconnect, true
	default:
		return ipGuardMark, false
	}
}

// healthVerdict 是一次出口探测的结论。
type healthVerdict int

const (
	healthOK          healthVerdict = iota // 出口 IP 与建隧道时一致
	healthProbeFailed                      // 探测本身失败，或返回空
	healthIPChanged                        // 能出网，但出口 IP 变了
)

// judgeExitIP 只做判定，不碰进程，方便单测。
//
// 只看"能不能出网"不够：netns 通过 veth 走母机 NAT，openvpn 死掉后
// 照样能出网，只是出口变回了母机 IP。所以必须比对期望的出口 IP。
func judgeExitIP(expected, observed string, probeErr error) healthVerdict {
	if probeErr != nil || observed == "" {
		return healthProbeFailed
	}
	if observed != expected {
		return healthIPChanged
	}
	return healthOK
}

// WatchHealth 周期检查每条隧道是否还走在 VPN 上。
//
// 默认 mark 模式只记录/标记，不自动换节点；只有显式设置
// FANOUT_IP_GUARD_MODE=reconnect 才恢复旧的自动换节点行为。
func (m *Manager) WatchHealth() {
	mode, ok := parseIPGuardMode(os.Getenv(ipGuardModeEnv))
	if !ok {
		log.Printf("%s 取值无法识别，按默认 mark 处理（不自动换节点）", ipGuardModeEnv)
	}
	if mode == ipGuardMark {
		log.Printf("IP 守护为 mark 模式：出口 IP 变化只标记 suspect，不自动换节点")
	} else {
		log.Printf("IP 守护为 reconnect 模式：探测失败会自动换节点重连")
	}

	fails := map[int]int{}

	for range time.Tick(healthInterval) {
		for _, t := range m.Tunnels() {
			if t.Status != "up" {
				continue
			}

			got, err := probeTunnelExitIP(t)
			verdict := judgeExitIP(t.ExitIP, got, err)
			switch verdict {
			case healthOK:
				fails[t.Slot] = 0
				t.clearSuspect()
				continue
			case healthIPChanged:
				if mode == ipGuardMark {
					// 能出网了，之前的探测失败计数不再有意义
					fails[t.Slot] = 0
				}
				if t.markSuspect() {
					log.Printf("隧道 %d (%s) 出口 IP 已变化（期望 %s，实际 %s），已标记 suspect",
						t.Slot, t.Node.HostName, t.ExitIP, got)
				}
			case healthProbeFailed:
				// mark 模式下探测失败只记录次数，不换节点：
				// 失败本身不能证明出口 IP 变了，贸然重连反而会破坏粘性。
			}

			if mode == ipGuardMark {
				if verdict == healthProbeFailed {
					fails[t.Slot]++
					if fails[t.Slot] < healthFailures {
						log.Printf("隧道 %d (%s) 探测失败 %d 次（mark 模式不自动换节点）",
							t.Slot, t.Node.HostName, fails[t.Slot])
					}
				}
				continue
			}

			// reconnect 模式：保持旧行为，探测失败或 IP 变化都算掉线。
			fails[t.Slot]++
			if fails[t.Slot] < healthFailures {
				log.Printf("隧道 %d (%s) 探测失败 %d 次", t.Slot, t.Node.HostName, fails[t.Slot])
				continue
			}

			log.Printf("隧道 %d (%s) 已掉线，正在换节点重连", t.Slot, t.Node.HostName)
			fails[t.Slot] = 0
			t.clearSuspect()
			m.reconnect(t, t.Node.HostName)
		}
	}
}

// probeTunnelExitIP 通过隧道查一次出口 IP。探测超时沿用健康检查的短超时，
// 不阻塞下一轮 tick。
func probeTunnelExitIP(t *Tunnel) (string, error) {
	out, err := cmdOutput(exec.Command("ip", "netns", "exec", t.nsName(),
		"curl", "-s", "--max-time", strconv.Itoa(int(healthTimeout.Seconds())),
		"http://api.ipify.org"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// reconnect 就地把一条隧道换到别的节点上，保持槽位与端口不变，
// 这样已经分发出去的客户端配置仍然可用。
//
// oldHost 必须是本次重连前那条隧道真正绑着的节点名。调用方若已经
// 改过 t.Node（比如手动换节点），就要把改之前的名字传进来，
// 否则 rebind 找不到旧绑定，入站会掉成孤儿。
func (m *Manager) reconnect(t *Tunnel, oldHost string) {
	t.Status = "starting"
	t.Err = "正在换节点重连"
	t.ExitIP = ""

	// 动手之前先把"原来绑的是谁"落盘。
	//
	// 换节点是两步：连上新节点、再把入站改绑过来。两步之间崩溃或重启的话，
	// 存盘的隧道已经是新节点、入站却还指着旧节点，那个入站就成了孤儿。
	// 这条线索留在盘上，重启恢复时能照着把它接回来。
	t.setPrevHost(oldHost)
	if err := m.saveState(); err != nil {
		log.Printf("保存状态失败: %v", err)
	}

	if t.ovpn != nil && t.ovpn.Process != nil {
		_ = t.ovpn.Process.Kill()
		t.ovpn = nil
	}
	t.teardownNetns()

	go func() {
		// 通知延后到 rebind/resync 之后：那两步会把入站改绑到新节点，
		// 提前重建配置会因为入站还指着旧节点名而丢掉路由规则
		m.bringUpPersist(t, false, true)
		if t.Status != "up" {
			return
		}
		// 出站 tag 跟着节点名走，换了节点就要把原来指向它的入站重新绑过去，
		// 否则面板里的路由会指向一个已经不存在的出站。
		if t.Node.HostName != oldHost {
			if err := m.rebind(oldHost, t); err != nil {
				log.Printf("重连后同步 3x-ui 绑定失败: %v", err)
				return
			}
		} else if err := m.resync(t); err != nil {
			// 节点名没变也要重写一次出站：出口 IP 可能变了，
			// 而且上一轮换节点时留下的绑定需要重新指回来。
			log.Printf("重连后重写 3x-ui 出站失败: %v", err)
			return
		}
		// 入站已经跟过来了，标记可以清了
		t.setPrevHost("")
		if err := m.saveState(); err != nil {
			log.Printf("保存状态失败: %v", err)
		}
	}()
}
