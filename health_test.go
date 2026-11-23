package main

import (
	"errors"
	"testing"
)

func TestParseIPGuardMode(t *testing.T) {
	cases := []struct {
		raw  string
		want ipGuardMode
		ok   bool
	}{
		{"", ipGuardMark, true},         // 未设置时默认 mark
		{"mark", ipGuardMark, true},     // 显式 mark
		{"  MARK  ", ipGuardMark, true}, // 大小写与空白都容忍
		{"reconnect", ipGuardReconnect, true},
		{"Reconnect", ipGuardReconnect, true},
		{"bogus", ipGuardMark, false}, // 无法识别时回落到 mark，并提示配置有误
		{"1", ipGuardMark, false},
	}
	for _, c := range cases {
		got, ok := parseIPGuardMode(c.raw)
		if got != c.want || ok != c.ok {
			t.Errorf("parseIPGuardMode(%q) = (%q, %v)，期望 (%q, %v)", c.raw, got, ok, c.want, c.ok)
		}
	}
}

func TestJudgeExitIP(t *testing.T) {
	cases := []struct {
		name     string
		expected string
		observed string
		err      error
		want     healthVerdict
	}{
		{"IP 一致", "203.0.113.9", "203.0.113.9", nil, healthOK},
		{"IP 变化", "203.0.113.9", "198.51.100.7", nil, healthIPChanged},
		{"探测报错", "203.0.113.9", "", errors.New("timeout"), healthProbeFailed},
		{"返回空串", "203.0.113.9", "", nil, healthProbeFailed},
		{"期望为空时任何 IP 都算变化", "", "198.51.100.7", nil, healthIPChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := judgeExitIP(c.expected, c.observed, c.err); got != c.want {
				t.Errorf("judgeExitIP(%q, %q, %v) = %v，期望 %v",
					c.expected, c.observed, c.err, got, c.want)
			}
		})
	}
}
