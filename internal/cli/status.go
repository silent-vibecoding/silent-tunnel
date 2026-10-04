package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"silenttunnel/internal/config"
)

// liveStatus is the shared on-disk status shape written by both daemon roles.
type liveStatus struct {
	Role         string `json:"role"`
	StartedAt    string `json:"started_at"`
	Sessions     int64  `json:"sessions"`
	StreamsOpen  int64  `json:"streams_open"`
	TotalStreams uint64 `json:"total_streams"`
	BytesIn      uint64 `json:"bytes_in"`
	BytesOut     uint64 `json:"bytes_out"`
	Reconnects   uint64 `json:"reconnects"`
	LastPeer     string `json:"last_peer"`
	UpdatedAt    string `json:"updated_at"`
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := int64(d) / (24 * int64(time.Hour))
	h := int64(d)/(int64(time.Hour)) % 24
	m := int64(d)/(int64(time.Minute)) % 60
	s := int64(d)/(int64(time.Second)) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh%dm", days, h, m)
	case h > 0:
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	default:
		return fmt.Sprintf("%dm%ds", m, s)
	}
}

// cmdStatus pretty-prints the daemon's live status file.
func cmdStatus() int {
	path := config.StatusPath()
	b, err := os.ReadFile(path)
	if err != nil {
		errf("فایل وضعیت پیدا نشد (%s) — دیمن احتمالاً اجرا نیست", path)
		return 1
	}
	var st liveStatus
	if err := json.Unmarshal(b, &st); err != nil {
		errf("فایل وضعیت خراب است: %v", err)
		return 1
	}
	fresh := false
	if fi, err := os.Stat(path); err == nil {
		fresh = time.Since(fi.ModTime()) < 15*time.Second
	}

	role := "هاب (ایران)"
	if st.Role == "node" {
		role = "نود (خارج)"
	}
	fmt.Println()
	fmt.Printf("  %s  Silent Tunnel — %s\n", info("●"), role)
	if !fresh {
		fmt.Printf("  %s\n", warn("دیمن در حال اجرا به نظر نمی‌رسد (وضعیت قدیمی است)"))
	}
	if started, err := time.Parse(time.RFC3339, st.StartedAt); err == nil {
		fmt.Printf("  آپ‌تایم:      %s\n", humanDuration(time.Since(started)))
	}
	fmt.Printf("  اتصالات تونل: %d\n", st.Sessions)
	fmt.Printf("  اتصال‌های باز: %d  (مجموع: %d)\n", st.StreamsOpen, st.TotalStreams)
	fmt.Printf("  دانلود/آپلود: %s / %s\n", humanBytes(st.BytesIn), humanBytes(st.BytesOut))
	fmt.Printf("  ری‌کانکت‌ها:   %d\n", st.Reconnects)
	if st.LastPeer != "" {
		fmt.Printf("  آخرین همتا:   %s\n", st.LastPeer)
	}
	fmt.Println()
	return 0
}
