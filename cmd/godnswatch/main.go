package main

import (
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/miekg/dns"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// RecordMap type for DNS records
type RecordMap map[string]string

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

var (
	normalStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFF")) // Default style
	malwareStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("red"))  // Malware style
)

type model struct {
	table        table.Model
	windowWidth  int
	windowHeight int
	dnsQueryHits sync.Map
	flaggedDNS   map[string]bool
}

func (m *model) Init() tea.Cmd {
	return tea.Tick(time.Millisecond*300, func(t time.Time) tea.Msg {
		return dnsQueryUpdateMsg{}
	})
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			//return m, tea.Batch(
			//	tea.Printf("Let's go to %s!", m.table.SelectedRow()[1]),
			//)
		}
	case tea.WindowSizeMsg:
		m.windowWidth, m.windowWidth = msg.Width, msg.Height
	case dnsQueryUpdateMsg:
		cmds = append(cmds, tea.Tick(time.Millisecond*5, func(t time.Time) tea.Msg {
			return dnsQueryUpdateMsg{}
		}))

	}
	//fmt.Println(m.dnsQueryHits)
	var rows []table.Row

	m.dnsQueryHits.Range(func(key, value any) bool {
		flagged := ""
		if keyStr, ok := key.(string); ok {
			if _, found := m.flaggedDNS[keyStr]; found {
				flagged = "\x1b[31mMALWARE\x1b[0m"
			}
			if valueInt, ok := value.(int); ok {
				rows = append(rows, table.Row{keyStr, fmt.Sprintf("%d", valueInt), flagged})
			}
		}
		return true // Continue iterating
	})

	sort.Slice(rows, func(i, j int) bool {
		return rows[i][0] > rows[j][0]
	})

	sort.Slice(rows, func(i, j int) bool {
		// Convert the hits back to integers for comparison
		hitsI, _ := strconv.Atoi(rows[i][1])
		hitsJ, _ := strconv.Atoi(rows[j][1])
		return hitsI > hitsJ
	})

	m.table.SetRows(rows)

	x, cmd := m.table.Update(msg)
	m.table = x
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m *model) View() string {
	return baseStyle.Render(m.table.View()) + "\n"
}

type dnsQueryUpdateMsg struct {
}

// LoadRecords loads the DNS records from a JSON file
func LoadRecords(filename string) (RecordMap, error) {
	var records RecordMap
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(content, &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// handleDNSRequest handles incoming DNS queries
func handleDNSRequest(records RecordMap, upstream string, m *model) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(r)
		domain := msg.Question[0].Name

		// Check if the domain is in our records
		if ip, found := records[domain]; found {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(ip),
			})
			if _, found := m.flaggedDNS[domain]; !found {
				m.flaggedDNS[domain] = true
			}
		} else {
			// Query the upstream server
			c := new(dns.Client)
			in, _, err := c.Exchange(r, upstream)
			if err == nil {
				msg.Answer = in.Answer
			}
		}

		//m.dnsQueryHits[domain]++
		value, ok := m.dnsQueryHits.Load(domain)
		if !ok {
			m.dnsQueryHits.Store(domain, 1)
		} else {
			count := value.(int)
			m.dnsQueryHits.Store(domain, count+1)
		}

		err := w.WriteMsg(&msg)
		if err != nil {
			return
		}
	}
}

var err error

func main() {
	// Load DNS records from a file
	records, err := LoadRecords("blacklist.json")
	if err != nil {
		fmt.Println("Failed to load DNS records:", err)
		os.Exit(1)
	}

	columns := []table.Column{
		{Title: "DNS Query", Width: 60},
		{Title: "Hits", Width: 5},
		{Title: "Flag", Width: 15},
	}

	rows := []table.Row{}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(25),
		table.WithWidth(80),
	)

	m := &model{table: t, flaggedDNS: make(map[string]bool)}

	go func() {
		// Specify your upstream DNS server
		upstream := "8.8.8.8:53" // Google's DNS for example

		// Setup DNS handler
		dns.HandleFunc(".", handleDNSRequest(records, upstream, m))

		// Create and start server
		server := &dns.Server{Addr: "127.0.0.1:53", Net: "udp"}
		fmt.Println("Starting server on 127.0.0.1:53")
		err = server.ListenAndServe()
		defer server.Shutdown()
		if err != nil {
			fmt.Println("Failed to start server:", err)
			os.Exit(1)
		}
	}()

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program", err)
		os.Exit(1)
	}
}
