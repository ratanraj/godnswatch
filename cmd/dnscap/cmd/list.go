package cmd

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"log"
)

type DNSPacket struct {
	Source      string
	Destination string
	Domains     []string
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all DNS queries in the pcap file",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Listing DNS queries from:", filePath)
		// Add your pcap handling and listing code here

		pcapHandle, err := pcap.OpenOffline(filePath)
		if err != nil {
			panic(err)
		}

		var filter string = "dst port 53"
		err = pcapHandle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}

		packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

		domainCounter := map[string]int{}

		for packet := range packetSource.Packets() {
			dnsPacket, _ := extractDNSDetails(packet)
			for _, domain := range dnsPacket.Domains {
				domainCounter[domain]++
			}
			// fmt.Printf("%s :[ %s ]\n", dnsPacket.Source, strings.Join(dnsPacket.Domains, ", "))
		}
		t := table.New().
			Border(lipgloss.NormalBorder()).
			BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("99"))).
			StyleFunc(func(row, col int) lipgloss.Style {
				switch {
				case row == 0:
					return HeaderStyle
				case row%2 == 0:
					return EvenRowStyle
				default:
					return OddRowStyle
				}
			}).
			Headers("No", "NAME", "FLAG")

		var rows [][]string

		for k, v := range domainCounter {
			s := ""
			if {
				s = "DANGER" // color the row RED if it is marked as danger
			}
			rows = append(rows, []string{k, fmt.Sprintf("%d", v)})

			// t.Row(k, fmt.Sprintf("%d", v), s)
		}

		fmt.Println(t)
	},
}

func extractDNSDetails(packet gopacket.Packet) (*DNSPacket, error) {
	// Check for IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, fmt.Errorf("not an IPv4 packet")
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Check for UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, fmt.Errorf("not a UDP packet") // Not a UDP packet
	}
	// udp, _ := udpLayer.(*layers.UDP)

	// Check for DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, fmt.Errorf("not a DNS packet") // Not a DNS packet
	}
	dns, _ := dnsLayer.(*layers.DNS)

	// Print IP addresses and UDP ports

	var domains []string
	// Iterate through DNS Questions (DNS requests)
	for _, dnsQuestion := range dns.Questions {
		domains = append(domains, string(dnsQuestion.Name))
	}

	return &DNSPacket{
		Source:      ip.SrcIP.String(),
		Destination: ip.DstIP.String(),
		Domains:     domains,
	}, nil
}

func init() {
	rootCmd.AddCommand(listCmd)
}
