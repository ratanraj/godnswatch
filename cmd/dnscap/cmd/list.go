package cmd

import (
	"bufio"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"io"
	"log"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

var (
	// styles
	dangerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
	baseStyle     = lipgloss.NewStyle().Padding(0, 1)
	headerStyle   = baseStyle.Copy().Foreground(lipgloss.Color("252")).Bold(true)
	selectedStyle = baseStyle.Copy().Foreground(lipgloss.Color("#01BE85")).Background(lipgloss.Color("#00432F"))

	blacklist map[string]bool // Making it map instead of list because it's slower to search

)

var err error

type DNSPacket struct {
	Source      string
	Destination string
	Domains     []string
}

func loadBlacklist(name string) map[string]bool {
	homePath := os.Getenv("HOME")
	blacklistFilePath := path.Join(homePath, name)
	blacklistFile, err := os.Open(blacklistFilePath)
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(blacklistFile)

	// Create a map to store the domains
	domainMap := make(map[string]bool)

	// Read the file line by line
	for scanner.Scan() {
		domain := scanner.Text()
		// Add the domain to the map with the value true
		domainMap[domain] = true
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	return domainMap
}

func loadS3File(filePath string) (*os.File, error) {
	// Initialize a session in us-east-1 that the SDK will use to load credentials
	// from the shared credentials file ~/.aws/credentials.
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1")},
	)

	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	// Create a new S3 service client.
	svc := s3.New(sess)

	strings.trim

	// Specify the bucket and object to download.
	bucket := "ratanraj.com"
	key := "pcaps/dns_malware_all.pcapng"

	// Create the file
	file, err := os.Create("/tmp/dns_malware_all.pcapng")
	if err != nil {
		//log.Fatalf("Failed to create file: %v", err)
		return nil, err
	}
	defer file.Close()

	// Download the file from S3.
	downloader := s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	result, err := svc.GetObject(&downloader)
	if err != nil {
		//log.Fatalf("Failed to download file: %v", err)
		return nil, err
	}

	// Write the contents of S3 Object to the file
	if _, err := io.Copy(file, result.Body); err != nil {
		//log.Fatalf("Failed to copy file content: %v", err)
		return nil, err
	}

	// Close the S3 object body, important to avoid leaks
	result.Body.Close()
	return file, nil
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all DNS queries in the pcap file",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Listing DNS queries from:", filePath)
		// Add your pcap handling and listing code here

		blacklist := loadBlacklist("blacklist.txt")

		var pcapHandle *pcap.Handle
		if strings.HasPrefix(strings.ToLower(filePath), "s3://") {
			fp, err := loadS3File(filePath)
			if err != nil {
				panic(err)
			}
			pcapHandle, err = pcap.OpenOfflineFile(fp)
			if err != nil {
				panic(err)
			}
		} else {
			pcapHandle, err = pcap.OpenOffline(filePath)
			if err != nil {
				panic(err)
			}
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
			BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))).
			StyleFunc(func(row, col int) lipgloss.Style {
				switch {
				case row == 0:
					return headerStyle
				case row%2 == 0:
					return baseStyle.Copy().Foreground(lipgloss.Color("245"))
				default:
					return baseStyle.Copy().Foreground(lipgloss.Color("252"))
				}
			}).
			Headers("DNS Query", "HITS", "FLAG")

		var rows [][]string

		for k, v := range domainCounter {
			s := ""

			if _, ok := blacklist[k]; ok {
				s = dangerStyle.Render("MALWARE") // color the row RED if it is marked as danger
			}

			rows = append(rows, []string{k, fmt.Sprintf("%d", v), s})

			// t.Row(k, fmt.Sprintf("%d", v), s)
		}

		sort.Slice(rows, func(i, j int) bool {
			//if rows[i][2] != "" {
			//	return true
			//}
			a, err := strconv.ParseInt(rows[i][1], 10, 64)
			if err != nil {
				return false
			}
			b, err := strconv.ParseInt(rows[j][1], 10, 64)
			if err != nil {
				return false
			}

			return a > b
		})

		t.Rows(rows...)

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
