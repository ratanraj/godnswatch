package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"time"
)

var domains = []string{
	"fastclick.net",
	"ab.chatgpt.com",
	"tcr9i.chat.openai.com",
	"js.intercomcdn.com",
	"api-iam.intercom.io",
	"practicalmalwareanalysis.com",
	"widget.intercom.io",
	"browser-intake-datadoghq.com",
	"chat.openai.com",
	"files.oaiusercontent.com",
	"practicalmalwareanalysis.com",
	"cdn.oaistatic.com",
	"lh3.googleusercontent.com",
	"www.google.com",
	"ssl.gstatic.com",
	"practicalmalwareanalysis.com",
	"clients6.google.com",
	"play.google.com",
	"mail.google.com",
	"drive-thirdparty.googleusercontent.com",
	"www.google.com",
	"practicalmalwareanalysis.com",
	"www.gstatic.com",
	"fonts.gstatic.com",
	"encrypted-tbn0.gstatic.com",
	"accounts.google.com",
	"play.google.com",
	"ssl.gstatic.com",
	"practicalmalwareanalysis.com",
	"heias.com",
}

// queryDNS performs a DNS query for the specified domain name at a specific DNS server.
func queryDNS(domainName string) {
	// Create a new DNS message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domainName), dns.TypeA) // SetQuestion for 'A' record, append dot to domain name to ensure FQDN
	m.RecursionDesired = true                      // Set recursion desired to true

	// Address of the DNS server
	const dnsServer = "127.0.0.1:8853"

	// Create a new DNS client
	c := new(dns.Client)

	// Send the DNS query
	r, _, err := c.Exchange(m, dnsServer)
	if err != nil {
		log.Println("DNS query failed: %v", err)
		return
	}

	// Check if we got any answers
	if len(r.Answer) == 0 {
		fmt.Println("No records found.")
		return
	}

	// Print all the answers
	for _, ans := range r.Answer {
		fmt.Println(ans)
	}
}

func main() {
	rand.NewSource(time.Now().UnixNano())

	for {
		randomIndex := rand.Intn(len(domains))
		time.Sleep(time.Second)
		queryDNS(domains[randomIndex])
	}
}
