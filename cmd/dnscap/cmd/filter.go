package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var domain string

var filterCmd = &cobra.Command{
	Use:   "filter [domain]",
	Short: "Filter DNS queries by domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain = args[0]
		fmt.Printf("Filtering DNS queries for domain %s in file: %s\n", domain, filePath)
		// Add your pcap handling and filtering code here
	},
}

func init() {
	rootCmd.AddCommand(filterCmd)
}
