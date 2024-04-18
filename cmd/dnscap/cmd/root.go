package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var filePath string

var rootCmd = &cobra.Command{
	Use:   "dnscap",
	Short: "dnscap is a CLI for capturing and analyzing DNS packets",
	Long: `dnscap is a CLI tool developed in Go that uses pcap files
to capture and analyze DNS traffic.`,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println("Please specify a subcommand: list or filter")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&filePath, "file", "f", "", "specify the pcap file to analyze")
	rootCmd.MarkPersistentFlagRequired("file")
}
