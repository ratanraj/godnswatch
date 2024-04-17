package cmd

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"os"

	"github.com/spf13/cobra"
)

var (
	HeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFACD")).Background(lipgloss.Color("#191970")).Padding(0, 1)
	EvenRowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#333333")).Padding(0, 1)
	OddRowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA")).Background(lipgloss.Color("#111111")).Padding(0, 1)
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
