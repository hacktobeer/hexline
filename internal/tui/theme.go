package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// EnableColor forces the 256-colour profile for board output. lipgloss detects
// the profile from the process stdout, which is the server's log file rather
// than the caller's terminal, so without this every screen is monochrome.
func EnableColor() {
	lipgloss.SetColorProfile(termenv.ANSI256)
}

// Palette: restrained 16-colour-safe accents that survive most terminals.
var (
	colAccent = lipgloss.Color("39")
	colDim    = lipgloss.Color("244")
	colWarn   = lipgloss.Color("203")
	colOK     = lipgloss.Color("42")
	colHeader = lipgloss.Color("111")
)

var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(colHeader)
	styleAccent   = lipgloss.NewStyle().Foreground(colAccent)
	styleDim      = lipgloss.NewStyle().Foreground(colDim)
	styleWarn     = lipgloss.NewStyle().Foreground(colWarn)
	styleOK       = lipgloss.NewStyle().Foreground(colOK)
	styleSelected = lipgloss.NewStyle().Reverse(true)
	styleBold     = lipgloss.NewStyle().Bold(true)
)
