// Package render turns stored plain text into terminal-safe output.
//
// Trust boundary: everything a user typed is untrusted. Sanitize runs on
// input before storage and again before rendering; escape sequences are
// emitted only by this package.
package render

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"
)

// Sanitize removes control characters that could drive a terminal, along with
// invisible formatting characters used for spoofing. Newlines, tabs and
// printable Unicode survive. Invalid UTF-8 is replaced with U+FFFD.
func Sanitize(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == 0x7f: // DEL
			continue
		case r < 0x20: // C0 controls, including ESC
			continue
		case r >= 0x80 && r <= 0x9f: // C1 controls (8-bit CSI et al.)
			continue
		case unicode.Is(unicode.Cf, r): // zero-width, bidi overrides, BOM
			continue
		case r == 0xFFFD:
			b.WriteRune(0xFFFD)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SanitizeLine sanitizes a single-line field and flattens newlines/tabs.
func SanitizeLine(s string) string {
	s = Sanitize(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}

// Clip hard-truncates s to n display columns and appends an ellipsis when cut.
// Display columns, not runes: a CJK glyph or emoji takes two columns, so rune
// counting would misalign every table it is used in.
func Clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if Width(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := Width(string(r))
		if used+w > n-1 {
			break
		}
		b.WriteRune(r)
		used += w
	}
	return b.String() + "…"
}

// PadRight pads s with spaces to width display columns. Longer strings are clipped.
func PadRight(s string, width int) string {
	s = Clip(s, width)
	n := Width(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// PadLeft left-pads s to width display columns.
func PadLeft(s string, width int) string {
	s = Clip(s, width)
	n := Width(s)
	if n >= width {
		return s
	}
	return strings.Repeat(" ", width-n) + s
}

// Width returns the display width in columns, ignoring SGR escapes.
func Width(s string) int { return ansi.StringWidth(s) }
