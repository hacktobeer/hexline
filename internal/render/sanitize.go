// Package render turns stored plain text into terminal-safe output.
//
// Trust boundary: everything a user typed is untrusted. Sanitize runs on
// input before storage and again before rendering; escape sequences are
// emitted only by this package.
package render

import (
	"strings"
	"unicode"
	"unicode/utf8"
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
		case r == utf8.RuneError:
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

// Clip hard-truncates s to n runes and appends an ellipsis when cut.
// It is for display only: never store clipped text.
func Clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// PadRight pads s with spaces to width (rune count). Longer strings are clipped.
func PadRight(s string, width int) string {
	s = Clip(s, width)
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// PadLeft left-pads s to width.
func PadLeft(s string, width int) string {
	s = Clip(s, width)
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return strings.Repeat(" ", width-n) + s
}

// Width returns the display width in runes, ignoring SGR escape sequences
// that this package emits.
func Width(s string) int {
	w := 0
	inEsc := false
	for _, r := range s {
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		if r == 0x1b {
			inEsc = true
			continue
		}
		w++
	}
	return w
}
