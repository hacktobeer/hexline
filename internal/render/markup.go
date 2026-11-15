package render

import (
	"strings"
	"unicode/utf8"
)

// Options controls rendering.
type Options struct {
	// Width is the usable column count. Values below 20 are clamped to 20.
	Width int
	// ANSI enables SGR styling. When false, markers are stripped entirely.
	ANSI bool
	// QuotePrefix is prepended to quoted lines (default "> ").
	QuotePrefix string
}

const (
	sgrBold    = "\x1b[1m"
	sgrItalic  = "\x1b[3m"
	sgrDim     = "\x1b[2m"
	sgrReverse = "\x1b[7m"
	sgrReset   = "\x1b[0m"
)

type blockKind int

const (
	blockPara blockKind = iota
	blockQuote
	blockList
	blockCode
)

type block struct {
	kind  blockKind
	lines []string
}

// Render converts user text into terminal lines: markup is parsed, then the
// result is wrapped to opts.Width. The returned string ends with a newline.
func Render(text string, opts Options) string {
	if opts.Width < 20 {
		opts.Width = 80
	}
	if opts.QuotePrefix == "" {
		opts.QuotePrefix = "> "
	}
	// Defense in depth: stored text is sanitized again before display.
	text = Sanitize(text)
	var out []string
	for _, b := range parseBlocks(text) {
		out = append(out, renderBlock(b, opts)...)
	}
	// Collapse leading/trailing blank lines but keep internal spacing.
	start, end := 0, len(out)
	for start < end && strings.TrimSpace(stripSGR(out[start])) == "" {
		start++
	}
	for end > start && strings.TrimSpace(stripSGR(out[end-1])) == "" {
		end--
	}
	out = out[start:end]
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

func parseBlocks(text string) []block {
	var blocks []block
	var cur block
	flush := func() {
		if len(cur.lines) > 0 {
			blocks = append(blocks, cur)
			cur = block{}
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "> "), trimmed == ">":
			if cur.kind != blockQuote {
				flush()
				cur.kind = blockQuote
			}
			cur.lines = append(cur.lines, strings.TrimPrefix(strings.TrimPrefix(trimmed, ">"), " "))
		case isListLine(trimmed):
			if cur.kind != blockList {
				flush()
				cur.kind = blockList
			}
			cur.lines = append(cur.lines, strings.TrimPrefix(strings.TrimPrefix(trimmed, "-"), "*"))
		case strings.HasPrefix(line, "    "), strings.HasPrefix(line, "\t"):
			if cur.kind != blockCode {
				flush()
				cur.kind = blockCode
			}
			cur.lines = append(cur.lines, strings.TrimPrefix(strings.TrimPrefix(line, "    "), "\t"))
		default:
			if cur.kind != blockPara {
				flush()
				cur.kind = blockPara
			}
			cur.lines = append(cur.lines, line)
		}
	}
	flush()
	return blocks
}

func isListLine(s string) bool {
	return strings.HasPrefix(s, "- ") || strings.HasPrefix(s, "* ")
}

func renderBlock(b block, opts Options) []string {
	switch b.kind {
	case blockCode:
		var out []string
		for _, l := range b.lines {
			for _, w := range wrapLine(l, opts.Width-4) {
				out = append(out, "    "+w)
			}
		}
		return out
	case blockList:
		var out []string
		bullet := "•"
		if !opts.ANSI {
			bullet = "*"
		}
		for i, l := range b.lines {
			spans := parseInline(l, opts.ANSI)
			wrapped := wrapSpans(spans, opts.Width-2)
			for j, wl := range wrapped {
				prefix := strings.Repeat(" ", utf8.RuneCountInString(bullet)+1)
				if i >= 0 && j == 0 {
					prefix = bullet + " "
				}
				out = append(out, prefix+wl)
			}
		}
		return out
	case blockQuote:
		prefix := opts.QuotePrefix
		if !opts.ANSI {
			prefix = "> "
		} else {
			prefix = sgrDim + "│ " + sgrReset
		}
		var out []string
		width := opts.Width - 2
		if width < 10 {
			width = 10
		}
		for _, l := range b.lines {
			spans := parseInline(l, opts.ANSI)
			for _, wl := range wrapSpans(spans, width) {
				out = append(out, prefix+wl)
			}
		}
		return out
	default:
		var out []string
		text := strings.Join(b.lines, " ")
		spans := parseInline(text, opts.ANSI)
		return append(out, wrapSpans(spans, opts.Width)...)
	}
}

// span is a run of text with an SGR style applied.
type span struct {
	text  string
	style string
}

func parseInline(s string, ansi bool) []span {
	var spans []span
	var buf strings.Builder
	flush := func(style string) {
		if buf.Len() > 0 {
			spans = append(spans, span{text: buf.String(), style: style})
			buf.Reset()
		}
	}
	var style string
	var pending string // marker awaiting its closing partner
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		marker := ""
		sgr := ""
		switch r {
		case '*':
			marker, sgr = "*", sgrBold
		case '_':
			marker, sgr = "_", sgrItalic
		case '`':
			marker, sgr = "`", sgrDim
		}
		if marker == "" {
			buf.WriteRune(r)
			continue
		}
		if !ansi {
			// Styling disabled: keep the literal text, drop only paired markers.
			if pending == "" && hasClosingMarker(runes[i+1:], marker) {
				pending = marker
				continue
			}
			if pending == marker {
				pending = ""
				continue
			}
			buf.WriteRune(r)
			continue
		}
		if pending == "" {
			// Only treat as markup when a closing marker follows later.
			if hasClosingMarker(runes[i+1:], marker) {
				flush(style)
				pending = marker
				style = sgr
				continue
			}
			buf.WriteRune(r)
			continue
		}
		if pending == marker {
			flush(style)
			pending, style = "", ""
			continue
		}
		buf.WriteRune(r)
	}
	flush(style)
	if len(spans) == 0 {
		return []span{{text: "", style: ""}}
	}
	return spans
}

func hasClosingMarker(rest []rune, marker string) bool {
	for _, r := range rest {
		if string(r) == marker {
			return true
		}
	}
	return false
}

func wrapSpans(spans []span, width int) []string {
	if width < 1 {
		width = 1
	}
	type cell struct {
		r     rune
		style string
	}
	var cells []cell
	for _, sp := range spans {
		for _, r := range sp.text {
			cells = append(cells, cell{r, sp.style})
		}
	}
	var lines []string
	var cur strings.Builder
	curW := 0
	curStyle := ""
	emit := func(c cell) {
		if c.style != curStyle {
			cur.WriteString(sgrReset)
			cur.WriteString(c.style)
			curStyle = c.style
		}
		cur.WriteRune(c.r)
	}
	flush := func() {
		if curStyle != "" {
			cur.WriteString(sgrReset)
		}
		lines = append(lines, cur.String())
		cur.Reset()
		curW = 0
		curStyle = ""
	}
	i := 0
	for i < len(cells) {
		start := i
		for i < len(cells) && cells[i].r != ' ' {
			i++
		}
		word := cells[start:i]
		if i < len(cells) && cells[i].r == ' ' {
			i++
		}
		if len(word) == 0 {
			continue
		}
		if curW > 0 && curW+1+len(word) > width {
			flush()
		}
		if curW > 0 {
			cur.WriteByte(' ')
			curW++
		}
		for _, c := range word {
			if curW >= width {
				flush()
			}
			emit(c)
			curW++
		}
	}
	if curW > 0 || len(lines) == 0 {
		flush()
	}
	return lines
}

func wrapLine(s string, width int) []string {
	return wrapSpans(parseInline(s, false), width)
}

func stripSGR(s string) string {
	var b strings.Builder
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
		b.WriteRune(r)
	}
	return b.String()
}
