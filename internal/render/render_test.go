package render

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeStripsEscapeSequences(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"\x1b[2Jclear", "[2Jclear"},
		{"\x1b]0;title\x07", "]0;title"},
		{"a\r\nb", "a\nb"},
		{"a\rb", "a\nb"},
		{"tab\there", "tab\there"},
		{"nul\x00byte", "nulbyte"},
		{"del\x7fchar", "delchar"},
		{"c1\u009b31mred", "c131mred"},
		{"zero\u200bwidth", "zerowidth"},
		{"bidi\u202eoverride", "bidioverride"},
		{"bom\ufeffstart", "bomstart"},
		{"bad\xffutf8", "bad\uFFFDutf8"},
	}
	for _, c := range cases {
		if got := Sanitize(c.in); got != c.want {
			t.Errorf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeLineFlattensAndTrims(t *testing.T) {
	got := SanitizeLine("  a\nb\tc  ")
	if got != "a b c" {
		t.Fatalf("got %q", got)
	}
}

func FuzzSanitize(f *testing.F) {
	seeds := []string{
		"plain", "\x1b[31mred\x1b[0m", "\x1b]8;;http://x\x07link", "\r\n\r\n",
		"\x9b2J", "\u202eabc", strings.Repeat("a", 300),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Sanitize(s)
		for _, r := range out {
			if r == 0x1b || r == 0x7f || (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("control rune %U survived sanitize of %q", r, s)
			}
		}
		if Sanitize(out) != out {
			t.Fatal("sanitize is not idempotent")
		}
	})
}

func TestRenderPlainParagraphWraps(t *testing.T) {
	out := Render(strings.Repeat("word ", 12), Options{Width: 20})
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if n := utf8.RuneCountInString(line); n > 20 {
			t.Errorf("line %q is %d runes, want <= 20", line, n)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("plain rendering emitted escape sequences")
	}
}

func TestRenderBoldAndItalic(t *testing.T) {
	out := Render("this is *bold* and _italic_", Options{Width: 80, ANSI: true})
	if !strings.Contains(out, sgrBold+"bold") {
		t.Errorf("missing bold span: %q", out)
	}
	if !strings.Contains(out, sgrItalic+"italic") {
		t.Errorf("missing italic span: %q", out)
	}
	if !strings.Contains(out, sgrReset) {
		t.Errorf("missing reset: %q", out)
	}
}

func TestRenderNoANSIStripsMarkers(t *testing.T) {
	out := Render("this is *bold* text", Options{Width: 80, ANSI: false})
	if strings.Contains(out, "*") || strings.Contains(out, "\x1b") {
		t.Fatalf("expected markers and escapes removed, got %q", out)
	}
	if !strings.Contains(out, "this is bold text") {
		t.Fatalf("unexpected text %q", out)
	}
}

func TestRenderUnmatchedMarkersAreLiteral(t *testing.T) {
	out := Render("2 * 3 = 6", Options{Width: 80, ANSI: true})
	if !strings.Contains(out, "2 * 3 = 6") {
		t.Fatalf("got %q", out)
	}
}

func TestRenderQuoteAndList(t *testing.T) {
	out := Render("> quoted line\n> second\n\n- one\n- two", Options{Width: 40, ANSI: false})
	if !strings.Contains(out, "> quoted line") {
		t.Errorf("missing quote: %q", out)
	}
	if !strings.Contains(out, "* one") || !strings.Contains(out, "* two") {
		t.Errorf("missing list items: %q", out)
	}
}

func TestRenderIndentedCodeKeepsWhitespace(t *testing.T) {
	out := Render("    for i := range xs {", Options{Width: 80, ANSI: false})
	if !strings.HasPrefix(out, "    for i := range xs {") {
		t.Fatalf("code block lost indent: %q", out)
	}
}

func TestRenderSanitizesInjectedInput(t *testing.T) {
	out := Render("safe\x1b[2Jwiped", Options{Width: 80, ANSI: true})
	if strings.Contains(out, "\x1b[2J") {
		t.Fatalf("escape survived: %q", out)
	}
}

func TestClipAndPad(t *testing.T) {
	if got := Clip("abcdef", 4); got != "abc…" {
		t.Errorf("Clip = %q", got)
	}
	if got := Clip("abc", 10); got != "abc" {
		t.Errorf("Clip short = %q", got)
	}
	if got := PadRight("ab", 5); got != "ab   " {
		t.Errorf("PadRight = %q", got)
	}
	if got := PadLeft("ab", 4); got != "  ab" {
		t.Errorf("PadLeft = %q", got)
	}
}

func TestWidthIgnoresSGR(t *testing.T) {
	if got := Width(sgrBold + "abc" + sgrReset); got != 3 {
		t.Fatalf("Width = %d, want 3", got)
	}
}

func TestStripSAUCE(t *testing.T) {
	art := []byte("\x1b[0mhello\n")
	comnt := append([]byte("COMNT"), []byte(strings.Repeat("c", 64))...)
	sauce := make([]byte, sauceRecSize)
	copy(sauce, "SAUCE00")
	copy(sauce[7:], "test board")
	data := append(append(append([]byte{}, art...), comnt...), sauce...)

	got := StripSAUCE(data)
	if string(got) != string(art) {
		t.Fatalf("StripSAUCE = %q, want %q", got, art)
	}
	if out := StripSAUCE(art); string(out) != string(art) {
		t.Fatal("art without SAUCE was modified")
	}
}

func TestLoadArtDecodesCP437(t *testing.T) {
	lines, err := LoadArt([]byte{0xdb, 0xdb, '\n'}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "██" {
		t.Fatalf("got %#v", lines)
	}
}

func TestWidthUsesDisplayColumns(t *testing.T) {
	if got := Width("日本"); got != 4 {
		t.Fatalf("Width(日本語) = %d, want 4", got)
	}
	if got := PadRight("日本", 5); got != "日本 " {
		t.Fatalf("PadRight = %q", got)
	}
	if got := Clip("日本語です", 4); got != "日…" {
		t.Fatalf("Clip = %q", got)
	}
	if Width(Clip("日本語です", 4)) > 4 {
		t.Fatal("clipped string exceeds its column budget")
	}
	if got := Clip("abc", 10); got != "abc" {
		t.Fatalf("Clip short = %q", got)
	}
}
