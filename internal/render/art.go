package render

import (
	"bytes"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// sauceRecSize is the size of a SAUCE metadata record.
const sauceRecSize = 128

// StripSAUCE removes a trailing SAUCE00 metadata record and its COMNT comment
// block from ANSI art. Art without SAUCE is returned unchanged.
func StripSAUCE(data []byte) []byte {
	if len(data) < sauceRecSize {
		return data
	}
	tail := data[len(data)-sauceRecSize:]
	if !bytes.HasPrefix(tail, []byte("SAUCE00")) {
		return data
	}
	cut := len(data) - sauceRecSize
	// A COMNT block is "COMNT" followed by N 64-byte comment lines and sits
	// immediately before the SAUCE record. Find the last one that aligns.
	for pos := cut - 5; pos >= 0; pos-- {
		if cut-pos > 5+64*64 { // sane upper bound on comment blocks
			break
		}
		if bytes.HasPrefix(data[pos:], []byte("COMNT")) && (cut-pos-5)%64 == 0 {
			cut = pos
		}
	}
	return data[:cut]
}

// DecodeCP437 converts DOS code page 437 bytes to UTF-8.
func DecodeCP437(data []byte) (string, error) {
	out, err := charmap.CodePage437.NewDecoder().Bytes(data)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// LoadArt prepares an ANSI art file for display: SAUCE metadata is stripped,
// CP437 is optionally decoded, lines are split and trailing blanks removed.
// Art is trusted sysop content, so escape sequences are preserved.
func LoadArt(data []byte, cp437 bool) ([]string, error) {
	data = StripSAUCE(data)
	var text string
	if cp437 {
		decoded, err := DecodeCP437(data)
		if err != nil {
			return nil, err
		}
		text = decoded
	} else {
		text = strings.ToValidUTF8(string(data), "\uFFFD")
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for len(lines) > 0 && strings.TrimSpace(stripSGR(lines[len(lines)-1])) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}
