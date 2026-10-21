package models

import (
	"strings"
	"unicode"
)

// asciiFold maps common Latin accented runes to their ASCII base so that, e.g., "Beyoncé" and
// "Beyonce" normalize to the same key. stdlib-only (no x/text dependency).
var asciiFold = map[rune]rune{
	'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'ā': 'a', 'ă': 'a', 'ą': 'a',
	'ç': 'c', 'ć': 'c', 'č': 'c',
	'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'ē': 'e', 'ė': 'e', 'ę': 'e',
	'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i', 'į': 'i',
	'ñ': 'n', 'ń': 'n',
	'ò': 'o', 'ó': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 'ø': 'o', 'ō': 'o',
	'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ū': 'u', 'ů': 'u',
	'ý': 'y', 'ÿ': 'y',
	'ž': 'z', 'ź': 'z', 'ż': 'z',
	'ß': 's',
}

// NormalizeName produces a canonical key for host-name matching/dedup: lowercased, accent-folded,
// punctuation stripped, and internal whitespace collapsed to single spaces. "Griffin McElroy",
// "Griffin Mcelroy", and "griffin  mcelroy" all normalize to "griffin mcelroy".
//
// Lives in the models package (not utils) because models cannot import utils — utils already
// imports models, which would create an import cycle.
func NormalizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if folded, ok := asciiFold[r]; ok {
			r = folded
		}
		switch {
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteRune(' ')
			// everything else (punctuation, symbols) is dropped
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
