package commandclassify

import "strings"

// Limits bound the entire input; no syntax is expanded, evaluated or skipped.
const (
	MaxInputBytes = 8192
	MaxWords      = 128
	MaxWordBytes  = 1024
)

// Span is a half-open byte range in the original input, not decoded text.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Word retains a literal value and its source range, including quotes/escapes.
type Word struct {
	Value string `json:"value"`
	Span  Span   `json:"span"`
}

type problem struct {
	reason string
	span   Span
}

// parse is deliberately smaller than a shell parser. Active compound syntax,
// expansion and nesting fail at the first unsupported byte; recursion depth is zero.
func parse(input string) ([]Word, *problem) {
	bad := func(reason string, start, end int) ([]Word, *problem) {
		return nil, &problem{reason, Span{start, end}}
	}
	if len(input) > MaxInputBytes {
		return bad("input_too_large", 0, len(input))
	}
	for i := 0; i < len(input); i++ {
		if input[i] < 32 && input[i] != '\t' || input[i] >= 127 {
			return bad("unsupported_control_or_non_ascii", i, i+1)
		}
	}
	var words []Word
	for i := 0; i < len(input); {
		if input[i] == ' ' || input[i] == '\t' {
			i++
			continue
		}
		if len(words) == MaxWords {
			return bad("too_many_words", i, len(input))
		}
		start := i
		var value strings.Builder
		var quote byte
		quoteStart := i
		for i < len(input) {
			c := input[i]
			if quote == 0 && (c == ' ' || c == '\t') {
				break
			}
			if quote == '\'' {
				if c == '\'' {
					quote = 0
				} else {
					value.WriteByte(c)
				}
				i++
			} else if c == '\\' {
				if i+1 == len(input) {
					return bad("unfinished_escape", i, i+1)
				}
				next := input[i+1]
				allowed := " \\\"'#$`;&|<>(){}[]*?!~"
				if quote == '"' {
					allowed = "\\\"$`"
				}
				if !strings.ContainsRune(allowed, rune(next)) {
					return bad("unsupported_escape", i, i+2)
				}
				value.WriteByte(next)
				i += 2
			} else if quote == '"' {
				if c == '"' {
					quote = 0
				} else if strings.ContainsRune("$`!", rune(c)) {
					return bad("active_shell_syntax", i, i+1)
				} else {
					value.WriteByte(c)
				}
				i++
			} else if c == '\'' || c == '"' {
				quote, quoteStart = c, i
				i++
			} else {
				if strings.ContainsRune(";|&<>(){}[]*?$`!#~^", rune(c)) || c == '=' && value.Len() == 0 {
					return bad("active_shell_syntax", i, i+1)
				}
				value.WriteByte(c)
				i++
			}
			if value.Len() > MaxWordBytes {
				return bad("word_too_large", start, i)
			}
		}
		if quote != 0 {
			return bad("unfinished_quote", quoteStart, len(input))
		}
		words = append(words, Word{value.String(), Span{start, i}})
	}
	if len(words) == 0 {
		return bad("empty_command", 0, len(input))
	}
	return words, nil
}
