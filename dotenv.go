package main

import (
	"regexp"
	"strings"
)

var unquotedValueRE = regexp.MustCompile(`^[A-Za-z0-9_./:@%+\-,=]+$`)

var dotenvEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	"\n", `\n`,
	"\r", `\r`,
	"\t", `\t`,
)

// SerializeDotenv renders entries as .env file content. Values containing
// anything outside a conservative character set are double-quoted with the
// usual dotenv escape sequences.
func SerializeDotenv(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Key)
		b.WriteByte('=')
		b.WriteString(quoteDotenvValue(e.Value))
		b.WriteByte('\n')
	}
	return b.String()
}

func quoteDotenvValue(value string) string {
	if value == "" || unquotedValueRE.MatchString(value) {
		return value
	}
	return `"` + dotenvEscaper.Replace(value) + `"`
}
