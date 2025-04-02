package util

import (
	"strings"
)

var sqlStringReplacer = strings.NewReplacer("'", "", `\`, "", "\x00", "")

// SanitizeSQLString removes dangerous chars from the given sql string
func SanitizeSQLString(s string) string {
	return sqlStringReplacer.Replace(s)
}
