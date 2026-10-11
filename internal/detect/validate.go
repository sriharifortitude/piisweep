package detect

import "strings"

// Each validator takes a normalised candidate (separators removed, letters upper-cased)
// and says whether its check digits are right. A validator is what separates "looks like
// a number" from "is one": without it every long digit run in a log would be a finding.

// ibanLengths is the IBAN length per country, from the SWIFT IBAN registry.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
	"BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
	"ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
	"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22,
	"MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25,
	"QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}

// ValidIBAN checks the country's length and the ISO 13616 mod-97 check.
func ValidIBAN(s string) bool {
	if len(s) < 5 {
		return false
	}
	if n, ok := ibanLengths[s[:2]]; !ok || n != len(s) {
		return false
	}
	if s[2] < '0' || s[2] > '9' || s[3] < '0' || s[3] > '9' {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// Luhn reports whether a digit string passes the Luhn (mod 10) check.
func Luhn(s string) bool {
	if len(s) < 2 {
		return false
	}
	sum, double := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// CardNetwork names the card scheme whose issuer range and length fit, or "" if none does.
func CardNetwork(s string) string {
	n := len(s)
	p := func(k int) int {
		v := 0
		for i := 0; i < k && i < n; i++ {
			v = v*10 + int(s[i]-'0')
		}
		return v
	}
	switch {
	case s[0] == '4' && (n == 16 || n == 19): // 13-digit Visa cards are no longer issued
		return "Visa"
	case (p(2) >= 51 && p(2) <= 55 || p(4) >= 2221 && p(4) <= 2720) && n == 16:
		return "Mastercard"
	case (p(2) == 34 || p(2) == 37) && n == 15:
		return "American Express"
	case (p(4) == 6011 || p(2) == 65 || p(3) >= 644 && p(3) <= 649) && n >= 16 && n <= 19:
		return "Discover"
	case p(4) >= 3528 && p(4) <= 3589 && n >= 16 && n <= 19:
		return "JCB"
	case (p(2) == 36 || p(2) == 38 || p(3) >= 300 && p(3) <= 305) && n >= 14 && n <= 19:
		return "Diners Club"
	case p(2) == 62 && n >= 16 && n <= 19:
		return "UnionPay"
	case (p(2) == 50 || p(2) >= 56 && p(2) <= 69) && n >= 12 && n <= 19:
		return "Maestro"
	}
	return ""
}

// ValidSteuerID checks a German tax identification number (Steuerliche Identifikationsnummer):
// eleven digits, no leading zero, one digit repeated two or three times among the first ten
// (never three in a row) and the rest distinct, and an ISO 7064 MOD 11,10 check digit.
func ValidSteuerID(s string) bool {
	if len(s) != 11 || s[0] == '0' || !allDigits(s) {
		return false
	}
	var counts [10]int
	for i := 0; i < 10; i++ {
		counts[s[i]-'0']++
	}
	repeated := 0
	for _, c := range counts {
		switch {
		case c == 2 || c == 3:
			repeated++
		case c > 3:
			return false
		}
	}
	if repeated != 1 {
		return false
	}
	for i := 0; i+2 < 10; i++ {
		if s[i] == s[i+1] && s[i+1] == s[i+2] {
			return false
		}
	}
	product := 10
	for i := 0; i < 10; i++ {
		sum := (int(s[i]-'0') + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == int(s[10]-'0')
}

// ValidBSN checks a Dutch citizen service number with the "elfproef" (11-test).
func ValidBSN(s string) bool {
	if len(s) != 9 || !allDigits(s) || s == "000000000" {
		return false
	}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(s[i]-'0') * (9 - i)
	}
	sum -= int(s[8] - '0')
	return sum%11 == 0
}

// ValidNIR checks a French social security number (NIR): 13 characters then a two-digit key,
// 97 minus the number modulo 97, where Corsica's departments 2A and 2B count as 19 and 18.
func ValidNIR(s string) bool {
	if len(s) != 15 {
		return false
	}
	body := s[:13]
	switch body[5:7] {
	case "2A":
		body = body[:5] + "19" + body[7:]
	case "2B":
		body = body[:5] + "18" + body[7:]
	}
	if !allDigits(body) || !allDigits(s[13:]) {
		return false
	}
	var n uint64
	for i := 0; i < len(body); i++ {
		n = n*10 + uint64(body[i]-'0')
	}
	key := int(s[13]-'0')*10 + int(s[14]-'0')
	return 97-int(n%97) == key
}

const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// ValidDNI checks a Spanish DNI (eight digits and a letter) or NIE (X, Y or Z, seven digits
// and a letter): the letter is the number modulo 23 in a fixed table.
func ValidDNI(s string) bool {
	if len(s) != 9 {
		return false
	}
	digits := s[:8]
	switch s[0] {
	case 'X':
		digits = "0" + s[1:8]
	case 'Y':
		digits = "1" + s[1:8]
	case 'Z':
		digits = "2" + s[1:8]
	}
	if !allDigits(digits) {
		return false
	}
	n := 0
	for i := 0; i < 8; i++ {
		n = n*10 + int(digits[i]-'0')
	}
	return dniLetters[n%23] == s[8]
}

// Values of a character in an odd (1st, 3rd, ...) position of a codice fiscale.
var cfOdd = map[byte]int{
	'0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
	'A': 1, 'B': 0, 'C': 5, 'D': 7, 'E': 9, 'F': 13, 'G': 15, 'H': 17, 'I': 19, 'J': 21,
	'K': 2, 'L': 4, 'M': 18, 'N': 20, 'O': 11, 'P': 3, 'Q': 6, 'R': 8, 'S': 12, 'T': 14,
	'U': 16, 'V': 10, 'W': 22, 'X': 25, 'Y': 24, 'Z': 23,
}

// ValidCodiceFiscale checks the control character of an Italian fiscal code.
func ValidCodiceFiscale(s string) bool {
	if len(s) != 16 {
		return false
	}
	sum := 0
	for i := 0; i < 15; i++ {
		c := s[i]
		if i%2 == 0 { // 1st, 3rd, ... in the specification's 1-based counting
			v, ok := cfOdd[c]
			if !ok {
				return false
			}
			sum += v
			continue
		}
		switch {
		case c >= '0' && c <= '9':
			sum += int(c - '0')
		case c >= 'A' && c <= 'Z':
			sum += int(c - 'A')
		default:
			return false
		}
	}
	return s[15] == byte('A'+sum%26)
}

// ValidBelgianNN checks a Belgian national register number: YYMMDD, a three-digit serial,
// and a check of 97 minus the first nine digits modulo 97, with 2 prefixed for people born
// from 2000. Months above 12 are allowed for "bis" numbers (+20, +40).
func ValidBelgianNN(s string) bool {
	if len(s) != 11 || !allDigits(s) {
		return false
	}
	month := int(s[2]-'0')*10 + int(s[3]-'0')
	day := int(s[4]-'0')*10 + int(s[5]-'0')
	if !(month <= 12 || month >= 20 && month <= 32 || month >= 40 && month <= 52) || day > 31 {
		return false
	}
	var n uint64
	for i := 0; i < 9; i++ {
		n = n*10 + uint64(s[i]-'0')
	}
	check := uint64(s[9]-'0')*10 + uint64(s[10]-'0')
	return 97-n%97 == check || 97-(2000000000+n)%97 == check
}

// ValidPESEL checks a Polish PESEL: weights 1,3,7,9 repeated, and a birth date in which the
// month carries the century (+80 for the 1800s, +20 for the 2000s, and so on).
func ValidPESEL(s string) bool {
	if len(s) != 11 || !allDigits(s) {
		return false
	}
	month := int(s[2]-'0')*10 + int(s[3]-'0')
	day := int(s[4]-'0')*10 + int(s[5]-'0')
	if m := month % 20; m < 1 || m > 12 || day < 1 || day > 31 {
		return false
	}
	weights := [10]int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	return (10-sum%10)%10 == int(s[10]-'0')
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func stripSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '.', '/', ' ':
			return -1
		}
		return r
	}, s)
}
