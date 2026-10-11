// Package detect finds personal data in a line of text.
//
// A candidate found by a pattern becomes a match only if its check digits are right, and its
// confidence depends on how strong that check is and on whether a keyword that names the kind
// of data appears on the same line. The matched value never leaves this package unmasked.
package detect

import (
	"net"
	"regexp"
	"sort"
	"strings"
)

// Confidence levels, weakest first.
type Confidence int

// Confidence levels.
const (
	Low Confidence = iota + 1
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "unknown"
}

// ParseConfidence reads "low", "medium" or "high".
func ParseConfidence(s string) (Confidence, bool) {
	switch strings.ToLower(s) {
	case "low":
		return Low, true
	case "medium":
		return Medium, true
	case "high":
		return High, true
	}
	return 0, false
}

// Match is one piece of personal data found on a line.
type Match struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Confidence Confidence `json:"-"`
	// Start and End are byte offsets in the line.
	Start int `json:"-"`
	End   int `json:"-"`
	// Masked is the value with most characters replaced; the raw value is not kept.
	Masked string `json:"masked"`
	// TestValue is set for well-known example values (4111 1111 1111 1111, DE89 3704 ...).
	TestValue bool `json:"test_value,omitempty"`
	// Also lists other kinds the same characters validate as.
	Also []string `json:"also,omitempty"`
}

type detector struct {
	id, kind string
	re       *regexp.Regexp
	keywords []string
	// check normalises and validates a candidate; it returns the confidence without keywords
	// (0 to reject) and with a keyword on the line.
	check func(raw, norm string) (plain, withKeyword Confidence)
	mask  func(norm string) string
	norm  func(raw string) string
	// minDigits and needs are cheap preconditions on the whole line, checked before the
	// pattern runs; most lines of a log fail them.
	minDigits int
	needs     string
	// shrink retries a failing candidate cut at each of its separators, longest first, so that
	// a card number followed by "2026" is still found.
	shrink bool
}

var detectors = []detector{
	{
		id: "PI001", minDigits: 0, needs: "@", kind: "email address",
		re:   regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9._%+\-]{0,63}@[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}\b`),
		norm: strings.ToLower,
		check: func(raw, norm string) (Confidence, Confidence) {
			at := strings.LastIndexByte(norm, '@')
			local, domain := norm[:at], norm[at+1:]
			tld := domain[strings.LastIndexByte(domain, '.')+1:]
			if fileExtensions[tld] || placeholderTLDs[tld] || reservedDomain(domain) {
				return 0, 0
			}
			if roleAddress(local) || strings.HasSuffix(domain, "users.noreply.github.com") {
				return Low, Low
			}
			return High, High
		},
		mask: maskEmail,
	},
	{
		id: "PI002", minDigits: 6, needs: "", kind: "IBAN",
		re:       regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`),
		keywords: []string{"iban", "konto", "account", "compte", "cuenta", "conto", "rekening", "bank"},
		norm:     func(raw string) string { return strings.ToUpper(stripSeparators(raw)) },
		check: func(_, n string) (Confidence, Confidence) {
			if !ValidIBAN(n) {
				return 0, 0
			}
			return High, High
		},
		mask:   func(n string) string { return n[:4] + strings.Repeat("*", len(n)-6) + n[len(n)-2:] },
		shrink: true,
	},
	{
		id: "PI003", minDigits: 12, needs: "", kind: "payment card number",
		re:       regexp.MustCompile(`\b\d(?:[ \-]?\d){11,18}\b`),
		keywords: []string{"card", "karte", "carte", "tarjeta", "carta", "kaart", "pan", "visa", "mastercard", "amex", "cc_num", "ccnum"},
		norm:     stripSeparators,
		check: func(raw, n string) (Confidence, Confidence) {
			if !Luhn(n) || CardNetwork(n) == "" || repetitive(n) {
				return 0, 0
			}
			if raw != n {
				// Written in groups: only the groupings cards are printed in count.
				if !cardGrouping(raw) {
					return 0, 0
				}
				return High, High
			}
			if len(n) == 15 || len(n) == 16 {
				return Medium, High
			}
			return Low, High // 12-14 and 17-19 unbroken digits are far more often other numbers
		},
		mask:   func(n string) string { return strings.Repeat("*", len(n)-4) + n[len(n)-4:] },
		shrink: true,
	},
	{
		id: "PI004", minDigits: 9, needs: "+", kind: "phone number",
		re:       regexp.MustCompile(`\+\d{1,3}[ \-.]?\(?\d{1,4}\)?(?:[ \-.]?\d{2,4}){2,4}\b`),
		keywords: []string{"phone", "tel", "mobile", "mobil", "handy", "telefon", "téléphone", "telefono", "teléfono", "cell", "fax", "whatsapp", "sms"},
		norm: func(raw string) string {
			return strings.NewReplacer(" ", "", "-", "", ".", "", "(", "", ")", "").Replace(raw)
		},
		check: func(_, n string) (Confidence, Confidence) {
			digits := len(n) - 1
			if digits < 9 || digits > 15 || repetitive(n[1:]) {
				return 0, 0
			}
			return Low, Medium
		},
		mask: func(n string) string { return n[:3] + strings.Repeat("*", len(n)-5) + n[len(n)-2:] },
	},
	{
		id: "PI005", minDigits: 2, needs: "", kind: "IP address",
		re:   regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b|(?i:\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b)`),
		norm: func(raw string) string { return raw },
		check: func(_, n string) (Confidence, Confidence) {
			ip := net.ParseIP(n)
			if ip == nil || !publicIP(ip) {
				return 0, 0
			}
			return Low, Low
		},
		mask: maskIP,
	},
	{
		id: "PI010", minDigits: 11, needs: "", kind: "German tax ID (Steuer-ID)",
		re:       regexp.MustCompile(`\b[1-9]\d(?: ?\d{3}){3}\b`),
		keywords: []string{"steuer", "idnr", "identifikationsnummer", "tax id", "tin", "taxid"},
		norm:     stripSeparators,
		check: func(_, n string) (Confidence, Confidence) {
			if !ValidSteuerID(n) {
				return 0, 0
			}
			return Low, High
		},
		mask: maskMiddle,
	},
	{
		id: "PI011", minDigits: 9, needs: "", kind: "Dutch citizen service number (BSN)",
		re:       regexp.MustCompile(`\b\d{4}[ .]?\d{2}[ .]?\d{3}\b`),
		keywords: []string{"bsn", "burgerservicenummer", "sofinummer", "sofi"},
		norm:     stripSeparators,
		check: func(_, n string) (Confidence, Confidence) {
			if !ValidBSN(n) || repetitive(n) {
				return 0, 0
			}
			return Low, High
		},
		mask: maskMiddle,
	},
	{
		id: "PI012", minDigits: 13, needs: "", kind: "French social security number (NIR)",
		re:       regexp.MustCompile(`\b[1-478] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[ABab]) ?\d{3} ?\d{3} ?\d{2}\b`),
		keywords: []string{"nir", "sécurité sociale", "securite sociale", "insee", "numéro de sécu", "secu"},
		norm:     func(raw string) string { return strings.ToUpper(stripSeparators(raw)) },
		check: func(_, n string) (Confidence, Confidence) {
			if !ValidNIR(n) {
				return 0, 0
			}
			return High, High
		},
		mask: maskMiddle,
	},
	{
		id: "PI013", minDigits: 7, needs: "", kind: "Spanish identity number (DNI/NIE)",
		re:       regexp.MustCompile(`\b(?:\d{8}|[XYZxyz][ \-]?\d{7})[ \-]?[A-Za-z]\b`),
		keywords: []string{"dni", "nie", "nif", "documento", "identidad"},
		norm:     func(raw string) string { return strings.ToUpper(stripSeparators(raw)) },
		check: func(_, n string) (Confidence, Confidence) {
			if !ValidDNI(n) {
				return 0, 0
			}
			return Medium, High
		},
		mask: maskMiddle,
	},
	{
		id: "PI014", minDigits: 0, needs: "", kind: "Italian fiscal code (codice fiscale)",
		re:       regexp.MustCompile(`(?i)\b[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]\b`),
		keywords: []string{"codice fiscale", "cf", "fiscal"},
		norm:     strings.ToUpper,
		check: func(_, n string) (Confidence, Confidence) {
			if !ValidCodiceFiscale(n) {
				return 0, 0
			}
			return High, High
		},
		mask: maskMiddle,
	},
	{
		id: "PI015", minDigits: 11, needs: "", kind: "Belgian national register number",
		re:       regexp.MustCompile(`\b\d{2}[.\-]?\d{2}[.\-]?\d{2}[.\-]?\d{3}[.\-]?\d{2}\b`),
		keywords: []string{"rijksregister", "registre national", "national number", "nn", "insz", "niss"},
		norm:     stripSeparators,
		check: func(raw, n string) (Confidence, Confidence) {
			if !ValidBelgianNN(n) {
				return 0, 0
			}
			if raw != n { // written YY.MM.DD-SSS.CC
				return Medium, High
			}
			return Low, High
		},
		mask: maskMiddle,
	},
	{
		id: "PI016", minDigits: 11, needs: "", kind: "Polish PESEL",
		re:       regexp.MustCompile(`\b\d{11}\b`),
		keywords: []string{"pesel"},
		norm:     func(raw string) string { return raw },
		check: func(_, n string) (Confidence, Confidence) {
			if !ValidPESEL(n) || repetitive(n) {
				return 0, 0
			}
			return Low, High
		},
		mask: maskMiddle,
	},
}

// Find returns the personal data on one line, at least as confident as min, with overlapping
// candidates resolved in favour of the more confident and then the longer.
func Find(line string, min Confidence) []Match {
	lower := ""
	digits := 0
	for i := 0; i < len(line); i++ {
		if line[i] >= '0' && line[i] <= '9' {
			digits++
		}
	}
	var all []Match
	for i := range detectors {
		d := &detectors[i]
		if digits < d.minDigits || d.needs != "" && !strings.Contains(line, d.needs) {
			continue
		}
		locs := d.re.FindAllStringIndex(line, -1)
		if len(locs) == 0 {
			continue
		}
		if lower == "" {
			lower = strings.ToLower(line)
		}
		for _, loc := range locs {
			raw := line[loc[0]:loc[1]]
			n := d.norm(raw)
			plain, withKW := d.check(raw, n)
			for end := loc[1] - 1; plain == 0 && d.shrink && end > loc[0]; end-- {
				if line[end] != ' ' && line[end] != '-' {
					continue
				}
				raw = line[loc[0]:end]
				n = d.norm(raw)
				if plain, withKW = d.check(raw, n); plain != 0 {
					loc = []int{loc[0], end}
				}
			}
			if plain == 0 || partOfLargerNumber(line, loc[0], loc[1], d.id) {
				continue
			}
			c := plain
			if withKW > plain && hasKeyword(lower, d.keywords) {
				c = withKW
			}
			all = append(all, Match{ID: d.id, Kind: d.kind, Confidence: c, Start: loc[0], End: loc[1],
				Masked: d.mask(n), TestValue: testValues[n]})
		}
	}
	return resolve(all, min, len(line))
}

func resolve(all []Match, min Confidence, lineLen int) []Match {
	if len(all) == 0 {
		return nil
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Confidence != all[j].Confidence {
			return all[i].Confidence > all[j].Confidence
		}
		return all[i].End-all[i].Start > all[j].End-all[j].Start
	})
	// owner[i] is the index in kept of the match covering byte i, or -1. Kept matches never
	// overlap, so checking a candidate costs its own length: linear for the line, where
	// comparing against every kept match was quadratic (32 s for a 1 MiB line of "1.1.1.1.").
	owner := make([]int32, lineLen)
	for i := range owner {
		owner[i] = -1
	}
	var kept []Match
	for _, m := range all {
		clash := int32(-1)
		for i := m.Start; i < m.End; i++ {
			if owner[i] >= 0 {
				clash = owner[i]
				break
			}
		}
		if clash < 0 {
			for i := m.Start; i < m.End; i++ {
				owner[i] = int32(len(kept))
			}
			kept = append(kept, m)
			continue
		}
		// The same characters validating as another kind is worth saying, not a second finding.
		k := &kept[clash]
		if m.Start == k.Start && m.End == k.End && m.ID != k.ID {
			k.Also = append(k.Also, m.Kind)
		}
	}
	var out []Match
	for _, m := range kept {
		if m.Confidence >= min {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// partOfLargerNumber rejects numeric candidates that continue a number: "-6151260282..." (a
// negative literal), "3.14159..." or "...1234.5678" (decimals), "0x..." (hex).
func partOfLargerNumber(line string, start, end int, id string) bool {
	switch id {
	case "PI001", "PI002", "PI004", "PI005", "PI014":
		return false
	}
	if start > 0 {
		switch line[start-1] {
		case '-', '.', '+', '_', '/':
			return true
		}
	}
	if end < len(line)-1 && (line[end] == '.' || line[end] == ',') && line[end+1] >= '0' && line[end+1] <= '9' {
		return true
	}
	return false
}

// hasKeyword looks for a keyword as a whole word, so "tin" does not match "testing".
func hasKeyword(lower string, keywords []string) bool {
	for _, k := range keywords {
		for from := 0; ; {
			i := strings.Index(lower[from:], k)
			if i < 0 {
				break
			}
			i += from
			end := i + len(k)
			if (i == 0 || !isWordByte(lower[i-1])) && (end == len(lower) || !isWordByte(lower[end])) {
				return true
			}
			from = i + 1
		}
	}
	return false
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
}

// cardGrouping accepts the ways card numbers are printed: one kind of separator, and groups of
// four (the last may be shorter), or 4-6-5 (American Express) or 4-6-4 (Diners Club). Pairs of
// digits in a comment ("23 22 21 20 ...") and two numbers side by side do not qualify.
func cardGrouping(raw string) bool {
	if strings.ContainsRune(raw, ' ') && strings.ContainsRune(raw, '-') {
		return false
	}
	groups := strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == '-' })
	var lens []int
	for _, g := range groups {
		lens = append(lens, len(g))
	}
	if len(lens) == 3 && lens[0] == 4 && lens[1] == 6 && (lens[2] == 5 || lens[2] == 4) {
		return true
	}
	if len(lens) < 3 {
		return false
	}
	for i, l := range lens {
		if l != 4 && !(i == len(lens)-1 && l >= 1 && l <= 3) {
			return false
		}
	}
	return true
}

// repetitive rejects 0000..., 1111..., 1234567... style placeholders.
func repetitive(n string) bool {
	if len(n) < 6 {
		return false
	}
	same, up := true, true
	for i := 1; i < len(n); i++ {
		if n[i] != n[0] {
			same = false
		}
		if (n[i-1]-'0'+1)%10 != n[i]-'0' {
			up = false
		}
	}
	return same || up
}

var fileExtensions = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true, "ico": true, "js": true,
	"css": true, "json": true, "html": true, "htm": true, "xml": true, "txt": true, "md": true, "pdf": true,
	"zip": true, "gz": true, "tar": true, "map": true, "ts": true, "tsx": true, "jsx": true, "woff": true, "woff2": true,
}

// reservedDomain reports domains that cannot belong to a person (RFC 2606, RFC 6761).
func reservedDomain(d string) bool {
	for _, s := range []string{"example.com", "example.org", "example.net"} {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	for _, s := range []string{".example", ".test", ".invalid", ".localhost", ".local"} {
		if strings.HasSuffix(d, s) {
			return true
		}
	}
	return d == "localhost"
}

// placeholderTLDs are endings seen in documentation and tests that are not real TLDs.
var placeholderTLDs = map[string]bool{
	"tld": true, "faketld": true, "service": true, "domain": true, "localdomain": true, "internal": true,
	"lan": true, "corp": true, "home": true, "fake": true, "dummy": true, "none": true, "sample": true,
}

// roleAddress reports mailboxes that belong to a function, not a person.
func roleAddress(local string) bool {
	local = strings.SplitN(local, "+", 2)[0]
	if roleLocalParts[local] {
		return true
	}
	for _, p := range []string{"noreply", "no-reply", "no_reply", "donotreply", "do-not-reply", "bounce", "mailer-daemon"} {
		if strings.HasPrefix(local, p) {
			return true
		}
	}
	return strings.Contains(local, "dmarc")
}

var roleLocalParts = map[string]bool{
	"noreply": true, "no-reply": true, "donotreply": true, "do-not-reply": true, "postmaster": true, "abuse": true,
	"hostmaster": true, "webmaster": true, "info": true, "support": true, "security": true, "admin": true,
	"root": true, "git": true, "mailer-daemon": true, "privacy": true, "dpo": true, "contact": true, "sales": true, "hello": true,
}

func publicIP(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, cidr := range documentation {
		if cidr.Contains(ip) {
			return false
		}
	}
	return true
}

var documentation = func() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "0.0.0.0/8",
		"100.64.0.0/10", "255.255.255.255/32", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4"} {
		_, n, _ := net.ParseCIDR(s)
		out = append(out, n)
	}
	return out
}()

// testValues are example values published by banks, card schemes and standards bodies. They
// are reported as such, so that test fixtures do not fail a scan of a codebase.
var testValues = map[string]bool{
	"4111111111111111": true, "4242424242424242": true, "4012888888881881": true, "5555555555554444": true,
	"5105105105105100": true, "378282246310005": true, "371449635398431": true, "6011111111111117": true,
	"4000056655665556": true, "5200828282828210": true, "3530111333300000": true, "30569309025904": true,
	"DE89370400440532013000": true, "GB82WEST12345698765432": true, "NL91ABNA0417164300": true,
	"FR1420041010050500013M02606": true, "GB29NWBK60161331926819": true, "ES9121000418450200051332": true,
	"IT60X0542811101000000123456": true, "BE68539007547034": true, "AT611904300234573201": true,
	"CH9300762011623852957": true, "12345678Z": true, "X1234567L": true, "111222333": true, "123456782": true,
	"RSSMRA85T10A562S": true, "44051401359": true,
}

func maskMiddle(n string) string {
	if len(n) <= 4 {
		return strings.Repeat("*", len(n))
	}
	return n[:2] + strings.Repeat("*", len(n)-4) + n[len(n)-2:]
}

func maskEmail(n string) string {
	at := strings.LastIndexByte(n, '@')
	local := n[:at]
	return local[:1] + strings.Repeat("*", max(len(local)-1, 3)) + n[at:]
}

func maskIP(n string) string {
	if strings.Contains(n, ":") {
		parts := strings.Split(n, ":")
		if len(parts) > 2 {
			return strings.Join(parts[:2], ":") + ":****"
		}
		return "****"
	}
	parts := strings.Split(n, ".")
	return parts[0] + "." + parts[1] + ".*.*"
}
