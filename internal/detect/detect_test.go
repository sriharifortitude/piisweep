package detect

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// Example values published by banks, card schemes, tax authorities and standard references.
// They anchor the validators to something other than this code's reading of the algorithms.
var published = []struct {
	name  string
	valid func(string) bool
	value string
}{
	{"IBAN DE", ValidIBAN, "DE89370400440532013000"},
	{"IBAN GB", ValidIBAN, "GB82WEST12345698765432"},
	{"IBAN NL", ValidIBAN, "NL91ABNA0417164300"},
	{"IBAN FR (letter in BBAN)", ValidIBAN, "FR1420041010050500013M02606"},
	{"IBAN NO (shortest)", ValidIBAN, "NO9386011117947"},
	{"card Visa", Luhn, "4111111111111111"},
	{"card Amex", Luhn, "378282246310005"},
	{"BSN", ValidBSN, "111222333"},
	{"BSN", ValidBSN, "123456782"},
	{"DNI", ValidDNI, "12345678Z"},
	{"NIE", ValidDNI, "X1234567L"},
	{"codice fiscale", ValidCodiceFiscale, "RSSMRA85T10A562S"},
	{"PESEL", ValidPESEL, "44051401359"},
	{"Steuer-ID", ValidSteuerID, "86095742719"},
	{"Steuer-ID", ValidSteuerID, "65929970489"},
	{"Steuer-ID", ValidSteuerID, "47036892816"},
	{"NIR", ValidNIR, "255081416802538"},
	{"NIR", ValidNIR, "184127645108946"},
	{"Belgian NN", ValidBelgianNN, "93051822361"},
	{"Belgian NN", ValidBelgianNN, "85073003328"},
}

func TestPublishedExamplesValidate(t *testing.T) {
	for _, p := range published {
		if !p.valid(p.value) {
			t.Errorf("%s %s should be valid", p.name, p.value)
		}
	}
}

// Changing any one character of a value with a strong check must make it invalid. Weak checks
// (Luhn, 11-test, mod 10) are covered by the transposition and single-digit tests below.
func TestEverySingleDigitChangeBreaksStrongChecks(t *testing.T) {
	for _, p := range published {
		switch p.name {
		case "card Visa", "card Amex", "BSN", "PESEL", "Steuer-ID":
			continue
		}
		for i := 0; i < len(p.value); i++ {
			c := p.value[i]
			if c < '0' || c > '9' {
				continue
			}
			for d := byte('0'); d <= '9'; d++ {
				if d == c {
					continue
				}
				changed := p.value[:i] + string(d) + p.value[i+1:]
				if p.valid(changed) {
					t.Errorf("%s: %s (digit %d changed) still validates", p.name, changed, i)
				}
			}
		}
	}
}

func TestLuhnCatchesEverySingleDigitError(t *testing.T) {
	v := "4111111111111111"
	for i := 0; i < len(v); i++ {
		for d := byte('0'); d <= '9'; d++ {
			if d != v[i] && Luhn(v[:i]+string(d)+v[i+1:]) {
				t.Fatalf("Luhn accepted a single-digit change at %d", i)
			}
		}
	}
}

func TestCardNetworks(t *testing.T) {
	for n, want := range map[string]string{
		"4111111111111111": "Visa", "5555555555554444": "Mastercard", "2221000000000009": "Mastercard",
		"378282246310005": "American Express", "6011111111111117": "Discover", "3530111333300000": "JCB",
		"30569309025904": "Diners Club", "4111111111111": "", "9111111111111111": "", "2720999999999996": "Mastercard",
		"2721000000000000": "",
	} {
		if got := CardNetwork(n); got != want {
			t.Errorf("%s: got %q want %q", n, got, want)
		}
	}
}

func TestSteuerIDDigitRules(t *testing.T) {
	for _, bad := range []string{
		"06095742719", // leading zero
		"12345678901", // no repeated digit
		"11122345678", // three in a row
		"11223345678", // two digits repeated
	} {
		if ValidSteuerID(bad) {
			t.Errorf("%s should fail the digit rules", bad)
		}
	}
}

func TestNIRCorsica(t *testing.T) {
	// Built from the rule: department 2A counts as 19 in the key.
	body := "185012A001123"
	n := uint64(1850119001123)
	key := 97 - n%97
	v := fmt.Sprintf("%s%02d", body, key)
	if !ValidNIR(v) {
		t.Fatalf("%s should be valid", v)
	}
	if ValidNIR(body + "00") {
		t.Fatal("wrong key accepted")
	}
}

func TestBelgianNNBornFrom2000(t *testing.T) {
	first9 := uint64(10022312345 / 100) // 100223123
	check := 97 - (2000000000+first9)%97
	v := fmt.Sprintf("%09d%02d", first9, check)
	if !ValidBelgianNN(v) {
		t.Fatalf("%s should be valid with the 2000 rule", v)
	}
}

// --- detection -----------------------------------------------------------------------------

func find(t *testing.T, line string, min Confidence) []Match {
	t.Helper()
	ms := Find(line, min)
	for _, m := range ms {
		raw := line[m.Start:m.End]
		norm := strings.ToUpper(stripSeparators(raw))
		if len(norm) > 4 && strings.Contains(strings.ToUpper(m.Masked), norm) {
			t.Fatalf("masked value %q contains the raw value", m.Masked)
		}
	}
	return ms
}

func one(t *testing.T, line string, min Confidence) Match {
	t.Helper()
	ms := find(t, line, min)
	if len(ms) != 1 {
		t.Fatalf("%q: want one match, got %+v", line, ms)
	}
	return ms[0]
}

func none(t *testing.T, line string, min Confidence) {
	t.Helper()
	if ms := find(t, line, min); len(ms) != 0 {
		t.Fatalf("%q: want nothing, got %+v", line, ms)
	}
}

func TestEachKindIsFoundWithTheRightConfidence(t *testing.T) {
	cases := []struct {
		line string
		id   string
		conf Confidence
	}{
		{"from alice.martin@posteo.de", "PI001", High},
		{"sent to noreply-dmarc-support@google.com", "PI001", Low},
		{"refund to DE44 5001 0517 5407 3249 31 please", "PI002", High},
		{"refund to DE44500105175407324931", "PI002", High},
		{"charged 4532 0151 1283 0366 today", "PI003", High},
		{"charged 4532015112830366 today", "PI003", Medium},
		{"card=4532015112830366", "PI003", High},
		{"reach me at +49 30 12345678", "PI004", Low},
		{"tel +49 30 12345678", "PI004", Medium},
		{"client 8.8.8.8 connected", "PI005", Low},
		{"client 2a00:1450:4001:82a::200e connected", "PI005", Low},
		{"Steuer-ID 86095742719", "PI010", High},
		{"ref 86095742719", "PI010", Low},
		{"bsn: 268411281", "PI011", High},
		{"NIR 2 55 08 14 168 025 38", "PI012", High},
		{"DNI 87654321X", "PI013", High},
		{"ref 87654321X", "PI013", Medium},
		{"CF: MRNGNN80A01H501E", "PI014", High},
		{"rijksregister 93.05.18-223.61", "PI015", High},
		{"93.05.18-223.61", "PI015", Medium},
		{"PESEL 02070803628", "PI016", High},
	}
	for _, c := range cases {
		ms := find(t, c.line, Low)
		var got *Match
		for i := range ms {
			if ms[i].ID == c.id {
				got = &ms[i]
			}
		}
		if got == nil {
			t.Errorf("%q: %s not found in %+v", c.line, c.id, ms)
			continue
		}
		if got.Confidence != c.conf {
			t.Errorf("%q: %s confidence %v, want %v", c.line, c.id, got.Confidence, c.conf)
		}
	}
}

func TestNothingIsFoundInOrdinaryText(t *testing.T) {
	for _, line := range []string{
		"GET /api/v1/orders/12345 200 OK 532ms",
		"icon@2x.png and logo@3x.webp",
		"mail user@example.com or ops@corp.example or x@host.tld",
		"see 10.0.0.1, 127.0.0.1, 192.0.2.10 and 2001:db8::1",
		"// 23 22 21 20 19 18 17 16",
		"x := -615126028225187231",
		"pi = 3.141592653589793",
		"timestamp 20261011093015123",
		"0000000000000000 and 1234567890123456",
		"version 1.2.3",
		"commit 4f2a9c1b7e6d5a4f3e2d1c0b9a8f7e6d5c4b3a29",
	} {
		none(t, line, Medium)
	}
}

func TestACardNumberFollowedByMoreDigitsIsStillFound(t *testing.T) {
	m := one(t, "4532 0151 1283 0366 2026", Medium)
	if m.ID != "PI003" || !strings.HasSuffix(m.Masked, "0366") {
		t.Fatalf("%+v", m)
	}
}

func TestAnIBANFollowedByAWordIsStillFound(t *testing.T) {
	if m := one(t, "DE44 5001 0517 5407 3249 31 EUR", Medium); m.ID != "PI002" {
		t.Fatalf("%+v", m)
	}
}

func TestTestValuesAreMarked(t *testing.T) {
	for _, line := range []string{"4111 1111 1111 1111", "DE89 3704 0044 0532 0130 00", "BSN 111222333", "RSSMRA85T10A562S"} {
		ms := find(t, line, Low)
		if len(ms) == 0 || !ms[0].TestValue {
			t.Errorf("%q: want a test value, got %+v", line, ms)
		}
	}
}

func TestOneSpanValidAsTwoKindsIsOneMatch(t *testing.T) {
	// Search for an 11-digit number that passes both the PESEL and the Steuer-ID checks.
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 2_000_000; i++ {
		v := fmt.Sprintf("%011d", r.Int64N(1e11))
		if ValidPESEL(v) && ValidSteuerID(v) {
			ms := find(t, "pesel "+v, Low)
			if len(ms) != 1 || ms[0].ID != "PI016" || len(ms[0].Also) == 0 {
				t.Fatalf("%s: want one PESEL match noting the Steuer-ID, got %+v", v, ms)
			}
			return
		}
	}
	t.Skip("no number valid as both found in the search")
}

func TestKeywordsAreWholeWords(t *testing.T) {
	// "testing" contains "tin"; it must not raise a bare 11-digit number to high.
	if m := one(t, "testing 86095742719", Low); m.Confidence != Low {
		t.Fatalf("%+v", m)
	}
}

func TestMinimumConfidenceFilters(t *testing.T) {
	none(t, "client 8.8.8.8", Medium)
	if len(find(t, "client 8.8.8.8", Low)) != 1 {
		t.Fatal("low should include it")
	}
}

func TestMasks(t *testing.T) {
	for line, want := range map[string]string{
		"alice.martin@posteo.de":      "a***********@posteo.de",
		"DE44 5001 0517 5407 3249 31": "DE44****************31",
		"4532 0151 1283 0366":         "************0366",
		"client 8.8.8.8":              "8.8.*.*",
		"CF: MRNGNN80A01H501E":        "MR************1E",
		"ab@posteo.de":                "a***@posteo.de",
	} {
		ms := find(t, line, Low)
		if len(ms) == 0 || ms[0].Masked != want {
			t.Errorf("%q: got %+v want %q", line, ms, want)
		}
	}
}

// --- generated values: every scheme, many random valid and invalid numbers -----------------

func ibanFor(country, bban string) string {
	for c := 0; c < 100; c++ {
		v := fmt.Sprintf("%s%02d%s", country, c, bban)
		if ValidIBAN(v) {
			return v
		}
	}
	return ""
}

func TestGeneratedValuesAreFound(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 11))
	digits := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteByte(byte('0' + r.IntN(10)))
		}
		return b.String()
	}
	for i := 0; i < 300; i++ {
		// IBAN (German): bank code and account, check digits computed by search.
		iban := ibanFor("DE", digits(18))
		if m := find(t, "IBAN "+iban, Medium); len(m) != 1 || m[0].ID != "PI002" {
			t.Fatalf("IBAN %s: %+v", iban, m)
		}
		// Card (Visa 16): last digit chosen to pass Luhn.
		body := "4" + digits(14)
		for d := 0; d < 10; d++ {
			if Luhn(body + fmt.Sprint(d)) {
				body += fmt.Sprint(d)
				break
			}
		}
		if repetitive(body) {
			continue
		}
		grouped := body[:4] + " " + body[4:8] + " " + body[8:12] + " " + body[12:]
		if m := find(t, "paid "+grouped, Medium); len(m) != 1 || m[0].ID != "PI003" {
			t.Fatalf("card %s: %+v", grouped, m)
		}
		// DNI.
		n := r.IntN(100000000)
		dni := fmt.Sprintf("%08d%c", n, dniLetters[n%23])
		if m := find(t, "DNI "+dni, Medium); len(m) != 1 || m[0].ID != "PI013" {
			t.Fatalf("DNI %s: %+v", dni, m)
		}
		wrong := fmt.Sprintf("%08d%c", n, dniLetters[(n+1)%23])
		if m := find(t, "DNI "+wrong, Low); len(m) != 0 {
			t.Fatalf("invalid DNI %s found: %+v", wrong, m)
		}
	}
}

func TestRandomDigitRunsRarelyMatchAtMedium(t *testing.T) {
	// The false positive rate on uniformly random 9-19 digit runs, the bulk of what logs hold.
	r := rand.New(rand.NewPCG(3, 5))
	hits, total := 0, 20000
	for i := 0; i < total; i++ {
		var b strings.Builder
		for j := 0; j < 9+r.IntN(11); j++ {
			b.WriteByte(byte('0' + r.IntN(10)))
		}
		if len(Find("id "+b.String()+" ok", Medium)) > 0 {
			hits++
		}
	}
	// Only 15-16 digit runs that start like a card and pass Luhn qualify: well under 1%.
	if rate := float64(hits) / float64(total); rate > 0.01 {
		t.Fatalf("%d of %d random digit runs matched at medium (%.2f%%)", hits, total, 100*rate)
	} else {
		t.Logf("%d of %d random digit runs matched at medium", hits, total)
	}
}

func FuzzFind(f *testing.F) {
	for _, s := range []string{"alice@posteo.de 4532 0151 1283 0366", "DE44 5001 0517 5407 3249 31", "+49 30 12345678",
		"2a00:1450::1", "93.05.18-223.61", "RSSMRA85T10A562S", "\xff\xfe@\x00", strings.Repeat("1 ", 500)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, m := range Find(line, Low) {
			if m.Start < 0 || m.End > len(line) || m.Start >= m.End {
				t.Fatalf("bad span %+v", m)
			}
			raw := strings.ToUpper(stripSeparators(line[m.Start:m.End]))
			if len(raw) > 6 && strings.Contains(strings.ToUpper(m.Masked), raw) {
				t.Fatalf("raw value in mask: %+v", m)
			}
		}
	})
}

// --- rule-by-rule checks found missing by mutation testing ---------------------------------

// steuerCheck computes the ISO 7064 MOD 11,10 check digit, written out separately from the
// validator so the digit-rule tests below can build otherwise-correct numbers.
func steuerCheck(first10 string) string {
	p := 10
	for _, c := range first10 {
		s := (int(c-'0') + p) % 10
		if s == 0 {
			s = 10
		}
		p = s * 2 % 11
	}
	return fmt.Sprint((11 - p) % 10)
}

func TestSteuerIDRulesWithCorrectCheckDigits(t *testing.T) {
	for name, first10 := range map[string]string{
		"leading zero":        "0612345779",
		"no repeated digit":   "1234567890",
		"three in a row":      "1112345678",
		"two repeated digits": "1123345678",
		"a digit four times":  "1213141567",
	} {
		v := first10 + steuerCheck(first10)
		if ValidSteuerID(v) {
			t.Errorf("%s: %s should be invalid", name, v)
		}
	}
	for _, first10 := range []string{"8609574271", "1213456789", "1231456789"} {
		if v := first10 + steuerCheck(first10); !ValidSteuerID(v) {
			t.Errorf("%s should be valid", v)
		}
	}
}

func TestIBANWithTheWrongLengthForItsCountry(t *testing.T) {
	// Check digits by ISO 13616 directly: 98 minus (BBAN, country as digits, "00") mod 97.
	bban := "1234567890123456" // 20 characters with the prefix; Germany has 22
	rem := 0
	for _, c := range bban + "1314" + "00" { // D=13, E=14
		rem = (rem*10 + int(c-'0')) % 97
	}
	short := fmt.Sprintf("DE%02d%s", 98-rem, bban)
	if len(short) != 20 {
		t.Fatal("unexpected length")
	}
	if ValidIBAN(short) {
		t.Fatalf("%s passes mod 97 but is the wrong length", short)
	}
}

func TestNIEWithY(t *testing.T) {
	n := 11234567 // Y counts as 1
	v := fmt.Sprintf("Y1234567%c", dniLetters[n%23])
	if !ValidDNI(v) {
		t.Fatalf("%s should be valid", v)
	}
}

// cfReference uses the ordering of odd-position values as it is usually printed:
// "BAKPLCQDREVOSFTGUHMINJWZYX" lists letters by value 0..25, and digit d counts as letter d.
func cfReference(first15 string) string {
	const oddOrder = "BAKPLCQDREVOSFTGUHMINJWZYX"
	sum := 0
	for i, c := range first15 {
		letter := c
		if c >= '0' && c <= '9' {
			letter = 'A' + (c - '0')
		}
		if i%2 == 0 {
			sum += strings.IndexRune(oddOrder, letter)
		} else {
			sum += int(letter - 'A')
		}
	}
	return first15 + string(rune('A'+sum%26))
}

func TestCodiceFiscaleAgainstAReferenceFormulation(t *testing.T) {
	if got := cfReference("RSSMRA85T10A562"); got != "RSSMRA85T10A562S" {
		t.Fatalf("the reference itself is wrong: %s", got)
	}
	r := rand.New(rand.NewPCG(13, 17))
	letters, digits := "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"
	pick := func(set string) byte { return set[r.IntN(len(set))] }
	for i := 0; i < 2000; i++ {
		b := []byte{pick(letters), pick(letters), pick(letters), pick(letters), pick(letters), pick(letters),
			pick(digits), pick(digits), pick("ABCDEHLMPRST"), pick(digits), pick(digits), pick(letters),
			pick(digits), pick(digits), pick(digits)}
		v := cfReference(string(b))
		if !ValidCodiceFiscale(v) {
			t.Fatalf("%s should be valid", v)
		}
	}
}

func belgianFor(first9 string, from2000 bool) string {
	var n uint64
	fmt.Sscan(first9, &n)
	if from2000 {
		n += 2000000000
	}
	return fmt.Sprintf("%s%02d", first9, 97-n%97)
}

func TestBelgianBisNumbersAndDates(t *testing.T) {
	for _, first9 := range []string{"932518223", "934518223", "930518223"} { // month +20, +40, plain
		if v := belgianFor(first9, false); !ValidBelgianNN(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	if v := belgianFor("931518223", false); ValidBelgianNN(v) { // month 15 is no month
		t.Errorf("%s should be invalid", v)
	}
}

func peselFor(first10 string) string {
	w := []int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	s := 0
	for i, c := range first10 {
		s += int(c-'0') * w[i]
	}
	return first10 + fmt.Sprint((10-s%10)%10)
}

func TestPESELCenturyInTheMonth(t *testing.T) {
	for _, first10 := range []string{"0227080362", "0287080362", "0247080362"} { // 2000s, 1800s, 2100s
		if v := peselFor(first10); !ValidPESEL(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	if v := peselFor("0213080362"); ValidPESEL(v) { // month 13
		t.Errorf("%s should be invalid", v)
	}
}

func TestMoreThingsThatAreNotPersonalData(t *testing.T) {
	for _, line := range []string{
		"see 10.0.0.1, 127.0.0.1, 192.0.2.10, 100.64.1.1 and 2001:db8::1",
		"x := -4532015112830366",
		"ratio 4532015112830366.5",
		"call +49 30 1234",
	} {
		none(t, line, Low)
	}
	if m := one(t, "dmarc-reports@company.eu", Low); m.Confidence != Low {
		t.Fatalf("a DMARC mailbox is a role address: %+v", m)
	}
}

func TestACardWithATwoDigitSuffixIsStillFound(t *testing.T) {
	// The pattern takes all 18 digits here; only cutting at a separator finds the card.
	m := one(t, "card 4532 0151 1283 0366 12", Medium)
	if m.ID != "PI003" || !strings.HasSuffix(m.Masked, "0366") {
		t.Fatalf("%+v", m)
	}
}

func TestTheIBANLengthTestUsesARealCheck(t *testing.T) {
	// The same arithmetic on a full-length German BBAN gives a valid IBAN, so the length rule
	// is the only thing rejecting the short one above.
	bban := "123456789012345678"
	rem := 0
	for _, c := range bban + "1314" + "00" {
		rem = (rem*10 + int(c-'0')) % 97
	}
	if v := fmt.Sprintf("DE%02d%s", 98-rem, bban); !ValidIBAN(v) {
		t.Fatalf("%s should be valid", v)
	}
}

func TestShortAndPlaceholderPhoneNumbers(t *testing.T) {
	// The pattern matches but 7 digits is too short; "order 55021" keeps the line past the prefilter.
	none(t, "dial +1 83 45 67 order 55021", Low)
	none(t, "dial +1 234 567 890 now", Low) // 1234567890: a placeholder, not a number
	if m := one(t, "dial +1 234 567 891 now", Low); m.ID != "PI004" {
		t.Fatalf("%+v", m)
	}
}
