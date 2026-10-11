package detect

import (
	"strings"
	"testing"
	"time"
)

// Adversarial lines must cost time proportional to their length. Quadrupling a line should
// roughly quadruple the time (linear); sixteen times would be quadratic. The first version
// took 32 seconds on a 1 MiB line of "1.1.1.1." for exactly that reason. The test compares
// ratios rather than absolute times so it holds under -race and on a slow CI runner.
func TestPathologicalLinesScaleLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for name, unit := range map[string]string{
		"digit pairs":  "1 ",
		"digit groups": "4532 ",
		"at signs":     "a@b.",
		"dots":         "1.1.",
		"colons":       "a:b:",
		"pluses":       "+49 ",
		"iban-ish":     "DE44 5001 ",
	} {
		measure := func(bytes int) time.Duration {
			line := strings.Repeat(unit, bytes/len(unit))
			best := time.Duration(1 << 62)
			for i := 0; i < 2; i++ {
				start := time.Now()
				Find(line, Low)
				if d := time.Since(start); d < best {
					best = d
				}
			}
			return best
		}
		small, large := measure(256<<10), measure(1<<20)
		ratio := float64(large) / float64(max(small, time.Millisecond))
		t.Logf("%-12s 256 KiB %v, 1 MiB %v, ratio %.1f", name, small.Round(time.Millisecond), large.Round(time.Millisecond), ratio)
		if ratio > 8 {
			t.Errorf("%s: 4x the input took %.1fx the time; that is not linear", name, ratio)
		}
	}
}
