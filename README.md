# piisweep

[![CI](https://github.com/sriharifortitude/piisweep/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/piisweep/actions/workflows/ci.yml)

Finds personal data in logs, exports and test fixtures: email addresses, IBANs, payment
card numbers, phone numbers, IP addresses, and European national identifiers. Every
candidate is checked against its check digits before it is reported, and the value is
never printed, only a masked form. Go, standard library only, MIT.

## What it is for

Personal data ends up where nobody meant to put it: a debug log that prints the request
body, a CSV export left in a bucket, a fixture copied from production. Under the GDPR each
of those is a copy that needs a lawful basis, a retention period and protection (Article
5(1)(c) and (e), Article 32). A scanner is how you find the copies before an auditor or
an attacker does:

<!-- demo:start -->
```
$ piisweep testdata/app.log
testdata/app.log:2:41  PI001 high   email address  j*******@piisweep-demo.eu
testdata/app.log:3:50  PI003 high   payment card number  ************8306
testdata/app.log:4:40  PI002 high   IBAN  DE21****************70
testdata/app.log:5:36  PI013 high   Spanish identity number (DNI/NIE)  93*****2R
testdata/app.log:6:40  PI012 high   French social security number (NIR)  29***********52
testdata/app.log:7:41  PI004 medium phone number  +33*******34
6 finding(s) in 1 file(s) scanned; 1 well-known test value(s) not counted
      1  PI001 email address
      1  PI002 IBAN
      1  PI003 payment card number
      1  PI004 phone number
      1  PI012 French social security number (NIR)
      1  PI013 Spanish identity number (DNI/NIE)

$ piisweep testdata/app.log --min-confidence low --summary
7 finding(s) in 1 file(s) scanned; 1 well-known test value(s) not counted
      1  PI001 email address
      1  PI002 IBAN
      1  PI003 payment card number
      1  PI004 phone number
      1  PI005 IP address
      1  PI012 French social security number (NIR)
      1  PI013 Spanish identity number (DNI/NIE)
```
<!-- demo:end -->

The fixture's values are generated: a random IBAN and card number with correct check
digits, valid identifiers built from their algorithms, an address on a made-up domain,
and a phone number from the range France reserves for fiction. The private address on
line 1 (`10.20.1.7`) and the sandbox test card on line 8 are not reported, and the order
number on line 9 is not mistaken for anything.

## Usage

```bash
go install github.com/sriharifortitude/piisweep/cmd/piisweep@v0.1.0

piisweep /var/log/app/                     # a directory: recursive; .git and node_modules skipped
kubectl logs deploy/api | piisweep -       # standard input
piisweep exports/ --json > findings.json   # for a pipeline
piisweep . --exclude testdata --exclude '*.min.js' --min-confidence high
```

Exit codes: 0 nothing found, 1 personal data found, 2 a usage error or an unreadable path.
`.gz` files are decompressed; UTF-16 files (with a byte order mark, or recognisable by
their zero bytes) are decoded; a file whose first 8 KiB is more than 1% zero bytes is
treated as binary and listed as skipped.

## What it finds

| ID | Kind | Check | Confidence without / with a keyword on the line |
|---|---|---|---|
| PI001 | email address | shape; reserved and placeholder domains, file names (`icon@2x.png`) excluded | high; role mailboxes (`noreply`, `dmarc…`, `postmaster`) low |
| PI002 | IBAN | per-country length and ISO 13616 mod 97 | high |
| PI003 | payment card number | Luhn, issuer range and length, card-style grouping | grouped high; 15-16 plain digits medium; other plain lengths low / high |
| PI004 | phone number | international `+` form, 9-15 digits | low / medium (`tel`, `phone`, `mobile`, …) |
| PI005 | IP address | public addresses only: private, loopback, documentation and shared ranges excluded | low |
| PI010 | German tax ID (Steuer-ID) | ISO 7064 MOD 11,10 and the digit-repetition rules | low / high |
| PI011 | Dutch BSN | the 11-test | low / high |
| PI012 | French NIR | 97 minus mod 97, Corsica's 2A/2B | high |
| PI013 | Spanish DNI / NIE | the mod 23 letter | medium / high |
| PI014 | Italian codice fiscale | the check letter, omocodia included | high |
| PI015 | Belgian national number | mod 97 with the 2000 rule, a plausible date | separated medium, plain low / high |
| PI016 | Polish PESEL | weighted mod 10 and a birth date with the century in the month | low / high |

Keywords count only as whole words on the same line, so `testing` does not make a number
a "tin". By default matches from medium up are reported; `--min-confidence low` adds the
weak ones (bare 9- and 11-digit numbers that pass a weak check, IP addresses, role
mailboxes) for a full audit. [ADR 1](docs/adr/0001-validate-before-reporting.md) has the
table of how often a random number passes each check, which is where these levels come from.

Example values published by banks, card schemes and standards (`4111 1111 1111 1111`,
`DE89 3704 0044 0532 0130 00`, `RSSMRA85T10A562S`, BSN `111222333` and others) are counted
and not reported, so a codebase's test fixtures do not fail the scan.

## The value is never printed

Output carries only a masked form: the first letter and the domain of an email address,
the country, check digits and last two characters of an IBAN, the last four digits of a
card, the first two octets of an IP address. There is no option to show the value. The
point of the tool is to reduce copies of personal data, and a report full of it would be
one more. A test runs every output mode over a sample and fails if any raw value appears,
and a fuzz target checks that no mask contains the value it masks.
[ADR 2](docs/adr/0002-never-print-the-value.md).

## Tested

```bash
go test ./...                                              # 50 tests and a fuzz target
go test -run '^$' -fuzz FuzzFind ./internal/detect         # the fuzz target on its own
```

**The checks are anchored to published values**, not only to my reading of the
algorithms: the example IBANs banks publish, the Visa and Amex test numbers, BSN 111222333,
DNI 12345678Z, the codice fiscale RSSMRA85T10A562S, PESEL 44051401359, and published
example Steuer-IDs, NIRs and Belgian numbers, twenty in all. For the strong checks, every
single-digit change to each example must fail. The codice fiscale is also checked against
a second formulation of its table, the `BAKPLCQDREVOSFTGUHMINJWZYX` ordering it is usually
printed with, on 2,000 generated codes.

**False positives, measured.**
- 20,000 random digit runs of 9-19 digits: 43 (0.2%) are reported at the default level,
  all card-shaped runs that pass Luhn.
- The Go source tree, 7,768 files and 150 MB of code and tests: 3 card numbers, all 15- or
  16-digit constants in test files, and 290 email addresses, most of them authors' real
  addresses in licence headers, which are personal data. The first version reported 51
  card numbers there; requiring card-style grouping and rejecting the tails of negative
  literals and decimals removed 48 of them.
- My own repositories: the hits were valid IBANs and addresses inside the official UBL
  sample invoices and my own payment-library test vectors, all of which the tool is right
  to point at, and real DMARC reporter mailboxes, which led to treating `noreply…` and
  `…dmarc…` local parts as role addresses.

**Speed.** The Go source tree scans in 11 seconds on the laptop this was built on (about
14 MB/s). The first version took 225 seconds; cheap per-detector preconditions (a digit
count, an `@`, a `+`) now decide which patterns run on a line at all.

**Hostile input.** Fuzzing turned up nothing, but a test written for adversarial lines
did: a 1 MiB line of `1.1.1.1.` took 32 seconds, because overlapping matches were compared
with each other in quadratic time. Overlap is now tracked per byte, and a test checks that
quadrupling seven kinds of adversarial line roughly quadruples the time (it measures about
4x; quadratic would be 16x). Lines over 1 MiB are scanned in 1 MiB pieces, each file is read
up to 1 GiB after decompression (`--max-bytes`), symbolic links are not followed, and a
file that is cut short says so.

**Mutation testing.** I broke the code in 56 places on purpose. On the first run 19 of the
mutants survived and 6 did not compile. The survivors showed whole rules that no test
reached: the Steuer-ID digit rules, IBAN length, the NIE `Y` prefix, the codice fiscale
table, Belgian bis-number months, PESEL's century encoding, private-address exclusion,
and the negative-literal rule. Some tests were also quietly beside the point. The IP
tests ran at a confidence level that filters IP addresses out anyway; the "card followed
by more digits" test passed without the code it was written for, because the pattern
backtracks by itself; and a "leading zero" Steuer-ID broke a different rule as well. Each
now has a test that fails when only that rule is broken. 54 of 56 are caught. The two
left are the digit prefilter, which only affects speed, and the symlink rule, whose test
cannot create symbolic links on the Windows machine this was built on and so runs only
on Linux CI.

**Not tested:** real production logs (I have none I may use); phone numbers written
without the international `+` prefix, which are not looked for at all; national
identifiers of EU countries not in the table; names and postal addresses, which no
check-digit approach can find.

## Limits

- **Not a data-protection assessment.** Finding a value says nothing about whether
  keeping it is lawful. It tells you where to look.
- **Check digits, not truth.** A valid IBAN may be a company's; a valid card number may
  never have been issued. A weak check (11-test, mod 10) passes about one random number in
  ten, which is why those kinds need a keyword to count.
- **Names, addresses and free text are out of scope.** So are photos, voices and
  anything in a binary format other than gzip.
- **One line at a time.** A value split across a line break, or across the 1 MiB piece
  boundary of a very long line, is missed.

## Licence

MIT.
