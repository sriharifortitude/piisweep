# 1. Validate before reporting, and say how sure

Status: accepted

## Context

A personal-data scanner that matches patterns alone is unusable on real logs. Every
order number, timestamp and hash is "a long digit run", and a tool that reports
thousands of them gets switched off. Most European identifiers carry check digits,
though, and the strength of those checks varies a great deal:

| Scheme | Check | A random candidate passes |
|---|---|---|
| IBAN | ISO 13616 mod 97, plus a fixed length per country | about 1 in 97, and only at the right length |
| French NIR | 97 minus the number mod 97 | about 1 in 97 |
| Italian codice fiscale | a letter from a weighted sum mod 26, in a rigid letter/digit shape | about 1 in 26, and the shape is rare |
| Spanish DNI/NIE | a letter from the number mod 23 | about 1 in 23 |
| Payment card | Luhn, plus an issuer range and length | about 1 in 10, narrowed by the range |
| German Steuer-ID | ISO 7064 MOD 11,10, plus digit-repetition rules | about 1 in 10, narrowed by the rules |
| Dutch BSN | the 11-test | about 1 in 11 |
| Polish PESEL | weighted mod 10, plus a valid birth date | about 1 in 10, narrowed by the date |
| Belgian national number | 97 minus mod 97 (with a 2000 rule) | about 2 in 97, plus a date shape |

## Decision

- A candidate is reported only if its check passes.
- Each detector gives two confidences: one without and one with a keyword for its kind
  ("iban", "bsn", "pesel", "steuer", "tel", ...) as a whole word on the same line.
  A strong check (IBAN, NIR, codice fiscale) is high on its own. A weak one (BSN,
  Steuer-ID, PESEL, a Belgian number written without separators) is low without a
  keyword and high with one.
- The default report starts at medium. So a bare 9- or 11-digit number that happens to
  pass an 11-test is not reported unless asked for (`--min-confidence low`), while
  `bsn: 268411281` is.
- Where the same characters pass two checks, there is one finding, and the other kind
  is named under "also valid as".

## Consequences

- On uniformly random 9-19-digit runs, 0.2% are reported at medium, and all of them are
  card-shaped 15-16-digit runs that pass Luhn. On the 150 MB Go source tree, 3 numbers
  were reported as card numbers, all of them constants in test files.
- A weak identifier written without its keyword is missed at the default level. That is
  the price of a default anyone will leave switched on. `--min-confidence low` exists
  for an audit.
