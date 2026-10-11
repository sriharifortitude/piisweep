# 2. Never print the value

Status: accepted

## Context

A scanner for personal data produces a list of where personal data is. If that list
holds the values themselves, it is a second copy of the data, often pasted into a CI log,
a ticket or a chat, which is worse than the original.

## Decision

The raw value never leaves the detector. A match carries only a masked form: the domain
and first letter of an email address, the country and check digits plus the last two
characters of an IBAN, the last four digits of a card (what PCI DSS allows on a receipt),
the first two octets of an IP address, and two characters at each end of an
identifier. There is no flag to turn masking off. Someone who needs the value has the
file and the line and column.

## Consequences

- A test runs every output mode (text, JSON, summary, low confidence) over a sample and
  fails if any raw value appears. A fuzz target checks that no mask contains the
  normalised value it was made from.
- Two findings with the same mask can be different values. Counting distinct people is
  not a goal of this tool.
