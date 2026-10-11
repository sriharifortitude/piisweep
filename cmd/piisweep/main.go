// Command piisweep finds personal data in logs, exports and test fixtures.
package main

import (
	"os"

	"github.com/sriharifortitude/piisweep/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
