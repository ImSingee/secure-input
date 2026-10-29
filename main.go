package main

import (
	"fmt"
	"os"
)

const usage = `secure-input — request environment values from a human without
sending them through the AI context.

Usage:
  secure-input serve [--addr :8787]
      Run the server that hosts fill-in forms and stores results in memory.

  secure-input request --server URL --out PATH --reason TEXT
                       [--var KEY[:DESCRIPTION]]... [--public KEY]...
                       [--spec JSON|@FILE] [--no-wait]
      Create a request on the server, print the fill-in URL, wait for the
      user, then write the submitted values to PATH in .env format.
      Values marked private (the default) are masked in the output.

  secure-input pull --server URL --id ID --out PATH [--wait SECONDS]
      Fetch the result of an existing request once. Results are deleted
      from the server on first pull.

Exit codes: 0 submitted, 2 declined, 3 request expired or unknown,
1 usage/network/server error.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "request":
		err = cmdRequest(os.Args[2:])
	case "pull":
		err = cmdPull(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
	if err != nil {
		exit(err)
	}
}

type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string { return e.msg }

func fail(code int, format string, args ...any) *cliError {
	return &cliError{code: code, msg: fmt.Sprintf(format, args...)}
}

func exit(err error) {
	code := 1
	if ce, ok := err.(*cliError); ok {
		code = ce.code
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(code)
}
