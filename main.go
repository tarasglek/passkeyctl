// Command passkeyctl is a software passkey for testing WebAuthn flows: it
// turns server options JSON on stdin into PublicKeyCredential JSON on stdout.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

const usage = "usage: passkeyctl attest|assert --cred FILE --origin URL < options.json"

const (
	exitUsage    = 1
	exitOptions  = 2
	exitRefused  = 3
	exitCredFile = 4
)

// exitError carries the process exit code for a failure.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, msg: fmt.Sprintf(format, args...)}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	output, err := execute(args, stdin)
	if err != nil {
		code := exitUsage
		var exit *exitError
		if errors.As(err, &exit) {
			code = exit.code
		}
		fmt.Fprintf(stderr, "passkeyctl: %v\n", err)
		return code
	}
	if _, err := stdout.Write(append(output, '\n')); err != nil {
		fmt.Fprintf(stderr, "passkeyctl: write output: %v\n", err)
		return exitUsage
	}
	return 0
}

func execute(args []string, stdin io.Reader) ([]byte, error) {
	if len(args) == 0 || (args[0] != "attest" && args[0] != "assert") {
		return nil, fail(exitUsage, usage)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	credPath := flags.String("cred", "", "credential file")
	originFlag := flags.String("origin", "", "origin the browser would report")
	if err := flags.Parse(args[1:]); err != nil || *credPath == "" ||
		*originFlag == "" || flags.NArg() != 0 {
		return nil, fail(exitUsage, usage)
	}
	origin, host, err := parseOrigin(*originFlag)
	if err != nil {
		return nil, err
	}
	options, err := readOptions(stdin)
	if err != nil {
		return nil, err
	}
	if args[0] == "attest" {
		return attest(*credPath, origin, host, options)
	}
	return assert(*credPath, origin, host, options)
}

// parseOrigin accepts an https origin, or http on a loopback host, and returns
// the origin as a browser would report it and its host name.
func parseOrigin(value string) (string, string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		u.ForceQuery {
		return "", "", fail(exitUsage, "--origin must look like https://host[:port]")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if u.Scheme != "https" &&
		!(u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback()))) {
		return "", "", fail(exitUsage, "--origin must use https, or http on a loopback host")
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), host, nil
}

// resolveRPID defaults the RP ID to the origin host and otherwise requires it
// to be the host or, for a domain name, one of its parent domains.
func resolveRPID(rpID, host string) (string, error) {
	switch {
	case rpID == "":
		return host, nil
	case rpID == host, net.ParseIP(host) == nil && strings.HasSuffix(host, "."+rpID):
		return rpID, nil
	}
	return "", fail(exitRefused, "RP ID %q does not match origin host %q", rpID, host)
}
