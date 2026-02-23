// log.go — Diagnostic logging for the Winsock bridge. Provides the LogCall helper
// which prints a timestamped trace line for every Winsock API invocation, showing
// the function name and its arguments. Used throughout all other files for call
// tracing during development and debugging.

package winsock

import (
	"fmt"
	"time"
	"os"
	"strconv"
)

var VERBOSE, _ = strconv.ParseBool(os.Getenv("KLINIKAL_VERBOSE"));

// LogCall logs a Winsock function call with its parameters.
func LogCall(funcName string, args ...interface{}) {
	if(VERBOSE) {
		timestamp := time.Now().Format("15:04:05.000")
		fmt.Printf("[%s] WINSOCK CALL: %s(%v)\n", timestamp, funcName, args)
	}
	return
}
