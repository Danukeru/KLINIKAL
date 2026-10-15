// log.go — Diagnostic logging for the socket stack. Provides the LogCall helper
// which prints a timestamped trace line for every socket API invocation, showing
// the function name and its arguments. Used throughout all other files for call
// tracing during development and debugging.

package linuxsock

import (
	"fmt"
	"time"
	"os"
	"strconv"
)

// VERBOSE gates call tracing (KLINIKAL_VERBOSE=1).
var VERBOSE, _ = strconv.ParseBool(os.Getenv("KLINIKAL_VERBOSE"));

// LogCall logs a socket function call with its parameters.
func LogCall(funcName string, args ...interface{}) {
	if(VERBOSE) {
		timestamp := time.Now().Format("15:04:05.000")
		fmt.Printf("[%s] KL CALL: %s(%v)\n", timestamp, funcName, args)
	}
	return
}
