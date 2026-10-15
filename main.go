package main

import "C"

// main is required by -buildmode=c-shared; the real entry point is
// klinikal_init (init_linux.go), called from the loader constructor.
func main() {}
