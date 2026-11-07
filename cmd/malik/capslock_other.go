//go:build !windows

package main

// capsLockOn is not detectable from a Unix terminal; the prompt simply shows no warning.
func capsLockOn() bool { return false }
