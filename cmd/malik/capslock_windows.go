//go:build windows

package main

import "syscall"

var procGetKeyState = syscall.NewLazyDLL("user32.dll").NewProc("GetKeyState")

// capsLockOn reports whether Caps Lock is active, so hidden passphrase prompts can warn about it.
func capsLockOn() bool {
	const vkCapital = 0x14
	if procGetKeyState.Find() != nil {
		return false
	}
	r, _, _ := procGetKeyState.Call(vkCapital)
	return r&1 == 1
}
