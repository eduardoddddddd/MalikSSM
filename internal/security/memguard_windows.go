//go:build windows

package security

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var domainEntropy = []byte("MalikSSM::HardwareDPAPI::v1::ASUS-Win-Server")

func lockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func unlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

// HardwareProviderName returns a human-readable description of the OS hardware/memory backing.
func HardwareProviderName() string {
	return "Windows DPAPI / TPM 2.0 + Win32 VirtualLock"
}

// ProtectBytesHardware encrypts sensitive bytes (such as the Master KEK on the Servidor Central
// or session.bin on a client workstation) using Windows DPAPI backed by the OS credential
// store and TPM 2.0.
func ProtectBytesHardware(plaintext []byte, extraContext string) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("cannot protect empty payload")
	}

	entropy := append([]byte{}, domainEntropy...)
	if extraContext != "" {
		entropy = append(entropy, []byte("::"+extraContext)...)
	}

	inBlob := windows.DataBlob{
		Size: uint32(len(plaintext)),
		Data: &plaintext[0],
	}
	entropyBlob := windows.DataBlob{
		Size: uint32(len(entropy)),
		Data: &entropy[0],
	}
	var outBlob windows.DataBlob

	err := windows.CryptProtectData(
		&inBlob,
		windows.StringToUTF16Ptr("MalikSSM Protected Secret"),
		&entropyBlob,
		0,
		nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN,
		&outBlob,
	)
	if err != nil {
		return nil, fmt.Errorf("windows DPAPI CryptProtectData failed: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	protected := unsafe.Slice(outBlob.Data, outBlob.Size)
	result := make([]byte, len(protected))
	copy(result, protected)
	return result, nil
}

// UnprotectBytesHardware decrypts bytes previously sealed with ProtectBytesHardware
// on the same Windows machine and user security context.
func UnprotectBytesHardware(ciphertext []byte, extraContext string) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("cannot unprotect empty payload")
	}

	entropy := append([]byte{}, domainEntropy...)
	if extraContext != "" {
		entropy = append(entropy, []byte("::"+extraContext)...)
	}

	inBlob := windows.DataBlob{
		Size: uint32(len(ciphertext)),
		Data: &ciphertext[0],
	}
	entropyBlob := windows.DataBlob{
		Size: uint32(len(entropy)),
		Data: &entropy[0],
	}
	var outBlob windows.DataBlob

	err := windows.CryptUnprotectData(
		&inBlob,
		nil,
		&entropyBlob,
		0,
		nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN,
		&outBlob,
	)
	if err != nil {
		return nil, fmt.Errorf("windows DPAPI CryptUnprotectData failed: %w", err)
	}
	defer func() {
		raw := unsafe.Slice(outBlob.Data, outBlob.Size)
		Zeroize(raw)
		windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))
	}()

	decrypted := unsafe.Slice(outBlob.Data, outBlob.Size)
	result := make([]byte, len(decrypted))
	copy(result, decrypted)
	return result, nil
}
