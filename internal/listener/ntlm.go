package listener

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

// NTLMSSP message type constants.
const (
	ntlmNegotiate    = 1
	ntlmChallenge    = 2
	ntlmAuthenticate = 3
)

// NTLMSSP negotiate flags.
const (
	ntlmFlagNegotiateUnicode  = 0x00000001
	ntlmFlagNegotiateNTLM     = 0x00000200
	ntlmFlagTargetInfo        = 0x00800000
	ntlmFlagNegotiate128      = 0x20000000
	ntlmFlagNegotiate56       = 0x80000000
	ntlmFlagRequestTarget     = 0x00000004
	ntlmFlagNegotiateSign     = 0x00000010
	ntlmFlagNegotiateSeal     = 0x00000020
	ntlmFlagNTLM2SessionSec   = 0x00080000
	ntlmFlagNegotiateAlwaysSign = 0x00008000
)

var ntlmsspSignature = []byte("NTLMSSP\x00")

// NTLMAuth holds the parsed fields from an NTLMSSP_AUTH (type 3) message.
type NTLMAuth struct {
	Domain      string
	Username    string
	Workstation string
	LMResponse  []byte
	NTResponse  []byte
}

// NTLMHashString formats captured NTLM data into a hashcat-compatible NetNTLMv2 string.
// Format (hashcat mode 5600): username::domain:serverChallenge:ntProofStr:ntBlob
func NTLMHashString(auth *NTLMAuth, serverChallenge []byte) string {
	if len(auth.NTResponse) < 16 {
		return ""
	}

	ntProofStr := hex.EncodeToString(auth.NTResponse[:16])
	ntBlob := hex.EncodeToString(auth.NTResponse[16:])
	challenge := hex.EncodeToString(serverChallenge)

	return fmt.Sprintf("%s::%s:%s:%s:%s",
		auth.Username, auth.Domain, challenge, ntProofStr, ntBlob)
}

// NTLMHashType returns the hash type based on the response lengths.
func NTLMHashType(auth *NTLMAuth) string {
	if len(auth.NTResponse) > 24 {
		return "NetNTLMv2"
	}
	if len(auth.NTResponse) == 24 {
		return "NetNTLMv1"
	}
	return "Unknown"
}

// GenerateServerChallenge creates an 8-byte random challenge.
func GenerateServerChallenge() ([]byte, error) {
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	return challenge, nil
}

// BuildNTLMChallenge constructs an NTLMSSP_CHALLENGE (type 2) message.
func BuildNTLMChallenge(serverChallenge []byte) []byte {
	targetName := encodeUTF16LE("PAPERCUT")
	targetInfo := buildTargetInfo()

	flags := uint32(
		ntlmFlagNegotiateUnicode |
			ntlmFlagNegotiateNTLM |
			ntlmFlagTargetInfo |
			ntlmFlagNegotiate128 |
			ntlmFlagNegotiate56 |
			ntlmFlagRequestTarget |
			ntlmFlagNegotiateAlwaysSign |
			ntlmFlagNTLM2SessionSec)

	// Type 2 message layout:
	// Signature (8) + MessageType (4) + TargetNameFields (8) + NegotiateFlags (4) +
	// ServerChallenge (8) + Reserved (8) + TargetInfoFields (8) + [TargetName] + [TargetInfo]
	headerLen := 8 + 4 + 8 + 4 + 8 + 8 + 8 // = 48

	targetNameOffset := uint32(headerLen)
	targetInfoOffset := targetNameOffset + uint32(len(targetName))

	msg := make([]byte, 0, int(targetInfoOffset)+len(targetInfo))

	// Signature
	msg = append(msg, ntlmsspSignature...)
	// MessageType
	msg = append(msg, le32(ntlmChallenge)...)
	// TargetName fields (Len, MaxLen, Offset)
	msg = append(msg, le16(uint16(len(targetName)))...)
	msg = append(msg, le16(uint16(len(targetName)))...)
	msg = append(msg, le32(targetNameOffset)...)
	// NegotiateFlags
	msg = append(msg, le32(flags)...)
	// ServerChallenge (8 bytes)
	msg = append(msg, serverChallenge...)
	// Reserved (8 bytes)
	msg = append(msg, make([]byte, 8)...)
	// TargetInfo fields (Len, MaxLen, Offset)
	msg = append(msg, le16(uint16(len(targetInfo)))...)
	msg = append(msg, le16(uint16(len(targetInfo)))...)
	msg = append(msg, le32(targetInfoOffset)...)
	// Payload: TargetName + TargetInfo
	msg = append(msg, targetName...)
	msg = append(msg, targetInfo...)

	return msg
}

// ParseNTLMAuth parses an NTLMSSP_AUTH (type 3) message.
func ParseNTLMAuth(data []byte) (*NTLMAuth, error) {
	if len(data) < 88 {
		return nil, fmt.Errorf("NTLMSSP_AUTH too short (%d bytes)", len(data))
	}

	// Verify signature
	if string(data[:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLMSSP signature")
	}

	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != ntlmAuthenticate {
		return nil, fmt.Errorf("expected NTLMSSP_AUTH (3), got %d", msgType)
	}

	// Type 3 layout:
	// Signature(8) + Type(4) + LmResponse(8) + NtResponse(8) + Domain(8) +
	// User(8) + Workstation(8) + EncryptedRandomSessionKey(8) + Flags(4)
	auth := &NTLMAuth{}

	// LM Response (offset 12)
	auth.LMResponse = readSecurityBuffer(data, 12)

	// NT Response (offset 20)
	auth.NTResponse = readSecurityBuffer(data, 20)

	// Domain (offset 28) - UTF-16LE
	domainBytes := readSecurityBuffer(data, 28)
	auth.Domain = decodeUTF16LE(domainBytes)

	// Username (offset 36) - UTF-16LE
	userBytes := readSecurityBuffer(data, 36)
	auth.Username = decodeUTF16LE(userBytes)

	// Workstation (offset 44) - UTF-16LE
	wsBytes := readSecurityBuffer(data, 44)
	auth.Workstation = decodeUTF16LE(wsBytes)

	return auth, nil
}

// ParseNTLMType returns the NTLMSSP message type from a raw message.
// Returns 0 if the data is not a valid NTLMSSP message.
func ParseNTLMType(data []byte) int {
	if len(data) < 12 {
		return 0
	}
	if string(data[:8]) != "NTLMSSP\x00" {
		return 0
	}
	return int(binary.LittleEndian.Uint32(data[8:12]))
}

// readSecurityBuffer reads a security buffer (Len/MaxLen/Offset) from the NTLMSSP message.
func readSecurityBuffer(data []byte, offset int) []byte {
	if offset+8 > len(data) {
		return nil
	}

	bufLen := int(binary.LittleEndian.Uint16(data[offset:]))
	bufOffset := int(binary.LittleEndian.Uint32(data[offset+4:]))

	if bufOffset+bufLen > len(data) || bufLen == 0 {
		return nil
	}

	return data[bufOffset : bufOffset+bufLen]
}

// buildTargetInfo builds a minimal AV_PAIR target info structure.
func buildTargetInfo() []byte {
	var info []byte
	// MsvAvNbDomainName (type 2)
	info = append(info, avPair(2, encodeUTF16LE("PAPERCUT"))...)
	// MsvAvNbComputerName (type 1)
	info = append(info, avPair(1, encodeUTF16LE("PAPERCUT"))...)
	// MsvAvDnsDomainName (type 4)
	info = append(info, avPair(4, encodeUTF16LE("papercut.local"))...)
	// MsvAvDnsComputerName (type 3)
	info = append(info, avPair(3, encodeUTF16LE("papercut.local"))...)
	// MsvAvEOL (type 0)
	info = append(info, le16(0)...)
	info = append(info, le16(0)...)
	return info
}

// avPair builds a single AV_PAIR: type(2) + length(2) + value
func avPair(avID uint16, value []byte) []byte {
	pair := le16(avID)
	pair = append(pair, le16(uint16(len(value)))...)
	pair = append(pair, value...)
	return pair
}

// encodeUTF16LE encodes a Go string to UTF-16LE bytes.
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// decodeUTF16LE decodes UTF-16LE bytes to a Go string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return strings.TrimRight(string(utf16.Decode(u16s)), "\x00")
}

// le16 encodes a uint16 as little-endian bytes.
func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// le32 encodes a uint32 as little-endian bytes.
func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
