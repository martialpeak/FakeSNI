package main

import (
	"crypto/rand"
	"encoding/binary"
)

// BuildClientHello constructs a minimal but realistic TLS ClientHello record
// advertising the given SNI. The resulting bytes can be dropped into a raw
// TCP payload. The record is deliberately small and contains only the
// extensions a typical DPI engine needs to match on the SNI.
func BuildClientHello(sni string) []byte {
	var random [32]byte
	_, _ = rand.Read(random[:])
	var sessionID [32]byte
	_, _ = rand.Read(sessionID[:])

	// A handful of common cipher suites (TLS 1.3 + a few ECDHE AEAD ones).
	cipherSuites := []byte{
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
		0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
		0xc0, 0x2b, // ECDHE-ECDSA-AES128-GCM-SHA256
		0xc0, 0x2f, // ECDHE-RSA-AES128-GCM-SHA256
		0xc0, 0x2c, // ECDHE-ECDSA-AES256-GCM-SHA384
		0xc0, 0x30, // ECDHE-RSA-AES256-GCM-SHA384
	}

	// server_name extension (type 0x0000)
	sniBytes := []byte(sni)
	sniExt := make([]byte, 0, len(sniBytes)+9)
	sniExt = append(sniExt, 0x00, 0x00)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniBytes)+5)) // ext_data length
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniBytes)+3)) // server_name_list length
	sniExt = append(sniExt, 0x00)                                           // name_type = host_name
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniBytes)))   // host_name length
	sniExt = append(sniExt, sniBytes...)

	// supported_versions: TLS 1.3, TLS 1.2
	supVer := []byte{0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03}
	// supported_groups: x25519, secp256r1, secp384r1
	supGrp := []byte{0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18}
	// signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
	sigAlg := []byte{0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01}
	// ec_point_formats: uncompressed
	ecPt := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}

	extensions := make([]byte, 0, 64+len(sniExt))
	extensions = append(extensions, sniExt...)
	extensions = append(extensions, supVer...)
	extensions = append(extensions, supGrp...)
	extensions = append(extensions, sigAlg...)
	extensions = append(extensions, ecPt...)

	// ClientHello body
	body := make([]byte, 0, 128+len(extensions))
	body = append(body, 0x03, 0x03) // legacy_version = TLS 1.2
	body = append(body, random[:]...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID[:]...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(cipherSuites)))
	body = append(body, cipherSuites...)
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	// Handshake header: type (1 byte) + length (3 bytes)
	hs := make([]byte, 0, len(body)+4)
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record header
	rec := make([]byte, 0, len(hs)+5)
	rec = append(rec, 0x16)       // content_type = Handshake
	rec = append(rec, 0x03, 0x01) // legacy_record_version = TLS 1.0
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}
