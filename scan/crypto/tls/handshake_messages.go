// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"reflect"
)

type clientHelloMsg struct {
	raw                 []byte
	vers                uint16
	random              []byte
	sessionId           []byte
	cipherSuites        []uint16
	compressionMethods  []uint8
	nextProtoNeg        bool
	serverName          string
	ocspStapling        bool
	scts                bool
	supportedCurves     []CurveID
	supportedPoints     []uint8
	ticketSupported     bool
	sessionTicket       []uint8
	signatureAndHashes  []signatureAndHash
	secureRenegotiation bool
	alpnProtocols       []string

	// lbarman: fields for TLS1.3
	supportedVersions                []uint16
	supportedSignatureAlgorithmsCert []signatureAndHash
	// lbarman: TODO check inconsistency: do we want "hasCookie", "hasKeyShare" like we have "ticketSupported" ?
	cookie        []byte
	keyShares     []keyShare
	earlyData     bool //requires pre_shared_key too, see RFC 8446 section 4.2.10
	pskModes      []uint8
	pskIdentities []pskIdentity
	pskBinders    [][]byte
}

func (m *clientHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		eqUint16s(m.cipherSuites, m1.cipherSuites) &&
		bytes.Equal(m.compressionMethods, m1.compressionMethods) &&
		m.nextProtoNeg == m1.nextProtoNeg &&
		m.serverName == m1.serverName &&
		m.ocspStapling == m1.ocspStapling &&
		m.scts == m1.scts &&
		eqCurveIDs(m.supportedCurves, m1.supportedCurves) &&
		bytes.Equal(m.supportedPoints, m1.supportedPoints) &&
		m.ticketSupported == m1.ticketSupported &&
		bytes.Equal(m.sessionTicket, m1.sessionTicket) &&
		eqSignatureAndHashes(m.signatureAndHashes, m1.signatureAndHashes) &&
		m.secureRenegotiation == m1.secureRenegotiation &&
		eqStrings(m.alpnProtocols, m1.alpnProtocols) &&
		eqUint16s(m.supportedVersions, m1.supportedVersions) &&
		eqSignatureAndHashes(m.supportedSignatureAlgorithmsCert, m1.supportedSignatureAlgorithmsCert) &&
		bytes.Equal(m.cookie, m1.cookie) &&
		eqKeyShares(m.keyShares, m1.keyShares) &&
		m.earlyData == m1.earlyData &&
		eqUint8s(m.pskModes, m1.pskModes) &&
		eqPskIdentity(m.pskIdentities, m1.pskIdentities) &&
		// lbarman: TODO check: do we want to avoid reflect ? If not, couldn't we simply DeepEqual(m,m1) ?
		reflect.DeepEqual(m.pskBinders, m1.pskBinders)
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 2 + len(m.cipherSuites)*2 + 1 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0
	if m.nextProtoNeg {
		numExtensions++
	}
	if m.ocspStapling {
		extensionsLength += 1 + 2 + 2
		numExtensions++
	}
	if len(m.serverName) > 0 {
		extensionsLength += 5 + len(m.serverName)
		numExtensions++
	}
	if len(m.supportedCurves) > 0 {
		extensionsLength += 2 + 2*len(m.supportedCurves)
		numExtensions++
	}
	if len(m.supportedPoints) > 0 {
		extensionsLength += 1 + len(m.supportedPoints)
		numExtensions++
	}
	if m.ticketSupported {
		extensionsLength += len(m.sessionTicket)
		numExtensions++
	}
	if len(m.signatureAndHashes) > 0 {
		extensionsLength += 2 + 2*len(m.signatureAndHashes)
		numExtensions++
	}
	if m.secureRenegotiation {
		extensionsLength += 1
		numExtensions++
	}
	if len(m.alpnProtocols) > 0 {
		extensionsLength += 2
		for _, s := range m.alpnProtocols {
			if l := len(s); l == 0 || l > 255 {
				panic("invalid ALPN protocol")
			}
			extensionsLength++
			extensionsLength += len(s)
		}
		numExtensions++
	}
	if m.scts {
		numExtensions++
	}

	if m.supportedSignatureAlgorithmsCert != nil && len(m.supportedSignatureAlgorithmsCert) > 0 {
		extensionsLength += 2 + 2*len(m.supportedSignatureAlgorithmsCert) // uint16 size + uint16 for each algo
		numExtensions++
	}

	if m.supportedVersions != nil && len(m.supportedVersions) > 0 {
		extensionsLength += 1 + 2*len(m.supportedVersions) // uint8 size + uint16 for each version
		numExtensions++
	}

	if m.cookie != nil {
		extensionsLength += 2 + len(m.cookie) // payload prefixed with uint16 size
		numExtensions++
	}

	if m.keyShares != nil && len(m.keyShares) > 0 {
		extensionsLength += 2
		for _, keyShare := range m.keyShares {
			extensionsLength += 2 + 2 + len(keyShare.data) // uint16 for keyShare.group + for size of keyShare.data
		}
		numExtensions++
	}

	if m.earlyData {
		// RFC 8446, Section 4.2.10
		extensionsLength += 0 // this extension has no payload
		numExtensions++
	}

	if m.pskModes != nil && len(m.pskModes) > 0 {
		extensionsLength += 1 * len(m.pskModes) // uint8 for size + uint8 per mode
		numExtensions++
	}

	if m.pskIdentities != nil && len(m.pskIdentities) > 0 {
		extensionsLength += 2 // uint16 size of the data in the following loop
		for _, psk := range m.pskIdentities {
			extensionsLength += 2 + len(psk.label) + 4 // uint16 size + data + uint32 ticket
		}
		extensionsLength += 2 // uint16 size of the data in the following loop
		for _, binder := range m.pskBinders {
			extensionsLength += 1 + len(binder) // uint8 size + data
		}
		numExtensions++
	}

	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	y := x[39+len(m.sessionId):]
	y[0] = uint8(len(m.cipherSuites) >> 7)
	y[1] = uint8(len(m.cipherSuites) << 1)
	for i, suite := range m.cipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.cipherSuites)*2:]
	z[0] = uint8(len(m.compressionMethods))
	copy(z[1:], m.compressionMethods)

	z = z[1+len(m.compressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		// The length is always 0
		z = z[4:]
	}
	if len(m.serverName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName & 0xff)
		l := len(m.serverName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		z[0] = byte((len(m.serverName) + 3) >> 8)
		z[1] = byte(len(m.serverName) + 3)
		z[3] = byte(len(m.serverName) >> 8)
		z[4] = byte(len(m.serverName))
		copy(z[5:], []byte(m.serverName))
		z = z[l:]
	}
	if m.ocspStapling {
		// RFC 4366, section 3.6
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z[2] = 0
		z[3] = 5
		z[4] = 1 // OCSP type
		// Two zero valued uint16s for the two lengths.
		z = z[9:]
	}
	if len(m.supportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.1
		z[0] = byte(extensionSupportedCurves >> 8)
		z[1] = byte(extensionSupportedCurves)
		l := 2 + 2*len(m.supportedCurves)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		z = z[6:]
		for _, curve := range m.supportedCurves {
			z[0] = byte(curve >> 8)
			z[1] = byte(curve)
			z = z[2:]
		}
	}
	if len(m.supportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.2
		z[0] = byte(extensionSupportedPoints >> 8)
		z[1] = byte(extensionSupportedPoints)
		l := 1 + len(m.supportedPoints)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l--
		z[4] = byte(l)
		z = z[5:]
		for _, pointFormat := range m.supportedPoints {
			z[0] = byte(pointFormat)
			z = z[1:]
		}
	}
	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.sessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.sessionTicket)
		z = z[len(m.sessionTicket):]
	}
	if len(m.signatureAndHashes) > 0 {
		// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		z[0] = byte(extensionSignatureAlgorithms >> 8)
		z[1] = byte(extensionSignatureAlgorithms)
		l := 2 + 2*len(m.signatureAndHashes)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		z = z[2:]
		for _, sigAndHash := range m.signatureAndHashes {
			z[0] = sigAndHash.hash
			z[1] = sigAndHash.signature
			z = z[2:]
		}
	}

	if m.secureRenegotiation {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = 1
		z = z[5:]
	}
	if len(m.alpnProtocols) > 0 {
		// lbarman: RFC 7301, Section 3.1
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		lengths := z[2:]
		z = z[6:]

		stringsLength := 0
		for _, s := range m.alpnProtocols {
			l := len(s)
			z[0] = byte(l)
			copy(z[1:], s)
			z = z[1+l:]
			stringsLength += 1 + l
		}

		lengths[2] = byte(stringsLength >> 8)
		lengths[3] = byte(stringsLength)
		stringsLength += 2
		lengths[0] = byte(stringsLength >> 8)
		lengths[1] = byte(stringsLength)
	}
	if m.scts {
		// https://tools.ietf.org/html/rfc6962#section-3.3.1
		z[0] = byte(extensionSCT >> 8)
		z[1] = byte(extensionSCT)
		// zero uint16 for the zero-length extension_data
		z = z[4:]
	}

	if m.supportedSignatureAlgorithmsCert != nil && len(m.supportedSignatureAlgorithmsCert) > 0 {
		// RFC 8446, Section 4.2.3
		z[0] = byte(extensionSignatureAlgorithmsCert >> 8)
		z[1] = byte(extensionSignatureAlgorithmsCert)
		l := 2 + 2*len(m.supportedSignatureAlgorithmsCert)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		z = z[2:]
		for _, sigAndHash := range m.supportedSignatureAlgorithmsCert {
			z[0] = sigAndHash.hash // lbarman: TODO check that this is not swapped. Tied to line 720
			z[1] = sigAndHash.signature
			z = z[2:]
		}
	}

	if m.supportedVersions != nil && len(m.supportedVersions) > 0 {
		z[0] = byte(extensionSupportedVersions >> 8)
		z[1] = byte(extensionSupportedVersions)
		l := 1 + 2*len(m.supportedVersions)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l--
		z[0] = byte(l)
		z = z[1:]
		for _, version := range m.supportedVersions {
			z[0] = byte(version >> 8)
			z[1] = byte(version)
			z = z[2:]
		}
	}

	if m.cookie != nil {
		// RFC 8446, Section 4.2.2
		z[0] = byte(extensionCookie >> 8)
		z[1] = byte(extensionCookie)
		l := 2 + len(m.cookie)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		z = z[2:]
		copy(z[0:], m.cookie)
		z = z[len(m.cookie):]
	}

	if m.keyShares != nil && len(m.keyShares) > 0 {
		// RFC 8446, Section 4.2.3
		z[0] = byte(extensionKeyShare >> 8)
		z[1] = byte(extensionKeyShare)
		l := 2
		for _, keyShare := range m.keyShares {
			l += 2 + 2 + len(keyShare.data) // uint16 for keyShare.group + for size of keyShare.data
		}
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		z = z[2:]
		for _, keyShare := range m.keyShares {
			z[0] = byte(uint16(keyShare.group) >> 8)
			z[1] = byte(uint16(keyShare.group))
			z[2] = byte(len(keyShare.data) >> 8)
			z[3] = byte(len(keyShare.data))
			z = z[4:]
			copy(z[0:], keyShare.data)
			z = z[len(keyShare.data):]
		}
	}

	if m.earlyData {
		// RFC 8446, Section 4.2.10
		z[0] = byte(extensionEarlyData >> 8)
		z[1] = byte(extensionEarlyData)
		z[2] = 0
		z[3] = 0
		z = z[4:]
	}

	if m.pskModes != nil && len(m.pskModes) > 0 {
		// RFC 8446, Section 4.2.9
		z[0] = byte(extensionPSKModes >> 8)
		z[1] = byte(extensionPSKModes)
		l := 1 + len(m.pskModes)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l--
		z[0] = byte(l)
		z = z[1:]

		for _, pskMode := range m.pskModes {
			z[0] = pskMode
			z = z[1:]
		}
	}

	// pre_shared_key must be the last extension
	if m.pskIdentities != nil && len(m.pskIdentities) > 0 {
		// RFC 8446, Section 4.2.11
		z[0] = byte(extensionPreSharedKey >> 8)
		z[1] = byte(extensionPreSharedKey)

		lengthIdentities := 0
		for _, psk := range m.pskIdentities {
			lengthIdentities += 2 + len(psk.label) + 4 // uint16 size + data + uint32 ticket
		}
		lengthBinders := 0
		for _, binder := range m.pskBinders {
			lengthBinders += 1 + len(binder) // uint8 size + data
		}
		l := 2 + lengthIdentities + 2 + lengthBinders

		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		z[0] = byte(lengthIdentities >> 8)
		z[1] = byte(lengthIdentities)
		z = z[2:]
		for _, psk := range m.pskIdentities {
			z[0] = byte((len(psk.label) >> 8) & 0xFF)
			z[1] = byte(len(psk.label) & 0xFF)
			z = z[2:]
			copy(z[0:], psk.label)
			z = z[len(psk.label):]

			// lbarman: TODO check 0xFF might not be needed since ticketAge is uint
			z[0] = byte((psk.obfuscatedTicketAge >> 24) & 0xFF)
			z[1] = byte((psk.obfuscatedTicketAge >> 16) & 0xFF)
			z[2] = byte((psk.obfuscatedTicketAge >> 8) & 0xFF)
			z[3] = byte(psk.obfuscatedTicketAge & 0xFF)
			z = z[4:]
		}

		z[0] = byte(lengthBinders >> 8)
		z[1] = byte(lengthBinders)
		z = z[2:]
		for _, binder := range m.pskBinders {
			z[0] = byte(len(binder))
			z = z[1:]
			copy(z[0:], binder)
			z = z[len(binder):]
		}
	}

	m.raw = x

	return x
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.cipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
		if m.cipherSuites[i] == scsvRenegotiation {
			m.secureRenegotiation = true
		}
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.signatureAndHashes = nil
	m.alpnProtocols = nil
	m.scts = false

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionServerName:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return false
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.serverName = string(d[:nameLen])
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			if length > 0 {
				return false
			}
			m.nextProtoNeg = true
		case extensionStatusRequest:
			m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l%2 == 1 || length != l+2 {
				return false
			}
			numCurves := l / 2
			m.supportedCurves = make([]CurveID, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
				d = d[2:]
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return false
			}
			l := int(data[0])
			if length != l+1 {
				return false
			}
			m.supportedPoints = make([]uint8, l)
			copy(m.supportedPoints, data[1:])
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.ticketSupported = true
			m.sessionTicket = data[:length]
		case extensionSignatureAlgorithms:
			// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			if length < 2 || length&1 != 0 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			n := l / 2
			d := data[2:]
			m.signatureAndHashes = make([]signatureAndHash, n)
			for i := range m.signatureAndHashes {
				m.signatureAndHashes[i].hash = d[0]
				m.signatureAndHashes[i].signature = d[1]
				d = d[2:]
			}
		case extensionRenegotiationInfo:
			if length != 1 || data[0] != 0 {
				return false
			}
			m.secureRenegotiation = true
		case extensionALPN:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(d[:stringLen]))
				d = d[stringLen:]
			}
		case extensionSCT:
			m.scts = true
			if length != 0 {
				return false
			}
		case extensionSignatureAlgorithmsCert:
			if length < 2 || length&1 != 0 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			n := l / 2
			d := data[2:]
			m.supportedSignatureAlgorithmsCert = make([]signatureAndHash, n)
			for i := range m.supportedSignatureAlgorithmsCert {
				m.supportedSignatureAlgorithmsCert[i].hash = d[0]
				m.supportedSignatureAlgorithmsCert[i].signature = d[1]
				d = d[2:]
			}
		case extensionSupportedVersions:
			if length < 1 || length&1 != 1 {
				return false
			}
			l := int(data[0])
			if l != length-1 {
				return false
			}
			n := l / 2
			d := data[1:]
			m.supportedVersions = make([]uint16, n)
			for i := range m.supportedVersions {
				m.supportedVersions[i] = uint16(d[0])<<8 | uint16(d[1])
				d = d[2:]
			}
		case extensionCookie:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:]
			m.cookie = make([]byte, l)
			copy(m.cookie[0:], d[0:l])
			d = d[l:]
		case extensionKeyShare:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			keySharesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			m.keyShares = make([]keyShare, 0)
			if len(d) != keySharesLen {
				return false
			}
			for len(d) > 0 {
				if len(d) < 2 {
					return false
				}
				keyShareGroup := CurveID(d[0])<<8 | CurveID(d[1])
				keyShareDataLen := int(d[2])<<8 | int(d[3])
				d = d[4:]
				keyShare := keyShare{
					group: keyShareGroup,
					data:  make([]byte, keyShareDataLen),
				}
				if len(d) < keyShareDataLen {
					return false
				}
				copy(keyShare.data[0:], d[0:keyShareDataLen])
				m.keyShares = append(m.keyShares, keyShare)

				d = d[keyShareDataLen:]
			}
		case extensionEarlyData:
			m.earlyData = true
		case extensionPSKModes:
			if length < 1 || length&1 != 1 {
				return false
			}
			l := int(data[0])
			if l != length-1 {
				return false
			}
			n := l / 2
			d := data[1:]
			m.pskModes = make([]uint8, n)
			for i := range m.pskModes {
				m.pskModes[i] = d[0]
				d = d[1:]
			}
		case extensionPreSharedKey:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			// lbarman: split between the ids and the binders
			lengthIdentities := int(d[0])<<8 | int(d[1])
			d_ids := d[2:]
			if len(d_ids) < lengthIdentities {
				return false
			}
			d_ids = d_ids[0:lengthIdentities]

			d_binders_with_size := d[2+lengthIdentities:]
			if len(d_binders_with_size) < 2 {
				return false
			}
			lengthBinders := int(d_binders_with_size[0])<<8 | int(d_binders_with_size[1])
			d_binders := d_binders_with_size[2:]
			if len(d_binders) < lengthBinders {
				return false
			}
			d_binders = d_binders[0:lengthBinders]

			// lbarman parse identities
			m.pskIdentities = make([]pskIdentity, 0)
			for len(d_ids) > 0 {
				if len(d_ids) < 2 {
					return false
				}
				labelLength := int(d_ids[0])<<8 | int(d_ids[1])
				d_ids = d_ids[2:]
				label := make([]byte, labelLength)
				if len(d) < labelLength {
					return false
				}
				copy(label[0:], d_ids[0:labelLength])
				d_ids = d_ids[labelLength:]
				obfuscatedTicketAge := uint32(d_ids[0])<<24 | uint32(d_ids[1])<<16 | uint32(d_ids[2])<<8 | uint32(d_ids[3])

				pskIdentity := pskIdentity{
					label,
					obfuscatedTicketAge,
				}

				m.pskIdentities = append(m.pskIdentities, pskIdentity)

				d_ids = d_ids[4:]
			}

			// lbarman parse binders
			m.pskBinders = make([][]byte, 0)
			for len(d_binders) > 0 {
				if len(d_binders) < 1 {
					return false
				}
				binderLength := int(d_binders[0])
				d_binders = d_binders[1:]
				binder := make([]byte, binderLength)
				if len(d_binders) < binderLength {
					return false
				}
				copy(binder[0:], d[0:binderLength])

				m.pskBinders = append(m.pskBinders, binder)
				d_binders = d_binders[binderLength:]
			}

		}

		data = data[length:]
	}

	return true
}

type serverHelloMsg struct {
	raw                 []byte
	vers                uint16
	random              []byte
	sessionId           []byte
	cipherSuite         uint16
	compressionMethod   uint8
	nextProtoNeg        bool
	nextProtos          []string
	ocspStapling        bool
	scts                [][]byte
	ticketSupported     bool
	secureRenegotiation bool
	// lbarman: TODO check why we don't need secureRenegotiation []byte
	alpnProtocol string

	// lbarman: fields for TLS1.3
	supportedVersion        uint16
	serverShare             keyShare
	selectedIdentityPresent bool
	selectedIdentity        uint16
	cookie                  []byte
	selectedGroup           CurveID
}

func (m *serverHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverHelloMsg)
	if !ok {
		return false
	}

	if len(m.scts) != len(m1.scts) {
		return false
	}
	for i, sct := range m.scts {
		if !bytes.Equal(sct, m1.scts[i]) {
			return false
		}
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		m.cipherSuite == m1.cipherSuite &&
		m.compressionMethod == m1.compressionMethod &&
		m.nextProtoNeg == m1.nextProtoNeg &&
		eqStrings(m.nextProtos, m1.nextProtos) &&
		m.ocspStapling == m1.ocspStapling &&
		m.ticketSupported == m1.ticketSupported &&
		m.secureRenegotiation == m1.secureRenegotiation &&
		m.alpnProtocol == m1.alpnProtocol &&
		m.supportedVersion == m1.supportedVersion &&
		eqKeyShare(m.serverShare, m1.serverShare) &&
		m.selectedIdentityPresent == m1.selectedIdentityPresent &&
		m.selectedIdentity == m1.selectedIdentity &&
		bytes.Equal(m.cookie, m1.cookie) &&
		m.selectedGroup == m1.selectedGroup
}

func (m *serverHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 38 + len(m.sessionId)
	numExtensions := 0
	extensionsLength := 0

	nextProtoLen := 0
	if m.nextProtoNeg {
		numExtensions++
		for _, v := range m.nextProtos {
			nextProtoLen += len(v)
		}
		nextProtoLen += len(m.nextProtos)
		extensionsLength += nextProtoLen
	}
	if m.ocspStapling {
		numExtensions++
	}
	if m.ticketSupported {
		numExtensions++
	}
	if m.secureRenegotiation {
		extensionsLength += 1
		numExtensions++
	}
	if alpnLen := len(m.alpnProtocol); alpnLen > 0 {
		if alpnLen >= 256 {
			panic("invalid ALPN protocol")
		}
		extensionsLength += 2 + 1 + alpnLen
		numExtensions++
	}
	sctLen := 0
	if len(m.scts) > 0 {
		for _, sct := range m.scts {
			sctLen += len(sct) + 2
		}
		extensionsLength += 2 + sctLen
		numExtensions++
	}
	// lbarman: this is mandatory in TLS 1.3, we should even remove the condition, it is kept for now if we want to explicitely do TLS 1.2
	if m.supportedVersion != 0 {
		extensionsLength += 2
		numExtensions++
	}
	if m.serverShare.group != 0 {
		extensionsLength += 2 + 2 + len(m.serverShare.data) // uint16 for group + size of data
		numExtensions++
	}
	if m.selectedIdentityPresent {
		extensionsLength += 2
		numExtensions++
	}
	if m.cookie != nil {
		extensionsLength += 2 + len(m.cookie) // payload prefixed with uint16 size
		numExtensions++
	}
	if m.selectedGroup != 0 {
		extensionsLength += 2
		numExtensions++
	}

	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeServerHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	z := x[39+len(m.sessionId):]
	z[0] = uint8(m.cipherSuite >> 8)
	z[1] = uint8(m.cipherSuite)
	z[2] = uint8(m.compressionMethod)

	z = z[3:]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		z[2] = byte(nextProtoLen >> 8)
		z[3] = byte(nextProtoLen)
		z = z[4:]

		for _, v := range m.nextProtos {
			l := len(v)
			if l > 255 {
				l = 255
			}
			z[0] = byte(l)
			copy(z[1:], []byte(v[0:l]))
			z = z[1+l:]
		}
	}
	if m.ocspStapling {
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z = z[4:]
	}
	if m.ticketSupported {
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		z = z[4:]
	}
	if m.secureRenegotiation {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = 1
		z = z[5:]
		// lbarman: TODO reference implementation actually sends some value here, not just a flag. Check
	}
	if alpnLen := len(m.alpnProtocol); alpnLen > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		l := 2 + 1 + alpnLen
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		l -= 1
		z[6] = byte(l)
		copy(z[7:], []byte(m.alpnProtocol))
		z = z[7+alpnLen:]
	}
	if sctLen > 0 {
		z[0] = byte(extensionSCT >> 8)
		z[1] = byte(extensionSCT)
		l := sctLen + 2
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z[4] = byte(sctLen >> 8)
		z[5] = byte(sctLen)

		z = z[6:]
		for _, sct := range m.scts {
			z[0] = byte(len(sct) >> 8)
			z[1] = byte(len(sct))
			copy(z[2:], sct)
			z = z[len(sct)+2:]
		}
	}
	// lbarman: this is mandatory in TLS 1.3, we should even remove the condition, it is kept for now if we want to explicitely do TLS 1.2
	if m.supportedVersion != 0 {
		z[0] = byte(extensionSupportedVersions >> 8)
		z[1] = byte(extensionSupportedVersions)
		z[2] = 0
		z[3] = 2
		z[4] = uint8(m.supportedVersion >> 8)
		z[5] = uint8(m.supportedVersion)
		z = z[6:]
	}
	if m.serverShare.group != 0 {
		extensionsLength += 2 + 2 + len(m.serverShare.data) // uint16 for group + size of data

		z[0] = byte(extensionKeyShare >> 8)
		z[1] = byte(extensionKeyShare)
		l := 2 + 2 + len(m.serverShare.data)
		z[2] = byte(l >> 8)
		z[3] = byte(l)

		z[4] = byte(m.serverShare.group >> 8)
		z[5] = byte(m.serverShare.group)

		l -= 2
		z[6] = byte(l >> 8)
		z[7] = byte(l)

		copy(z[8:], []byte(m.serverShare.data))
		z = z[8+len(m.serverShare.data):]
	}
	if m.selectedIdentityPresent {
		z[0] = byte(extensionPreSharedKey >> 8)
		z[1] = byte(extensionPreSharedKey)
		z[2] = 0
		z[3] = 2
		z[4] = uint8(m.selectedIdentity >> 8)
		z[5] = uint8(m.selectedIdentity)
		z = z[6:]
	}
	if m.cookie != nil {
		z[0] = byte(extensionCookie >> 8)
		z[1] = byte(extensionCookie)
		l := 2 + len(m.cookie)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		copy(z[2:], m.cookie)
		z = z[2+len(m.cookie):]
	}
	if m.selectedGroup != 0 {
		z[0] = byte(extensionKeyShare >> 8)
		z[1] = byte(extensionKeyShare)
		z[2] = 0
		z[3] = 2
		z[4] = uint8(m.selectedGroup >> 8)
		z[5] = uint8(m.selectedGroup)
		z = z[6:]
	}

	m.raw = x

	return x
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 3 {
		return false
	}
	m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.compressionMethod = data[2]
	data = data[3:]

	m.nextProtoNeg = false
	m.nextProtos = nil
	m.ocspStapling = false
	m.scts = nil
	m.ticketSupported = false
	m.alpnProtocol = ""

	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			d := data[:length]
			for len(d) > 0 {
				l := int(d[0])
				d = d[1:]
				if l == 0 || l > len(d) {
					return false
				}
				m.nextProtos = append(m.nextProtos, string(d[:l]))
				d = d[l:]
			}
		case extensionStatusRequest:
			if length > 0 {
				return false
			}
			m.ocspStapling = true
		case extensionSessionTicket:
			if length > 0 {
				return false
			}
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if length != 1 || data[0] != 0 {
				return false
			}
			m.secureRenegotiation = true
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return false
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return false
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return false
			}
			m.alpnProtocol = string(d)
		case extensionSCT:
			d := data[:length]

			if len(d) < 2 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != l {
				return false
			}
			if l == 0 {
				continue
			}

			m.scts = make([][]byte, 0, 3)
			for len(d) != 0 {
				if len(d) < 2 {
					return false
				}
				sctLen := int(d[0])<<8 | int(d[1])
				d = d[2:]
				if len(d) < sctLen {
					return false
				}
				m.scts = append(m.scts, d[:sctLen])
				d = d[sctLen:]
			}
		case extensionSupportedVersions:
			if length != 2 {
				return false
			}
			m.supportedVersion = uint16(data[0])<<8 | uint16(data[1])
		case extensionCookie:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:]
			m.cookie = make([]byte, l)
			copy(m.cookie[0:], d[0:l])
			d = d[l:]
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if length == 2 {
				m.selectedGroup = CurveID(data[0])<<8 | CurveID(data[1])
			} else {
				if length < 2 {
					return false
				}
				m.serverShare.group = CurveID(data[0])<<8 | CurveID(data[1])
				serverShareDataLen := int(data[2])<<8 | int(data[3])
				d := data[4:]

				if len(d) < serverShareDataLen {
					return false
				}

				m.serverShare.data = make([]byte, serverShareDataLen)
				copy(m.serverShare.data[0:], d)
			}
		case extensionPreSharedKey:
			if length != 2 {
				return false
			}
			m.selectedIdentity = uint16(data[0])<<8 | uint16(data[1])
		}
		data = data[length:]
	}

	return true
}

// lbarman: TODO missing following message types & marshalling :
// - encryptedExtensionsMsg
// - endOfEarlyData
// - keyUpdateMsg
// - newSessionTicketMsg
// - certificateRequestMsg
// - certificateMsg

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		eqByteSlices(m.certificates, m1.certificates)
}

func (m *certificateMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	length := 3 + 3*len(m.certificates) + i
	x = make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	certificateOctets := length - 3
	x[4] = uint8(certificateOctets >> 16)
	x[5] = uint8(certificateOctets >> 8)
	x[6] = uint8(certificateOctets)

	y := x[7:]
	for _, slice := range m.certificates {
		y[0] = uint8(len(slice) >> 16)
		y[1] = uint8(len(slice) >> 8)
		y[2] = uint8(len(slice))
		copy(y[3:], slice)
		y = y[3+len(slice):]
	}

	m.raw = x
	return
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *serverKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.key, m1.key)
}

func (m *serverKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	m.raw = x
	return x
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}

type certificateStatusMsg struct {
	raw        []byte
	statusType uint8 // lbarman: TODO not present in reference implementation, check
	response   []byte
}

func (m *certificateStatusMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateStatusMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.statusType == m1.statusType &&
		bytes.Equal(m.response, m1.response)
}

func (m *certificateStatusMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var x []byte
	if m.statusType == statusTypeOCSP {
		x = make([]byte, 4+4+len(m.response))
		x[0] = typeCertificateStatus
		l := len(m.response) + 4
		x[1] = byte(l >> 16)
		x[2] = byte(l >> 8)
		x[3] = byte(l)
		x[4] = statusTypeOCSP

		l -= 4
		x[5] = byte(l >> 16)
		x[6] = byte(l >> 8)
		x[7] = byte(l)
		copy(x[8:], m.response)
	} else {
		x = []byte{typeCertificateStatus, 0, 0, 1, m.statusType}
	}

	m.raw = x
	return x
}

func (m *certificateStatusMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 5 {
		return false
	}
	m.statusType = data[4]

	m.response = nil
	if m.statusType == statusTypeOCSP {
		if len(data) < 8 {
			return false
		}
		respLen := uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		if uint32(len(data)) != 4+4+respLen {
			return false
		}
		m.response = data[8:]
	}
	return true
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) equal(i interface{}) bool {
	_, ok := i.(*serverHelloDoneMsg)
	return ok
}

func (m *serverHelloDoneMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ciphertext, m1.ciphertext)
}

func (m *clientKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) equal(i interface{}) bool {
	m1, ok := i.(*finishedMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.verifyData, m1.verifyData)
}

func (m *finishedMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	x = make([]byte, 4+len(m.verifyData))
	x[0] = typeFinished
	x[3] = byte(len(m.verifyData))
	copy(x[4:], m.verifyData)
	m.raw = x
	return
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.verifyData = data[4:]
	return true
}

type nextProtoMsg struct {
	raw   []byte
	proto string
}

func (m *nextProtoMsg) equal(i interface{}) bool {
	m1, ok := i.(*nextProtoMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.proto == m1.proto
}

func (m *nextProtoMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	l := len(m.proto)
	if l > 255 {
		l = 255
	}

	padding := 32 - (l+2)%32
	length := l + padding + 2
	x := make([]byte, length+4)
	x[0] = typeNextProtocol
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	y := x[4:]
	y[0] = byte(l)
	copy(y[1:], []byte(m.proto[0:l]))
	y = y[1+l:]
	y[0] = byte(padding)

	m.raw = x

	return x
}

func (m *nextProtoMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 5 {
		return false
	}
	data = data[4:]
	protoLen := int(data[0])
	data = data[1:]
	if len(data) < protoLen {
		return false
	}
	m.proto = string(data[0:protoLen])
	data = data[protoLen:]

	if len(data) < 1 {
		return false
	}
	paddingLen := int(data[0])
	data = data[1:]
	if len(data) != paddingLen {
		return false
	}

	return true
}

type certificateRequestMsg struct {
	raw []byte
	// hasSignatureAndHash indicates whether this message includes a list
	// of signature and hash functions. This change was introduced with TLS
	// 1.2.
	hasSignatureAndHash bool

	certificateTypes       []byte
	signatureAndHashes     []signatureAndHash
	certificateAuthorities [][]byte
}

func (m *certificateRequestMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateRequestMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.certificateTypes, m1.certificateTypes) &&
		eqByteSlices(m.certificateAuthorities, m1.certificateAuthorities) &&
		eqSignatureAndHashes(m.signatureAndHashes, m1.signatureAndHashes)
}

func (m *certificateRequestMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.4
	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

	if m.hasSignatureAndHash {
		length += 2 + 2*len(m.signatureAndHashes)
	}

	x = make([]byte, 4+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(len(m.certificateTypes))

	copy(x[5:], m.certificateTypes)
	y := x[5+len(m.certificateTypes):]

	if m.hasSignatureAndHash {
		n := len(m.signatureAndHashes) * 2
		y[0] = uint8(n >> 8)
		y[1] = uint8(n)
		y = y[2:]
		for _, sigAndHash := range m.signatureAndHashes {
			y[0] = sigAndHash.hash
			y[1] = sigAndHash.signature
			y = y[2:]
		}
	}

	y[0] = uint8(casLength >> 8)
	y[1] = uint8(casLength)
	y = y[2:]
	for _, ca := range m.certificateAuthorities {
		y[0] = uint8(len(ca) >> 8)
		y[1] = uint8(len(ca))
		y = y[2:]
		copy(y, ca)
		y = y[len(ca):]
	}

	m.raw = x
	return
}

func (m *certificateRequestMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 5 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	numCertTypes := int(data[4])
	data = data[5:]
	if numCertTypes == 0 || len(data) <= numCertTypes {
		return false
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, data) != numCertTypes {
		return false
	}

	data = data[numCertTypes:]

	if m.hasSignatureAndHash {
		if len(data) < 2 {
			return false
		}
		sigAndHashLen := uint16(data[0])<<8 | uint16(data[1])
		data = data[2:]
		if sigAndHashLen&1 != 0 {
			return false
		}
		if len(data) < int(sigAndHashLen) {
			return false
		}
		numSigAndHash := sigAndHashLen / 2
		m.signatureAndHashes = make([]signatureAndHash, numSigAndHash)
		for i := range m.signatureAndHashes {
			m.signatureAndHashes[i].hash = data[0]
			m.signatureAndHashes[i].signature = data[1]
			data = data[2:]
		}
	}

	if len(data) < 2 {
		return false
	}
	casLength := uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	if len(data) < int(casLength) {
		return false
	}
	cas := make([]byte, casLength)
	copy(cas, data)
	data = data[casLength:]

	m.certificateAuthorities = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return false
		}
		caLen := uint16(cas[0])<<8 | uint16(cas[1])
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return false
		}

		m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
		cas = cas[caLen:]
	}
	if len(data) > 0 {
		return false
	}

	return true
}

type certificateVerifyMsg struct {
	raw                 []byte
	hasSignatureAndHash bool
	signatureAndHash    signatureAndHash
	signature           []byte
}

func (m *certificateVerifyMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateVerifyMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.hasSignatureAndHash == m1.hasSignatureAndHash &&
		m.signatureAndHash.hash == m1.signatureAndHash.hash &&
		m.signatureAndHash.signature == m1.signatureAndHash.signature &&
		bytes.Equal(m.signature, m1.signature)
}

func (m *certificateVerifyMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.8
	siglength := len(m.signature)
	length := 2 + siglength
	if m.hasSignatureAndHash {
		length += 2
	}
	x = make([]byte, 4+length)
	x[0] = typeCertificateVerify
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	y := x[4:]
	if m.hasSignatureAndHash {
		y[0] = m.signatureAndHash.hash
		y[1] = m.signatureAndHash.signature
		y = y[2:]
	}
	y[0] = uint8(siglength >> 8)
	y[1] = uint8(siglength)
	copy(y[2:], m.signature)

	m.raw = x

	return
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 6 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	data = data[4:]
	if m.hasSignatureAndHash {
		m.signatureAndHash.hash = data[0]
		m.signatureAndHash.signature = data[1]
		data = data[2:]
	}

	if len(data) < 2 {
		return false
	}
	siglength := int(data[0])<<8 + int(data[1])
	data = data[2:]
	if len(data) != siglength {
		return false
	}

	m.signature = data

	return true
}

type newSessionTicketMsg struct {
	raw    []byte
	ticket []byte
}

func (m *newSessionTicketMsg) equal(i interface{}) bool {
	m1, ok := i.(*newSessionTicketMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ticket, m1.ticket)
}

func (m *newSessionTicketMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc5077#section-3.3
	ticketLen := len(m.ticket)
	length := 2 + 4 + ticketLen
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[8] = uint8(ticketLen >> 8)
	x[9] = uint8(ticketLen)
	copy(x[10:], m.ticket)

	m.raw = x

	return
}

func (m *newSessionTicketMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 10 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	ticketLen := int(data[8])<<8 + int(data[9])
	if len(data)-10 != ticketLen {
		return false
	}

	m.ticket = data[10:]

	return true
}

func eqUint8s(x, y []uint8) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqUint16s(x, y []uint16) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqCurveIDs(x, y []CurveID) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqStrings(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqByteSlices(x, y [][]byte) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if !bytes.Equal(v, y[i]) {
			return false
		}
	}
	return true
}

func eqSignatureAndHashes(x, y []signatureAndHash) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		v2 := y[i]
		if v.hash != v2.hash || v.signature != v2.signature {
			return false
		}
	}
	return true
}

func eqKeyShare(x, y keyShare) bool {
	return x.group == y.group && bytes.Equal(x.data, y.data)
}

func eqKeyShares(x, y []keyShare) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		v2 := y[i]
		if !eqKeyShare(v, v2) {
			return false
		}
	}
	return true
}

func eqPskIdentity(x, y []pskIdentity) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		v2 := y[i]
		if v.obfuscatedTicketAge != v2.obfuscatedTicketAge || !bytes.Equal(v.label, v2.label) {
			return false
		}
	}
	return true
}
