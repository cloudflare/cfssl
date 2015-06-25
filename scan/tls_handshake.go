package scan

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cloudflare/cf-tls/tls"
)

// Sentinel for failures in sayHello. Should always be caught.
var errHelloFailed = errors.New("Handshake failed in sayHello")

// TLSHandshake contains scanners testing host cipher suite negotiation
var TLSHandshake = &Family{
	Description: "Scans for host's SSL/TLS version and cipher suite negotiation",
	Scanners: map[string]*Scanner{
		"CipherSuite": {
			"Determines host's cipher suites accepted and prefered order",
			cipherSuiteScan,
		},
	},
}

func getCipherIndex(ciphers []uint16, serverCipher uint16) (cipherIndex int, err error) {
	//func getCipherIndex(ciphers []uint16, serverCipher uint16) (cipherIndex int, err error) {
	//	fmt.Println(serverCipher, ciphers)
	var cipherID uint16
	for cipherIndex, cipherID = range ciphers {
		if serverCipher == cipherID {
			return
		}
	}
	err = fmt.Errorf("server negotiated ciphersuite we didn't send: %s", tls.CipherSuites[serverCipher])
	return
}

func getCurveIndex(curves []tls.CurveID, serverCurve tls.CurveID) (curveIndex int, err error) {
	var curveID tls.CurveID
	for curveIndex, curveID = range curves {
		if serverCurve == curveID {
			return
		}
	}
	err = fmt.Errorf("server negotiated elliptic curve we didn't send: %s", tls.Curves[serverCurve])
	return
}

func sayHello(host string, ciphers []uint16, curves []tls.CurveID, vers uint16) (cipherIndex, curveIndex int, err error) {
	tcpConn, err := net.Dial(Network, host)
	if err != nil {
		return
	}
	config := defaultTLSConfig(host)
	config.MinVersion = vers
	config.MaxVersion = vers
	config.CipherSuites = ciphers
	config.CurvePreferences = curves
	conn := tls.Client(tcpConn, config)
	serverCipher, serverCurveType, serverCurve, serverVersion, err := conn.SayHello()
	conn.Close()
	if err != nil {
		err = errHelloFailed
		return
	}

	if serverVersion != vers {
		err = fmt.Errorf("server negotiated protocol version we didn't send: %s", tls.Versions[serverVersion])
		return
	}

	cipherIndex, err = getCipherIndex(ciphers, serverCipher)

	if tls.CipherSuites[serverCipher].EllipticCurve {
		if curves == nil {
			curves = allCurvesIDs()
		}
		if serverCurveType != 3 {
			err = fmt.Errorf("server negotiated non-named ECDH parameters; we didn't analyze them. Server curve type: %d", serverCurveType)
		}
		curveIndex, err = getCurveIndex(curves, serverCurve)
	}

	return
}

func allCiphersIDs() []uint16 {
	ciphers := make([]uint16, 0, len(tls.CipherSuites))
	for cipherID := range tls.CipherSuites {
		ciphers = append(ciphers, cipherID)
	}
	return ciphers
}

func allCurvesIDs() []tls.CurveID {
	curves := make([]tls.CurveID, 0, len(tls.Curves))
	for curveID := range tls.Curves {
		// No unassigned or explicit curves in the scan, per http://tools.ietf.org/html/rfc4492#section-5.4
		if curveID == 0 || curveID == 65281 || curveID == 65282 {
			continue
		} else {
			curves = append(curves, curveID)
		}
	}
	return curves
}

type cipherDatum struct {
	versionID uint16
	curves    []tls.CurveID
}

// cipherVersions contains lists of host's supported cipher suites based on SSL/TLS Version.
// If a cipher suite uses ECC, also contains a list of supported curves by SSL/TLS Version.
type cipherVersions struct {
	cipherID uint16
	data     []cipherDatum
}

type cipherVersionList []cipherVersions

func (cvList cipherVersionList) String() string {
	cvStrings := make([]string, len(cvList))
	for i, c := range cvList {
		versStrings := make([]string, len(c.data))
		for j, d := range c.data {
			curveStrings := make([]string, len(d.curves))
			for k, c := range d.curves {
				curveStrings[k] = tls.Curves[c]
			}
			versStrings[j] = fmt.Sprintf("%s: [ %s ]", tls.Versions[d.versionID], strings.Join(curveStrings, ","))
		}
		cvStrings[i] = fmt.Sprintf("%s\t%s", tls.CipherSuites[c.cipherID], strings.Join(versStrings, ","))
	}
	return strings.Join(cvStrings, "\n")
}

func (cvList cipherVersionList) MarshalJSON() ([]byte, error) {
	b := new(bytes.Buffer)
	cvStrs := make([]string, len(cvList))
	for i, cv := range cvList {
		versStrings := make([]string, len(cv.data))
		for j, d := range cv.data {
			curveStrings := make([]string, len(d.curves))
			if len(d.curves) > 0 {
				for k, c := range d.curves {
					curveStrings[k] = fmt.Sprintf("\"%s\"", tls.Curves[c])
				}
				versStrings[j] = fmt.Sprintf("{\"%s\":[%s]}", tls.Versions[d.versionID], strings.Join(curveStrings, ","))
			} else {
				versStrings[j] = fmt.Sprintf("\"%s\"", tls.Versions[d.versionID])
			}
		}
		cvStrs[i] = fmt.Sprintf("{\"%s\":[%s]}", tls.CipherSuites[cv.cipherID].String(), strings.Join(versStrings, ","))
	}
	fmt.Fprintf(b, "[%s]", strings.Join(cvStrs, ","))
	return b.Bytes(), nil
}

func doCurveScan(host string, vers, cipherID uint16, ciphers []uint16) (supportedCurves []tls.CurveID, err error) {
	allCurves := allCurvesIDs()
	curves := make([]tls.CurveID, len(allCurves))
	copy(curves, allCurves)
	for len(curves) > 0 {
		var curveIndex int
		_, curveIndex, err = sayHello(host, []uint16{cipherID}, curves, vers)
		if err != nil {
			// This case is expected, because eventually we ask only for curves the server doesn't support
			if err == errHelloFailed {
				err = nil
				break
			}
			return
		}
		curveID := curves[curveIndex]
		supportedCurves = append(supportedCurves, curveID)
		curves = append(curves[:curveIndex], curves[curveIndex+1:]...)
	}
	return
}

// cipherSuiteScan returns, by TLS Version, the sort list of cipher suites
// supported by the host
func cipherSuiteScan(host string) (grade Grade, output Output, err error) {
	var cvList cipherVersionList
	allCiphers := allCiphersIDs()

	var vers uint16
	for vers = tls.VersionTLS12; vers >= tls.VersionSSL30; vers-- {
		ciphers := make([]uint16, len(allCiphers))
		copy(ciphers, allCiphers)
		for len(ciphers) > 0 {
			var cipherIndex int
			cipherIndex, _, err = sayHello(host, ciphers, nil, vers)
			if err != nil {
				if err == errHelloFailed {
					err = nil
					break
				}
				return
			}
			if vers == tls.VersionSSL30 {
				grade = Warning
			}
			cipherID := ciphers[cipherIndex]

			// If this is an EC cipher suite, do a second scan for curve support
			var supportedCurves []tls.CurveID
			if tls.CipherSuites[cipherID].EllipticCurve {
				supportedCurves, err = doCurveScan(host, vers, cipherID, ciphers)
				if len(supportedCurves) == 0 {
					err = errors.New("couldn't negotiate any curves")
				}
			}
			for i, c := range cvList {
				if cipherID == c.cipherID {
					cvList[i].data = append(c.data, cipherDatum{vers, supportedCurves})
					goto exists
				}
			}
			cvList = append(cvList, cipherVersions{cipherID, []cipherDatum{cipherDatum{vers, supportedCurves}}})
		exists:
			ciphers = append(ciphers[:cipherIndex], ciphers[cipherIndex+1:]...)
		}
	}

	if len(cvList) == 0 {
		err = errors.New("couldn't negotiate any cipher suites")
		return
	}

	if grade != Warning {
		grade = Good
	}

	output = cvList
	return
}
