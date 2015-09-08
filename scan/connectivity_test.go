// Tests specific to the connectivity family.

package scan

import (
	"net"
	"net/http"
	"testing"

	"github.com/cloudflare/cfssl/helpers/testsuite"
)

func TestConnectivity(t *testing.T) {

	tcpServer := testsuite.NewTestServer(
		http.Server{Addr: net.JoinHostPort(addr, portTCP)})
	err := tcpServer.Start()
	if err != nil {
		t.Fatal(err.Error())
	}

	defer tcpServer.Kill()

	// === TEST: test the connectivity scan's response to a TCP-only server //

	dnsLookup := Connectivity.Scanners["DNSLookup"]
	tcpDial := Connectivity.Scanners["TCPDial"]
	tlsDial := Connectivity.Scanners["TLSDial"]

	grade, _, err := dnsLookup.Scan(tcpServer.Addr)
	if grade != Good {
		t.Log("TCP server failed DNSLookup scan (grade = " + grade.String() + ")")
		t.FailNow()
	}
	checkError(err, t)

	grade, _, err = tcpDial.Scan(tcpServer.Addr)
	if grade != Good {
		t.Log("TCP server failed TCPDial scan (grade = " + grade.String() + ")")
		t.FailNow()
	}
	checkError(err, t)

	grade, _, err = tlsDial.Scan(tcpServer.Addr)
	if grade != Bad {
		t.Log("TCP server did not fail TLSDial scan (grade = " + grade.String() +
			", error = " + err.Error() + ")")
		t.FailNow()
	}
}

func checkError(err error, t *testing.T) {
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}
