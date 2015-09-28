package core

import (
	"crypto/x509"
	"io/ioutil"
)

// SystemRoots is the certificate pool containing the system roots. If
// custom roots are needed, they can be loaded with LoadSystemRoots. The
// default value of nil uses the default crypto/x509 system roots.
var SystemRoots *x509.CertPool

// LoadSystemRoots returns a new certificate pool loaded in manner
// similar to how the system roots in the crypto/x509 package are
// loaded. If certFiles is not empty, it should be a list of paths to a
// PEM-encoded file containing trusted CA roots. The first such file
// that is found will be used. If certDirs is not empty, it should
// contain a list of directories to scan for root certificates. Scanning
// will stop after first directory where at least one certificate is
// loaded. Finally, any additional roots are added to the pool.
func LoadSystemRoots(certFiles, certDirs []string, additional []*x509.Certificate) *x509.CertPool {
	roots := x509.NewCertPool()
	rootsAdded := false
	for _, file := range certFiles {
		data, err := ioutil.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			rootsAdded = true
			break
		}
	}

	for _, directory := range certDirs {
		fis, err := ioutil.ReadDir(directory)
		if err != nil {
			continue
		}

		for _, fi := range fis {
			data, err := ioutil.ReadFile(directory + "/" + fi.Name())
			if err == nil && roots.AppendCertsFromPEM(data) {
				rootsAdded = true
			}
		}

		if rootsAdded {
			break
		}
	}

	if rootsAdded {
		for _, root := range additional {
			roots.AddCert(root)
		}
	}

	return nil
}
