// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo,!arm,!arm64,!ios

package x509

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1060
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <errno.h>
#include <sys/sysctl.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// FetchPEMRootsCTX509_MountainLion is the version of FetchPEMRoots from Go 1.6
// which still works on OS X 10.8 (Mountain Lion).
// It lacks support for admin & user cert domains.
// See golang.org/issue/16473
int FetchPEMRootsCTX509_MountainLion(CFDataRef *pemRoots) {
	if (pemRoots == NULL) {
		return -1;
	}
	CFArrayRef certs = NULL;
	OSStatus err = SecTrustCopyAnchorCertificates(&certs);
	if (err != noErr) {
		return -1;
	}
	CFMutableDataRef combinedData = CFDataCreateMutable(kCFAllocatorDefault, 0);
	int i, ncerts = CFArrayGetCount(certs);
	for (i = 0; i < ncerts; i++) {
		CFDataRef data = NULL;
		SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
		if (cert == NULL) {
			continue;
		}
		// Note: SecKeychainItemExport is deprecated as of 10.7 in favor of SecItemExport.
		// Once we support weak imports via cgo we should prefer that, and fall back to this
		// for older systems.
		err = SecKeychainItemExport(cert, kSecFormatX509Cert, kSecItemPemArmour, NULL, &data);
		if (err != noErr) {
			continue;
		}
		if (data != NULL) {
			CFDataAppendBytes(combinedData, CFDataGetBytePtr(data), CFDataGetLength(data));
			CFRelease(data);
		}
	}
	CFRelease(certs);
	*pemRoots = combinedData;
	return 0;
}

// useOldCodeCTX509 reports whether the running machine is OS X 10.8 Mountain Lion
// or older. We only support Mountain Lion and higher, but we'll at least try our
// best on older machines and continue to use the old code path.
//
// See golang.org/issue/16473
int useOldCodeCTX509() {
	char str[256];
	size_t size = sizeof(str);
	memset(str, 0, size);
	sysctlbyname("kern.osrelease", str, &size, NULL, 0);
	// OS X 10.8 is osrelease "12.*", 10.7 is 11.*, 10.6 is 10.*.
	// We never supported things before that.
	return memcmp(str, "12.", 3) == 0 || memcmp(str, "11.", 3) == 0 || memcmp(str, "10.", 3) == 0;
}

// FetchPEMRootsCTX509 fetches the system's list of trusted X.509 root certificates.
//
// On success it returns 0 and fills pemRoots with a CFDataRef that contains the extracted root
// certificates of the system. On failure, the function returns -1.
//
// Note: The CFDataRef returned in pemRoots must be released (using CFRelease) after
// we've consumed its content.
int FetchPEMRootsCTX509(CFDataRef *pemRoots) {
	if (useOldCodeCTX509()) {
		return FetchPEMRootsCTX509_MountainLion(pemRoots);
	}

	// Get certificates from all domains, not just System, this lets
	// the user add CAs to their "login" keychain, and Admins to add
	// to the "System" keychain
	SecTrustSettingsDomain domains[] = { kSecTrustSettingsDomainSystem,
					     kSecTrustSettingsDomainAdmin,
					     kSecTrustSettingsDomainUser };

	int numDomains = sizeof(domains)/sizeof(SecTrustSettingsDomain);
	if (pemRoots == NULL) {
		return -1;
	}

	CFMutableDataRef combinedData = CFDataCreateMutable(kCFAllocatorDefault, 0);
	for (int i = 0; i < numDomains; i++) {
		CFArrayRef certs = NULL;
		// Only get certificates from domain that are trusted
		OSStatus err = SecTrustSettingsCopyCertificates(domains[i], &certs);
		if (err != noErr) {
			continue;
		}

		int numCerts = CFArrayGetCount(certs);
		for (int j = 0; j < numCerts; j++) {
			CFDataRef data = NULL;
			CFErrorRef errRef = NULL;
			SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, j);
			if (cert == NULL) {
				continue;
			}
			// We only want to add Root CAs, so make sure Subject and Issuer Name match
			CFDataRef subjectName = SecCertificateCopyNormalizedSubjectContent(cert, &errRef);
			if (errRef != NULL) {
				CFRelease(errRef);
				continue;
			}
			CFDataRef issuerName = SecCertificateCopyNormalizedIssuerContent(cert, &errRef);
			if (errRef != NULL) {
				CFRelease(subjectName);
				CFRelease(errRef);
				continue;
			}
			Boolean equal = CFEqual(subjectName, issuerName);
			CFRelease(subjectName);
			CFRelease(issuerName);
			if (!equal) {
				continue;
			}

			// Note: SecKeychainItemExport is deprecated as of 10.7 in favor of SecItemExport.
			// Once we support weak imports via cgo we should prefer that, and fall back to this
			// for older systems.
			err = SecKeychainItemExport(cert, kSecFormatX509Cert, kSecItemPemArmour, NULL, &data);
			if (err != noErr) {
				continue;
			}

			if (data != NULL) {
				CFDataAppendBytes(combinedData, CFDataGetBytePtr(data), CFDataGetLength(data));
				CFRelease(data);
			}
		}
		CFRelease(certs);
	}
	*pemRoots = combinedData;
	return 0;
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

func loadSystemRoots() (*CertPool, error) {
	roots := NewCertPool()

	var data C.CFDataRef = nil
	err := C.FetchPEMRootsCTX509(&data)
	if err == -1 {
		// TODO: better error message
		return nil, errors.New("crypto/x509: failed to load darwin system roots with cgo")
	}

	defer C.CFRelease(C.CFTypeRef(data))
	buf := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(C.CFDataGetLength(data)))
	roots.AppendCertsFromPEM(buf)
	return roots, nil
}
