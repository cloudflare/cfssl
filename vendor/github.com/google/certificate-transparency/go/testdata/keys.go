// Package testdata holds data and utility functions needed for various Go tests.
package testdata

import "encoding/hex"

// Hashes of text string 'abcd' with various algorithms; check with either "<alg>sum input" or "openssl dgst -<alg> input"
const (
	// AbcdMD5 is 'abcd' hashed with MD5
	AbcdMD5 = "e2fc714c4727ee9395f324cd2e7f331f"
	// AbcdSHA1 is 'abcd' hashed with SHA1
	AbcdSHA1 = "81fe8bfe87576c3ecb22426f8e57847382917acf"
	// AbcdSHA224 is 'abcd' hashed with SHA224
	AbcdSHA224 = "a76654d8e3550e9a2d67a0eeb6c67b220e5885eddd3fde135806e601"
	// AbcdSHA256 is 'abcd' hashed with SHA256
	AbcdSHA256 = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
	// AbcdSHA384 is 'abcd' hashed with SHA384
	AbcdSHA384 = "1165b3406ff0b52a3d24721f785462ca2276c9f454a116c2b2ba20171a7905ea5a026682eb659c4d5f115c363aa3c79b"
	// AbcdSHA512 is 'abcd' hashed with SHA512
	AbcdSHA512 = "d8022f2060ad6efd297ab73dcc5355c9b214054b0d1776a136a669d26a7d3b14f73aa0d0ebff19ee333368f0164b6419a96da49e3e481753e7e96b716bdccb6f"
)

const (
	// RsaPrivateKeyPEM was generated with:
	//    openssl genpkey -algorithm RSA -out rsa.privkey.pem -pkeyopt rsa_keygen_bits:2048
	RsaPrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDP8SJM5SBIbFpF\n" +
		"dRAUEERo35E4iFXfT5SVAzBIqATkCpf3LfdFZgssPeliBdTtgdvT/CWC2m6aVXYZ\n" +
		"eScAJOauTpGDyJ7OXj7Yhx1q6u28NuQleU3UQK5QYb7VOjeIse7oTh+THf5IK5T5\n" +
		"esyh+ioybEYBXXMQetHc4YbXAq06crNT2BP+AxQ4z27xu4X5CKLwwVMa2xwMCFDC\n" +
		"Y7mxQzEhFv8+HbOtM0IQMSSyh6+o0w4Yzt6i/TUOytZb1D7WHOEMpVTd1CMbXjN0\n" +
		"tFZvoO0V+n0OV3oT1E5AvwujVguUJblQiapbL890/nZbBtP3xMoFLLhc7sX7N2vR\n" +
		"1wLWsjOVAgMBAAECggEBAL+frUZDV86l20JqsFhs7T3f2MnKCahyg7AWciZif69O\n" +
		"e+BTQa14bg9lNm8YhLIim1vs3vyJIqei3eR3mxMs7k/vI3XYKVBv1WZgjSF8QXzS\n" +
		"8Mf/01MoD/sPOHby4T5dCpaVd89xMmV7lBubqHwUN1KkKJcVcPXc2Qy94C6/zrcu\n" +
		"Vb7Q91ugTvvhyalWEN02M3tzHEn4cXrnMLWPmTgxb7YtTMRIbJFx2um7/W9G5D+1\n" +
		"ZtKMjwt+P/yXynx3Sa555MjjJ1/LUyMSbQZoLE0SGOigz1VQnP8nFlpvXUHzktiA\n" +
		"IBPBBQSsEoS8H3z6WThwY72O795/i2l5mf7EUUAa2/kCgYEA+W7tJPg69KWHKn6E\n" +
		"gGZKIDTxvp3vRxjLedp7D7cu6bVPCBVIHrPQdmp/mneY6x7Air0a9gCVbh32iCrm\n" +
		"UrSBCio4i6jtqtna2T1Gc0z63K3UrVQPR0Z6Swq1XDOI6/I23ibxPr12/XXWWYlA\n" +
		"wkPwvewJVrjtMoP1dkAKVbyzImcCgYEA1WqS0xg7BL4iNGFPrrSme2blZOgga83x\n" +
		"CtY9dnWAs0IvdxsuItCDaFVJm3oU18ohirEMzqZvbRlwMlUawpd75hCNWyVF4cRo\n" +
		"+l1RvzOlC/7QXX/E+Kv7sTEUYH7hJyS46QhOtC1/ndAyObk9c2VNJmERfMwIHNm9\n" +
		"BfSN8yrq1KMCgYEA94fCZPbGIvSFj4EgYv+fvhhscvrucsLDYniTuUPTlXAtLttX\n" +
		"x8gwLuN/ID5hjarl7oi90bVAlZe8iOLx0M96YykFFmuc9/jcOsuZN2EEbq0/KocJ\n" +
		"5nSldgT5d7dYwLWNB6bjr5x8Egm3nwEbN+4OYZt0pRA9q+zSUfg5iV4K8y8CgYA7\n" +
		"S9YposTbJ3zXcuYx022iQc+gvsIrUdgUO7xuCm3M4KnRfRLPh4HLXk8KTNw3rKiv\n" +
		"IUw+qo2xEW1T/sNlp7M8FANCfNOyy+CjF4ScDFxiPdVk9RgkQ5y1+b4ApaAnQRPD\n" +
		"Y5SCiVW44lziHu7M/it2a2fxdbsXUQQtAGrkUltW4wKBgAPZyEGi4V2wryOswmkC\n" +
		"I29TbC6ChnUOvqJfSfz536eIi41D1Ua2Y/VlAK1ud7K8ilr/M4VoRjHqbPivR1Uk\n" +
		"RU7nO3cWRBuDBjgZWeAq5WFIMPbm9gRlaTECI6EFtAOI1GcHOsOBecd3PBiQNXvj\n" +
		"YyGD1wSrHQwDcnxtP1rqEQDV\n" +
		"-----END PRIVATE KEY-----\n"

	// RsaPublicKeyPEM was generated from above with:
	//    openssl rsa -pubout -in rsa.privkey.pem -out rsa.pubkey.pem
	RsaPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz/EiTOUgSGxaRXUQFBBE\n" +
		"aN+ROIhV30+UlQMwSKgE5AqX9y33RWYLLD3pYgXU7YHb0/wlgtpumlV2GXknACTm\n" +
		"rk6Rg8iezl4+2IcdaurtvDbkJXlN1ECuUGG+1To3iLHu6E4fkx3+SCuU+XrMofoq\n" +
		"MmxGAV1zEHrR3OGG1wKtOnKzU9gT/gMUOM9u8buF+Qii8MFTGtscDAhQwmO5sUMx\n" +
		"IRb/Ph2zrTNCEDEksoevqNMOGM7eov01DsrWW9Q+1hzhDKVU3dQjG14zdLRWb6Dt\n" +
		"Ffp9Dld6E9ROQL8Lo1YLlCW5UImqWy/PdP52WwbT98TKBSy4XO7F+zdr0dcC1rIz\n" +
		"lQIDAQAB\n" +
		"-----END PUBLIC KEY-----\n"

	// RsaSignedAbcdHex was generated with:
	//    echo -n "abcd" > sign.input
	//    openssl sha256 -sign rsa.privkey.pem -out sign.rsa sign.input
	// Verify with:
	//    openssl sha256 -verify rsa.pubkey.pem -signature sign.rsa sign.input
	RsaSignedAbcdHex = "4692f17adad62324a38a786d9b05eb7facf95c277729bc23e8d4f4fe25c0ac0e" +
		"9115f14ffd4dc6c00e6b2717677e96ed4da9e2226745db5c2d14ec8b4f96959e" +
		"a43ca73e3ab801d4e76b0c0599c741b9701dd0c22b20cc7a294fccce97d2eda2" +
		"72448830a19b0b1075f962d3bcf65922f81f4747dde1a2883ffce12941927af6" +
		"25549ea7b4f745a95f5558822af434cc7471ea5a21cce656a7667d29bff3e6f2" +
		"fb3d48bbee1a60116f0dd429d5691b008482e9ec42538bcf2692e1a685e836c8" +
		"49316fb3c49b58bd5a0c33f0256b09d59af08a018fe64cd31051cb9e9a1d3fde" +
		"e186bd80bfe304abbbec2ac18d3bee09465cb69f2638728aba4b9886a252768a"

	// DsaPrivateKeyPEM was generated with:
	//    openssl dsaparam -out dsa.param.pem 2048; openssl gendsa dsa.param.pem -out dsa.privkey.pem
	DsaPrivateKeyPEM = "-----BEGIN DSA PRIVATE KEY-----\n" +
		"MIIDVwIBAAKCAQEA3Q72qQc0ZM2eUjvZ/XOROQTbhmjzuZdzY7kd+82n54NPeqVz\n" +
		"+FWmk26INd7pUNbn/TjniN5+pC2pK+p9alFLE19bOvsY4x7Ugwrpd9sQIea3W4Q7\n" +
		"H9PaEW+BooFzT/feC9TmnU0ynwoNhZB33Cr3k3PFt/69lmyrkd91wTpXrstrQurU\n" +
		"h4baL5l6t2/JT3TxpKx6xe19hWqqFsBLu/j+kE2o2Aw1TVLHg4/74TJLfqAkWnCI\n" +
		"u9QL0uGQnW80kRfJnT+tUJXrXMpg1HxK7CsDEW5xsAWF370Is0UPaP7jRru6FiSN\n" +
		"ObcVhSqCIs+QJIWie9cRtwniwhoi4z6AfGeEYQIhAOkSzAsWja1fwB486/LCW+zv\n" +
		"DJKiCGLTalimfawzHQHFAoIBAQDJvCujEZ/WeQFLlP/0zS+2DjqdaxnKj1xuXfoL\n" +
		"LOocvMw06dnrQNmDu/nBQiYSfzf7zjwpnx+AVjBQssK0jXs0l7gw52FyCIztDejT\n" +
		"/ybMVudwKUGudxAEjOclOSQ7XVpPd4p3UMy+E6pkJ8VRiuNFDibYTD+O3XhFTj2l\n" +
		"6LqV/KcB2fWV1fUqfxax2vpcwe4clTJbJXUgJC3mYmUXv1U6z0hliDz2WMhbOyea\n" +
		"1fs31zYvIMyk2wJFJl7+EbXb8BgYcQt1FE4c14fuFnincAW0So+xBZ5DtiTja4lm\n" +
		"DE0OAI2hhLslSQ7rGwWt2zIKSFLtsWf78CP1wigJvWcUVhazAoIBAFAhxgtOaV8G\n" +
		"FJxs6A3TtXEmmrq3i5/w3/8l7skWamcHvcwrvw37g5KQY+N+85JZszHPjmUzEq/o\n" +
		"NOLjF6zq7+oRtWbOR3Mvc2hHsHg86tE/HAkBIu2G73c9UuskzGSMec4F6TyWKHvC\n" +
		"26F2cvu9aA42v/8q1d/QQs3+LrtARGhyFCqnBVNSZmZj5ngR0kLGUfs/LQklpGFe\n" +
		"VciXK57RxHSPo15lnKiHW9kCte7tGEg9Eber8paMz67dQDuj1yRkS5H7JXqRZjIP\n" +
		"UrICWGGk1vluQsuoyI/Nu8/tL7Im24xZH6XHBm4F+aijl9XlAJiKXfkCLIaxYSdc\n" +
		"4PXquTwtRLICIQCijrpD+UhidGFLPZCCLzBC239PrP7PabSVurWXHh5iYw==\n" +
		"-----END DSA PRIVATE KEY-----\n"

	// DsaPrivateKeyPKCS8PEM is a copy of the private key above, encoded in PKCS#8 format.
	// Generated from above with:
	//    openssl pkcs8 -topk8 -nocrypt -in dsa.privkey.pem -out dsa.privkey.pkcs8.pem
	DsaPrivateKeyPKCS8PEM = "-----BEGIN PRIVATE KEY-----\n" +
		"MIICZgIBADCCAjoGByqGSM44BAEwggItAoIBAQDdDvapBzRkzZ5SO9n9c5E5BNuG\n" +
		"aPO5l3NjuR37zafng096pXP4VaaTbog13ulQ1uf9OOeI3n6kLakr6n1qUUsTX1s6\n" +
		"+xjjHtSDCul32xAh5rdbhDsf09oRb4GigXNP994L1OadTTKfCg2FkHfcKveTc8W3\n" +
		"/r2WbKuR33XBOleuy2tC6tSHhtovmXq3b8lPdPGkrHrF7X2FaqoWwEu7+P6QTajY\n" +
		"DDVNUseDj/vhMkt+oCRacIi71AvS4ZCdbzSRF8mdP61QletcymDUfErsKwMRbnGw\n" +
		"BYXfvQizRQ9o/uNGu7oWJI05txWFKoIiz5AkhaJ71xG3CeLCGiLjPoB8Z4RhAiEA\n" +
		"6RLMCxaNrV/AHjzr8sJb7O8MkqIIYtNqWKZ9rDMdAcUCggEBAMm8K6MRn9Z5AUuU\n" +
		"//TNL7YOOp1rGcqPXG5d+gss6hy8zDTp2etA2YO7+cFCJhJ/N/vOPCmfH4BWMFCy\n" +
		"wrSNezSXuDDnYXIIjO0N6NP/JsxW53ApQa53EASM5yU5JDtdWk93indQzL4TqmQn\n" +
		"xVGK40UOJthMP47deEVOPaXoupX8pwHZ9ZXV9Sp/FrHa+lzB7hyVMlsldSAkLeZi\n" +
		"ZRe/VTrPSGWIPPZYyFs7J5rV+zfXNi8gzKTbAkUmXv4RtdvwGBhxC3UUThzXh+4W\n" +
		"eKdwBbRKj7EFnkO2JONriWYMTQ4AjaGEuyVJDusbBa3bMgpIUu2xZ/vwI/XCKAm9\n" +
		"ZxRWFrMEIwIhAKKOukP5SGJ0YUs9kIIvMELbf0+s/s9ptJW6tZceHmJj\n" +
		"-----END PRIVATE KEY-----\n"

	// DsaPublicKeyPEM was generated from above with:
	//    openssl dsa -in dsa.privkey.pem -pubout -out dsa.pubkey.pem
	DsaPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
		"MIIDRzCCAjoGByqGSM44BAEwggItAoIBAQDdDvapBzRkzZ5SO9n9c5E5BNuGaPO5\n" +
		"l3NjuR37zafng096pXP4VaaTbog13ulQ1uf9OOeI3n6kLakr6n1qUUsTX1s6+xjj\n" +
		"HtSDCul32xAh5rdbhDsf09oRb4GigXNP994L1OadTTKfCg2FkHfcKveTc8W3/r2W\n" +
		"bKuR33XBOleuy2tC6tSHhtovmXq3b8lPdPGkrHrF7X2FaqoWwEu7+P6QTajYDDVN\n" +
		"UseDj/vhMkt+oCRacIi71AvS4ZCdbzSRF8mdP61QletcymDUfErsKwMRbnGwBYXf\n" +
		"vQizRQ9o/uNGu7oWJI05txWFKoIiz5AkhaJ71xG3CeLCGiLjPoB8Z4RhAiEA6RLM\n" +
		"CxaNrV/AHjzr8sJb7O8MkqIIYtNqWKZ9rDMdAcUCggEBAMm8K6MRn9Z5AUuU//TN\n" +
		"L7YOOp1rGcqPXG5d+gss6hy8zDTp2etA2YO7+cFCJhJ/N/vOPCmfH4BWMFCywrSN\n" +
		"ezSXuDDnYXIIjO0N6NP/JsxW53ApQa53EASM5yU5JDtdWk93indQzL4TqmQnxVGK\n" +
		"40UOJthMP47deEVOPaXoupX8pwHZ9ZXV9Sp/FrHa+lzB7hyVMlsldSAkLeZiZRe/\n" +
		"VTrPSGWIPPZYyFs7J5rV+zfXNi8gzKTbAkUmXv4RtdvwGBhxC3UUThzXh+4WeKdw\n" +
		"BbRKj7EFnkO2JONriWYMTQ4AjaGEuyVJDusbBa3bMgpIUu2xZ/vwI/XCKAm9ZxRW\n" +
		"FrMDggEFAAKCAQBQIcYLTmlfBhScbOgN07VxJpq6t4uf8N//Je7JFmpnB73MK78N\n" +
		"+4OSkGPjfvOSWbMxz45lMxKv6DTi4xes6u/qEbVmzkdzL3NoR7B4POrRPxwJASLt\n" +
		"hu93PVLrJMxkjHnOBek8lih7wtuhdnL7vWgONr//KtXf0ELN/i67QERochQqpwVT\n" +
		"UmZmY+Z4EdJCxlH7Py0JJaRhXlXIlyue0cR0j6NeZZyoh1vZArXu7RhIPRG3q/KW\n" +
		"jM+u3UA7o9ckZEuR+yV6kWYyD1KyAlhhpNb5bkLLqMiPzbvP7S+yJtuMWR+lxwZu\n" +
		"Bfmoo5fV5QCYil35AiyGsWEnXOD16rk8LUSy\n" +
		"-----END PUBLIC KEY-----\n"

	// DsaSignedAbcdHex was generated with:
	//    echo -n "abcd" > sign.input
	//    openssl dgst -dss1 -sign dsa.privkey.pem -out sign.dsa sign.input
	// Note that this includes randomization so will give different results each time.
	// Verify with:
	//    openssl dgst -dss1 -verify dsa.pubkey.pem -signature sign.dsa sign.input
	DsaSignedAbcdHex = "3045022100c287211dec54eab597ed5264f6fdf57faf651909914c533d42f0e3" +
		"2809e9141402205f34cc4b8ca12ebdf025bf36bbe1ff7d807d4cfe951ac1329a" +
		"35a39f5e971f10"

	// EcdsaPrivateKeyPEM was generated with:
	//    openssl ecparam -genkey -name prime256v1 -noout -out ecdsa.privkey.pem
	EcdsaPrivateKeyPEM = "-----BEGIN EC PRIVATE KEY-----\n" +
		"MHcCAQEEIHg0hg3vLqLVI7wv2y0cCk+kmwuwoKsMZqzqbjqP1AtjoAoGCCqGSM49\n" +
		"AwEHoUQDQgAEjHs6Rw7KFt8Wd2ZcioZi7eZY5nodUXMnCWUhZzsGVsPaexqUyPSr\n" +
		"9cQgrCe7MPRLJ524AO6rREqfs7FKt85++A==\n" +
		"-----END EC PRIVATE KEY-----\n"

	// EcdsaPrivateKeyPKCS8PEM is a copy of the private key above, encoded in PKCS#8 format.
	// Generated from above with:
	//    openssl pkcs8 -topk8 -nocrypt -in ecdsa.privkey.pem -out ecdsa.privkey.pkcs8.pem
	EcdsaPrivateKeyPKCS8PEM = "-----BEGIN PRIVATE KEY-----\n" +
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeDSGDe8uotUjvC/b\n" +
		"LRwKT6SbC7CgqwxmrOpuOo/UC2OhRANCAASMezpHDsoW3xZ3ZlyKhmLt5ljmeh1R\n" +
		"cycJZSFnOwZWw9p7GpTI9Kv1xCCsJ7sw9EsnnbgA7qtESp+zsUq3zn74\n" +
		"-----END PRIVATE KEY-----\n"

	// EcdsaPublicKeyPEM was generated from above with:
	//    openssl ec -in ecdsa.privkey.pem -pubout -out ecdsa.pubkey.pem
	EcdsaPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjHs6Rw7KFt8Wd2ZcioZi7eZY5nod\n" +
		"UXMnCWUhZzsGVsPaexqUyPSr9cQgrCe7MPRLJ524AO6rREqfs7FKt85++A==\n" +
		"-----END PUBLIC KEY-----\n"

	// EcdsaSignedAbcdHex was generated with:
	//    echo -n "abcd" > sign.input
	//    openssl dgst -sha256 -sign ecdsa.privkey.pem -out sign.ecdsa sign.input
	// Note that this includes randomization so will give different results each time.
	// Verify with:
	//    openssl dgst -sha256 -verify ecdsa.pubkey.pem -signature sign.ecdsa sign.input
	EcdsaSignedAbcdHex = "304502202e0204dadf2baa35e426b66ab8cd32a9ba33421187645a9110512e3e" +
		"d1b8007b022100ae83f5f993ab3af6f46bb09b4f15d07cc582b03e1353879ada" +
		"ce68796fe537e5"
)

// FromHex decodes a hex string to a byte array, and panics on error; only suitable for
// use in test code.
func FromHex(hexdata string) []byte {
	data, err := hex.DecodeString(hexdata)
	if err != nil {
		panic("non hex data: " + err.Error())
	}
	return data
}
