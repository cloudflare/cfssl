package pkcs11

// Config contains configuration information required to use a PKCS
// #11 key.
type Config struct {
	Module string
	Token  string
	PIN    string
	Label  string
}
