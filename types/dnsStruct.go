package types

const (
	TypeA     = 1   // IPv4 address
	TypeNS    = 2   // Name server
	TypeCNAME = 5   // Canonical name
	TypeSOA   = 6   // Start of authority
	TypeMX    = 15  // Mail exchange
	TypeTXT   = 16  // Text record
	TypeAAAA  = 28  // IPv6 address
	TypeOPT   = 41  // EDNS0 option
	TypeANY   = 255 // All records
)

const (
	ClassIN  = 1   // Internet
	ClassCS  = 2   // CSNET
	ClassCH  = 3   // CHAOS
	ClassHS  = 4   // Hesiod
	ClassANY = 255 // Any class
)

const (
	RCodeNoError  = 0 // Success
	RCodeFormErr  = 1 // Format error
	RCodeServFail = 2 // Server failure
	RCodeNXDomain = 3 // Domain doesn't exist
	RCodeNotImpl  = 4 // Not implemented
	RCodeRefused  = 5 // Refused
)

type DNSMessage struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSResourceRecord
	Authorities []DNSResourceRecord
	Additional  []DNSResourceRecord
}

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}
