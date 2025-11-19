# Go DNS Server

A fully functional DNS server implemented from scratch in Go. This project demonstrates building a DNS forwarding server that handles both UDP and TCP queries with complete DNS protocol parsing, EDNS support, and proper connection management.

## Features

- **Dual Protocol Support**: UDP (port 8080) and TCP (port 8081) DNS server implementations
- **DNS Forwarding**: Forwards queries to upstream DNS servers (default: Google's 8.8.8.8)
- **Complete DNS Protocol Parsing**: 
  - Header parsing with all flags and counters
  - Question section parsing with domain name decompression
  - Resource record parsing (Answers, Authorities, Additional)
  - DNS message compression/pointer support
- **EDNS0 Support**: Handles EDNS (Extension mechanisms for DNS) OPT records
- **Robust TCP Handling**:
  - TCP length prefix handling (RFC 1035)
  - Proper handling of partial reads and client disconnects
  - Connection timeouts to prevent stuck connections
- **Graceful Shutdown**: Context-based cancellation for clean server termination
- **Type Safety**: Well-structured types for DNS messages, headers, questions, and resource records

## DNS Protocol Implementation

### Supported Record Types
- **A** (1): IPv4 address
- **NS** (2): Name server
- **CNAME** (5): Canonical name
- **SOA** (6): Start of authority
- **MX** (15): Mail exchange
- **TXT** (16): Text record
- **AAAA** (28): IPv6 address
- **OPT** (41): EDNS0 option
- **ANY** (255): All records

### Key Implementation Features

1. **Domain Name Compression**: Properly handles DNS compression pointers (0xC0 prefix)
2. **TCP Length Prefix**: Implements the 2-byte length prefix required for TCP DNS queries
3. **EDNS Support**: Forwards EDNS OPT records to upstream servers for modern DNS features
4. **Concurrent Handling**: Each TCP connection is handled in a separate goroutine
5. **Error Recovery**: Continues serving despite individual query failures
