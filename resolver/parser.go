package resolver

import (
	"fmt"
	"strings"

	"aifia.com/dns-server/types"
)

type MyDNSQuestion struct {
	types.DNSQuestion
}

func Parser(data []byte) (*types.DNSMessage, error) {

	if len(data) < 12 {
		return nil, fmt.Errorf("message too short: %d bytes", len(data))
	}

	header := types.DNSHeader{
		ID:      uint16(data[0])<<8 | uint16(data[1]),
		Flags:   uint16(data[2])<<8 | uint16(data[3]),
		QDCount: uint16(data[4])<<8 | uint16(data[5]),
		ANCount: uint16(data[6])<<8 | uint16(data[7]),
		NSCount: uint16(data[8])<<8 | uint16(data[9]),
		ARCount: uint16(data[10])<<8 | uint16(data[11]),
	}
	offset := 12

	// Parse Questions
	questions, newOffset, err := parseQuestion(data, offset, int(header.QDCount))
	if err != nil {
		return nil, fmt.Errorf("failed to parse questions: %w", err)
	}
	offset = newOffset

	// Parse Answers
	answers, newOffset, err := parseResourceRecords(data, offset, int(header.ANCount))
	if err != nil {
		return nil, fmt.Errorf("failed to parse answers: %w", err)
	}
	offset = newOffset

	// Parse Authorities
	authorities, newOffset, err := parseResourceRecords(data, offset, int(header.NSCount))
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorities: %w", err)
	}
	offset = newOffset

	// Parse Additional
	additional, _, err := parseResourceRecords(data, offset, int(header.ARCount))
	if err != nil {
		return nil, fmt.Errorf("failed to parse additional: %w", err)
	}

	dnsMessage := &types.DNSMessage{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additional:  additional,
	}
	return dnsMessage, nil
}

func parseQuestion(data []byte, offset int, qCount int) ([]types.DNSQuestion, int, error) {
	questions := []types.DNSQuestion{}

	for i := 0; i < qCount; i++ {
		name, bytesRead, err := parseName(data, offset)
		if err != nil {
			return nil, offset, fmt.Errorf("failed to parse question name: %w", err)
		}
		offset += bytesRead

		if offset+4 > len(data) {
			return nil, offset, fmt.Errorf("incomplete question section")
		}

		qType := uint16(data[offset])<<8 | uint16(data[offset+1])
		qClass := uint16(data[offset+2])<<8 | uint16(data[offset+3])
		offset += 4

		questions = append(questions, types.DNSQuestion{
			Name:  name,
			Type:  qType,
			Class: qClass,
		})
	}
	return questions, offset, nil
}

func parseName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", 0, fmt.Errorf("offset out of bounds")
	}

	bytesRead := 0
	labels := []string{}

	for {
		if offset+bytesRead >= len(data) {
			return "", bytesRead, fmt.Errorf("unexpected end of data")
		}

		length := int(data[offset+bytesRead])
		bytesRead++

		if length == 0 {
			break
		}

		if length >= 192 {
			if offset+bytesRead >= len(data) {
				return "", bytesRead, fmt.Errorf("incomplete pointer")
			}

			pointerOffset := ((length & 0x3F) << 8) | int(data[offset+bytesRead])
			bytesRead++
			pointedName, _, err := parseName(data, pointerOffset)
			if err != nil {
				return "", bytesRead, fmt.Errorf("failed to follow pointer: %w", err)
			}

			if len(labels) > 0 {
				labels = append(labels, pointedName)
			} else {
				return pointedName, bytesRead, nil
			}
			break
		}

		if length > 63 {
			return "", bytesRead, fmt.Errorf("invalid label length: %d", length)
		}

		if offset+bytesRead+length > len(data) {
			return "", bytesRead, fmt.Errorf("label extends beyond data")
		}

		labels = append(labels, string(data[offset+bytesRead:offset+bytesRead+length]))
		bytesRead += length
	}
	return joinLabels(labels), bytesRead, nil

}

func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	var builder strings.Builder
	for i, label := range labels {
		if i > 0 {
			builder.WriteByte('.')
		}
		builder.WriteString(label)
	}
	return builder.String()
}

func parseResourceRecords(data []byte, offset int, count int) ([]types.DNSResourceRecord, int, error) {
	records := []types.DNSResourceRecord{}

	for i := 0; i < count; i++ {
		name, bytesRead, err := parseName(data, offset)
		if err != nil {
			return nil, offset, fmt.Errorf("failed to parse RR name: %w", err)
		}
		offset += bytesRead

		if offset+10 > len(data) {
			return nil, offset, fmt.Errorf("incomplete resource record header")
		}

		rrType := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2

		rrClass := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2

		ttl := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
			uint32(data[offset+2])<<8 | uint32(data[offset+3])
		offset += 4

		rdLength := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2

		if offset+int(rdLength) > len(data) {
			return nil, offset, fmt.Errorf("incomplete resource record data")
		}

		rData := make([]byte, rdLength)
		copy(rData, data[offset:offset+int(rdLength)])
		offset += int(rdLength)

		records = append(records, types.DNSResourceRecord{
			Name:     name,
			Type:     rrType,
			Class:    rrClass,
			TTL:      ttl,
			RDLength: rdLength,
			RData:    rData,
		})
	}

	return records, offset, nil
}

func (q MyDNSQuestion) String() string {
	typeName := getTypeName(q.Type)
	className := getClassName(q.Class)
	return fmt.Sprintf("%s (Type:%s Class:%s)", q.Name, typeName, className)
}

func getTypeName(qType uint16) string {
	switch qType {
	case types.TypeA:
		return "A"
	case types.TypeNS:
		return "NS"
	case types.TypeCNAME:
		return "CNAME"
	case types.TypeMX:
		return "MX"
	case types.TypeTXT:
		return "TXT"
	case types.TypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("%d", qType)
	}
}

func getClassName(qClass uint16) string {
	switch qClass {
	case types.ClassIN:
		return "IN"
	case types.ClassCH:
		return "CH"
	case types.ClassHS:
		return "HS"
	default:
		return fmt.Sprintf("%d", qClass)
	}
}
