package resolver

import (
	"fmt"
	"net"
	"time"

	"aifia.com/dns-server/types"
)

func Resolve(query *types.DNSMessage) (*types.DNSMessage, error) {

	if len(query.Questions) == 0 {
		return buildErrorMessage(query, types.RCodeFormErr), nil
	}

	upStream := "8.8.8.8:53"
	response, err := forwardDNSQuery(upStream, query)
	if err != nil {
		fmt.Printf("Error forwarding to upstream: %v\n", err)
		return buildErrorMessage(query, types.RCodeServFail), nil
	}

	return response, nil

}

func forwardDNSQuery(upstream string, query *types.DNSMessage) (*types.DNSMessage, error) {

	data, err := serializeQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize query: %w", err)
	}

	conn, err := net.DialTimeout("udp", upstream, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to upstream: %w", err)
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from upstream: %w", err)
	}

	response, err := Parser(buffer[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse response from upstream: %w", err)
	}

	response.Header.ID = query.Header.ID

	return response, nil
}

func serializeQuery(query *types.DNSMessage) ([]byte, error) {
	var data []byte

	data = append(data, encodeHeader(&query.Header)...)

	for _, q := range query.Questions {
		data = append(data, encodeQuestion(&q)...)
	}

	// Include Additional records (e.g., EDNS OPT records)
	for _, additional := range query.Additional {
		data = append(data, encodeAdditional(&additional)...)
	}

	return data, nil
}

func buildErrorMessage(query *types.DNSMessage, rcode uint16) *types.DNSMessage {
	return &types.DNSMessage{
		Header:    *buildResponseHeader(&query.Header, 0, rcode),
		Questions: query.Questions,
		Answers:   []types.DNSResourceRecord{},
	}
}

func buildResponseHeader(query *types.DNSHeader, answerCount uint16, rcode uint16) *types.DNSHeader {
	flags := uint16(0x8000)
	flags |= (query.Flags & 0x0100)
	flags |= 0x0080
	flags |= (rcode & 0x000F)

	return &types.DNSHeader{
		ID:      query.ID,
		Flags:   flags,
		QDCount: query.QDCount,
		ANCount: answerCount,
		NSCount: 0,
		ARCount: 0,
	}
}
