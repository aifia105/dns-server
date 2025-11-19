package resolver

import (
	"strings"

	"aifia.com/dns-server/types"
)

func Serializer(msg *types.DNSMessage) ([]byte, error) {

	var responseData []byte
	responseData = append(responseData, encodeHeader(&msg.Header)...)

	for _, q := range msg.Questions {
		responseData = append(responseData, encodeQuestion(&q)...)
	}

	for _, answer := range msg.Answers {
		responseData = append(responseData, encodeAnswer(&answer)...)
	}

	for _, authority := range msg.Authorities {
		responseData = append(responseData, encodeAuthority(&authority)...)
	}

	for _, additional := range msg.Additional {
		responseData = append(responseData, encodeAdditional(&additional)...)
	}

	return responseData, nil

}

func encodeHeader(header *types.DNSHeader) []byte {
	data := make([]byte, 12)
	data[0] = byte(header.ID >> 8)
	data[1] = byte(header.ID & 0xFF)
	data[2] = byte(header.Flags >> 8)
	data[3] = byte(header.Flags & 0xFF)
	data[4] = byte(header.QDCount >> 8)
	data[5] = byte(header.QDCount & 0xFF)
	data[6] = byte(header.ANCount >> 8)
	data[7] = byte(header.ANCount & 0xFF)
	data[8] = byte(header.NSCount >> 8)
	data[9] = byte(header.NSCount & 0xFF)
	data[10] = byte(header.ARCount >> 8)
	data[11] = byte(header.ARCount & 0xFF)
	return data
}

func encodeName(name string) []byte {
	var encoded []byte

	labels := strings.Split(name, ".")

	for _, label := range labels {
		if label == "" {
			continue
		}

		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}
	encoded = append(encoded, 0)
	return encoded
}

func encodeQuestion(question *types.DNSQuestion) []byte {
	var data []byte

	data = append(data, encodeName(question.Name)...)

	data = append(data, byte(question.Type>>8))
	data = append(data, byte(question.Type&0xFF))
	data = append(data, byte(question.Class>>8))
	data = append(data, byte(question.Class&0xFF))

	return data
}

func encodeAnswer(response *types.DNSResourceRecord) []byte {
	var data []byte

	data = append(data, encodeName(response.Name)...)

	data = append(data, byte(response.Type>>8))
	data = append(data, byte(response.Type&0xFF))
	data = append(data, byte(response.Class>>8))
	data = append(data, byte(response.Class&0xFF))

	data = append(data, byte(response.TTL>>24))
	data = append(data, byte(response.TTL>>16))
	data = append(data, byte(response.TTL>>8))
	data = append(data, byte(response.TTL&0xFF))

	data = append(data, byte(response.RDLength>>8))
	data = append(data, byte(response.RDLength&0xFF))

	data = append(data, response.RData...)

	return data
}

func encodeAuthority(authority *types.DNSResourceRecord) []byte {
	var data []byte

	data = append(data, encodeName(authority.Name)...)

	data = append(data, byte(authority.Type>>8))
	data = append(data, byte(authority.Type&0xFF))
	data = append(data, byte(authority.Class>>8))
	data = append(data, byte(authority.Class&0xFF))

	data = append(data, byte(authority.TTL>>24))
	data = append(data, byte(authority.TTL>>16))
	data = append(data, byte(authority.TTL>>8))
	data = append(data, byte(authority.TTL&0xFF))

	data = append(data, byte(authority.RDLength>>8))
	data = append(data, byte(authority.RDLength&0xFF))

	data = append(data, authority.RData...)

	return data
}

func encodeAdditional(additional *types.DNSResourceRecord) []byte {
	var data []byte

	data = append(data, encodeName(additional.Name)...)

	data = append(data, byte(additional.Type>>8))
	data = append(data, byte(additional.Type&0xFF))
	data = append(data, byte(additional.Class>>8))
	data = append(data, byte(additional.Class&0xFF))

	data = append(data, byte(additional.TTL>>24))
	data = append(data, byte(additional.TTL>>16))
	data = append(data, byte(additional.TTL>>8))
	data = append(data, byte(additional.TTL&0xFF))

	data = append(data, byte(additional.RDLength>>8))
	data = append(data, byte(additional.RDLength&0xFF))

	data = append(data, additional.RData...)

	return data
}
