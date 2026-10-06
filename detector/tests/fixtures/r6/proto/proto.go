package proto

import "encoding/json"

type Conn interface {
	ReadMessage() (int, []byte, error)
}

type Msg struct{ Path, Name string }

// returns data read from the network, decoded via an out-parameter
func Read(c Conn) (Msg, []byte, error) {
	_, data, err := c.ReadMessage()
	if err != nil {
		return Msg{}, nil, err
	}
	var m Msg
	if err := json.Unmarshal(data, &m); err != nil {
		return Msg{}, nil, err
	}
	return m, data, nil
}
