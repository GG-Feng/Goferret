package api

// ToolCall is decoded from a client message (the tags map the wire format).
type ToolCall struct {
	Name string         `json:"name"`
	Path string         `json:"path"`
	Args map[string]any `json:"args"`
}

// Config is built by the program itself: no tags, not decoded data.
type Config struct {
	Root string
}

// Pick returns one of its arguments (a pass-through).
func Pick(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
