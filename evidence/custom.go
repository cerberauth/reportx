package evidence

type CustomEvidence struct {
	Data map[string]any
}

func (e *CustomEvidence) IsEmpty() bool {
	return len(e.Data) == 0
}
