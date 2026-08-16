package evidence

type HTTPEvidence struct {
	RawRequest      string
	RawResponse     string
	RequestMethod   string
	RequestURL      string
	RequestHeaders  map[string][]string
	ResponseStatus  int
	ResponseHeaders map[string][]string
	RequestBody     []byte
	ResponseBody    []byte
}

func (e *HTTPEvidence) HasStructured() bool {
	return e.RequestMethod != "" || e.RequestURL != "" || e.ResponseStatus != 0 ||
		len(e.RequestHeaders) > 0 || len(e.ResponseHeaders) > 0 || len(e.RequestBody) > 0 || len(e.ResponseBody) > 0
}

func (e *HTTPEvidence) IsEmpty() bool {
	return e.RawRequest == "" && e.RawResponse == "" && !e.HasStructured()
}
