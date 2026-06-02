package format

import "github.com/cerberauth/reportx"

const defaultTitle = "Security Report"

type Formatter interface {
	Format(r *reportx.Report) ([]byte, error)
	MediaType() string
	FileExtension() string
}
