package format

import (
	"flag"
	"fmt"
	"io"
	"os"
)

type FormatName string

const (
	FormatJSON     FormatName = "json"
	FormatJSONL    FormatName = "jsonl"
	FormatSARIF    FormatName = "sarif"
	FormatMarkdown FormatName = "markdown"
	FormatHTML     FormatName = "html"
	FormatTerminal FormatName = "terminal"
)

var FormatNames = []FormatName{
	FormatJSON,
	FormatJSONL,
	FormatSARIF,
	FormatMarkdown,
	FormatHTML,
	FormatTerminal,
}

func NewFormatter(name string) (Formatter, error) {
	switch FormatName(name) {
	case FormatJSON:
		return NewJSONFormatter(), nil
	case FormatJSONL:
		return NewJSONLFormatter(), nil
	case FormatSARIF:
		return NewSARIFFormatter(), nil
	case FormatMarkdown, "md":
		return NewMarkdownFormatter(), nil
	case FormatHTML:
		return NewHTMLFormatter(), nil
	case FormatTerminal, "text", "plain":
		return NewTerminalFormatter(), nil
	default:
		return nil, fmt.Errorf("unknown format %q: valid values are json, jsonl, sarif, markdown, html, terminal", name)
	}
}

type CLIFlags struct {
	Format  string
	Output  string
	NoColor bool
}

func RegisterFlags(fs *flag.FlagSet) *CLIFlags {
	f := &CLIFlags{}
	fs.StringVar(&f.Format, "format", "terminal",
		`output format: json | jsonl | sarif | markdown | html | terminal`)
	fs.StringVar(&f.Output, "output", "",
		`file path to write the report (default: stdout)`)
	fs.BoolVar(&f.NoColor, "no-color", false,
		`disable ANSI colors in terminal output`)
	return f
}

func (f *CLIFlags) Formatter() (Formatter, error) {
	if (FormatName(f.Format) == FormatTerminal || f.Format == "text" || f.Format == "plain") && f.NoColor {
		return NewTerminalFormatterNoColor(), nil
	}
	return NewFormatter(f.Format)
}

func (f *CLIFlags) Writer() (io.Writer, func(), error) {
	if f.Output == "" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(f.Output)
	if err != nil {
		return nil, nil, fmt.Errorf("reportx: create output file: %w", err)
	}
	return file, func() { file.Close() }, nil
}
