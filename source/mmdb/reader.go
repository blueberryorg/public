package main

import (
	"github.com/ice-cream-heaven/log"
	"github.com/pterm/pterm"
	"os"
)

type FileReader struct {
	file *os.File
	bar  *pterm.ProgressbarPrinter
}

func (p *FileReader) Read(b []byte) (n int, err error) {
	n, err = p.file.Read(b)
	p.bar.Add(n)
	return n, err
}

func (p *FileReader) Close() error {
	_, _ = p.bar.Stop()
	return p.file.Close()
}

func NewFileReader(name string, file *os.File) (*FileReader, error) {
	stat, err := file.Stat()
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	bar, err := pterm.DefaultProgressbar.
		WithTitle(name).
		WithTotal(int(stat.Size())).
		WithRemoveWhenDone(true).
		WithShowTitle(true).
		WithShowCount(false).
		WithShowPercentage(true).
		WithShowElapsedTime(true).
		Start()
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	p := &FileReader{
		file: file,
		bar:  bar,
	}

	return p, nil
}
