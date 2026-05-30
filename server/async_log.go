package main

import (
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"
)

var (
	logCh     = make(chan *RequestLog, 4096)
	logOnce   sync.Once
)

func initAsyncLogWriter() {
	logOnce.Do(func() {
		go logWriterLoop()
	})
}

func asyncLogInsert(entry *RequestLog) {
	initAsyncLogWriter()
	select {
	case logCh <- entry:
	default:
		log.Printf("[WARN] asyncLogInsert: channel full, dropping log entry")
		dbInsertLog(entry)
	}
}

func logWriterLoop() {
	batch := make([]*RequestLog, 0, 100)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case entry := <-logCh:
			batch = append(batch, entry)
			if len(batch) >= 100 {
				flushLogBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			drain:
		 for {
				select {
				case entry := <-logCh:
					batch = append(batch, entry)
				default:
					break drain
				}
			}
			if len(batch) > 0 {
				flushLogBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func flushLogBatch(batch []*RequestLog) {
	if gormDB == nil {
		return
	}
	for _, entry := range batch {
		dbInsertLog(entry)
	}
}

type streamTokenExtractor struct {
	buf         strings.Builder
	inputTok    int
	outputTok   int
}

func newStreamTokenExtractor() *streamTokenExtractor {
	return &streamTokenExtractor{}
}

func (s *streamTokenExtractor) feed(data []byte) {
	s.buf.Write(data)
	content := s.buf.String()
	for {
		idx := strings.LastIndex(content, "\n")
		if idx == -1 {
			break
		}
		complete := content[:idx]
		content = content[idx+1:]
		lines := strings.Split(complete, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			payload := strings.TrimPrefix(line, "data: ")
			if payload == "[DONE]" {
				continue
			}
			var chunk map[string]interface{}
			if json.Unmarshal([]byte(payload), &chunk) != nil {
				continue
			}
			if usage, ok := chunk["usage"].(map[string]interface{}); ok {
				if v, ok := usage["prompt_tokens"].(float64); ok {
					s.inputTok = int(v)
				} else if v, ok := usage["input_tokens"].(float64); ok {
					s.inputTok = int(v)
				}
				if v, ok := usage["completion_tokens"].(float64); ok {
					s.outputTok = int(v)
				} else if v, ok := usage["output_tokens"].(float64); ok {
					s.outputTok = int(v)
				}
			}
		}
	}
	s.buf.Reset()
	s.buf.WriteString(content)
}

func (s *streamTokenExtractor) tokens() (int, int) {
	return s.inputTok, s.outputTok
}
