package structuredlog

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Logger struct {
	component string
	logger    *slog.Logger
}

func New(component string) *Logger {
	return NewWithWriter(component, os.Stdout)
}

func NewWithWriter(component string, writer io.Writer) *Logger {
	normalizedComponent := strings.TrimSpace(component)
	if normalizedComponent == "" {
		normalizedComponent = "ole"
	}
	if writer == nil {
		writer = io.Discard
	}
	base := slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{AddSource: false}))
	return &Logger{
		component: normalizedComponent,
		logger:    base.With("service", "ole", "component", normalizedComponent),
	}
}

func (l *Logger) Component() string {
	if l == nil {
		return ""
	}
	return l.component
}

func (l *Logger) Info(message string, keyvals ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Info(strings.TrimSpace(message), normalizeKeyvals(keyvals...)...)
}

func (l *Logger) Error(message string, keyvals ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Error(strings.TrimSpace(message), normalizeKeyvals(keyvals...)...)
}

func FieldsMap(keyvals ...any) map[string]string {
	normalized := normalizeKeyvals(keyvals...)
	if len(normalized) == 0 {
		return nil
	}
	fields := make(map[string]string, len(normalized)/2)
	for idx := 0; idx+1 < len(normalized); idx += 2 {
		key := strings.TrimSpace(fmt.Sprint(normalized[idx]))
		if key == "" {
			continue
		}
		fields[key] = stringifyValue(normalized[idx+1])
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func normalizeKeyvals(keyvals ...any) []any {
	if len(keyvals) == 0 {
		return nil
	}
	normalized := make([]any, 0, len(keyvals)+1)
	for idx := 0; idx < len(keyvals); idx += 2 {
		key := fmt.Sprintf("field_%d", idx/2)
		if idx < len(keyvals) {
			if candidate := strings.TrimSpace(fmt.Sprint(keyvals[idx])); candidate != "" {
				key = candidate
			}
		}
		normalized = append(normalized, key)
		if idx+1 < len(keyvals) {
			normalized = append(normalized, normalizeValue(keyvals[idx+1]))
			continue
		}
		normalized = append(normalized, "")
	}
	return normalized
}

func normalizeValue(value any) any {
	switch typed := value.(type) {
	case error:
		if typed == nil {
			return ""
		}
		return typed.Error()
	default:
		return value
	}
}

func stringifyValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case error:
		return typed.Error()
	default:
		return fmt.Sprint(typed)
	}
}
