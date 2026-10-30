package prommetrics

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

type family struct {
	name    string
	help    string
	typ     string
	samples map[string]sample
}

type sample struct {
	labels map[string]string
	value  float64
}

func NewRegistry() *Registry {
	return &Registry{families: map[string]*family{}}
}

func (r *Registry) IncCounter(name, help string, labels map[string]string, delta float64) {
	if r == nil || delta == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.ensureFamilyLocked(name, help, "counter")
	key := labelsKey(labels)
	item := f.samples[key]
	item.labels = cloneLabels(labels)
	item.value += delta
	f.samples[key] = item
}

func (r *Registry) SetCounter(name, help string, labels map[string]string, value float64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.ensureFamilyLocked(name, help, "counter")
	key := labelsKey(labels)
	f.samples[key] = sample{labels: cloneLabels(labels), value: value}
}

func (r *Registry) SetGauge(name, help string, labels map[string]string, value float64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.ensureFamilyLocked(name, help, "gauge")
	key := labelsKey(labels)
	f.samples[key] = sample{labels: cloneLabels(labels), value: value}
}

func (r *Registry) Render() []byte {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	families := make([]family, 0, len(r.families))
	for _, item := range r.families {
		if item == nil {
			continue
		}
		copyFamily := family{
			name:    item.name,
			help:    item.help,
			typ:     item.typ,
			samples: make(map[string]sample, len(item.samples)),
		}
		for key, value := range item.samples {
			copyFamily.samples[key] = sample{labels: cloneLabels(value.labels), value: value.value}
		}
		families = append(families, copyFamily)
	}
	r.mu.Unlock()

	sort.Slice(families, func(i, j int) bool { return families[i].name < families[j].name })
	var buffer bytes.Buffer
	for _, item := range families {
		buffer.WriteString("# HELP ")
		buffer.WriteString(item.name)
		buffer.WriteByte(' ')
		buffer.WriteString(escapeHelp(item.help))
		buffer.WriteByte('\n')
		buffer.WriteString("# TYPE ")
		buffer.WriteString(item.name)
		buffer.WriteByte(' ')
		buffer.WriteString(item.typ)
		buffer.WriteByte('\n')

		keys := make([]string, 0, len(item.samples))
		for key := range item.samples {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			entry := item.samples[key]
			buffer.WriteString(item.name)
			if len(entry.labels) > 0 {
				buffer.WriteByte('{')
				buffer.WriteString(renderLabels(entry.labels))
				buffer.WriteByte('}')
			}
			buffer.WriteByte(' ')
			buffer.WriteString(formatFloat(entry.value))
			buffer.WriteByte('\n')
		}
	}
	return buffer.Bytes()
}

func (r *Registry) ensureFamilyLocked(name, help, typ string) *family {
	if existing := r.families[name]; existing != nil {
		return existing
	}
	item := &family{
		name:    strings.TrimSpace(name),
		help:    strings.TrimSpace(help),
		typ:     strings.TrimSpace(typ),
		samples: map[string]sample{},
	}
	r.families[item.name] = item
	return item
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func labelsKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, "|")
}

func renderLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, key, escapeLabelValue(labels[key])))
	}
	return strings.Join(parts, ",")
}

func escapeLabelValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return replacer.Replace(value)
}

func escapeHelp(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "\n", " ")
}

func formatFloat(value float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", value), "0"), ".")
}
