package verifier

import "fmt"

// Raw values remain in this in-memory boundary. Comparison contains only redacted evidence.
type RawField struct {
	Ref, Record              string
	Role, Path               string
	Observed, Classification string
	Value                    *string
	ValueType                string
	ElementCount             int
	GroupRef                 *string
}

func (field *RawField) Length() int {
	if field.Value == nil {
		return 0
	}

	return len([]rune(*field.Value))
}

func (field *RawField) Text() string {
	if field == nil || field.Value == nil {
		return ""
	}

	return *field.Value
}

type RawRecord struct {
	Ref, Source   string
	Position      int
	Kind          string
	Fields        []*RawField
	Hosts         map[string]bool
	NativeIDValid bool
	NativeID      *string
}

func NewRecord(ref, source string, position int, kind string) *RawRecord {
	return &RawRecord{
		Ref:      ref,
		Source:   source,
		Position: position,
		Kind:     kind,
		Hosts:    map[string]bool{},
	}
}

func (record *RawRecord) Add(
	role, path, observed, class, valueType string,
	value *string,
	elementCount int,
	group *string,
) *RawField {
	field := &RawField{
		Ref:            fmt.Sprintf("%sF%03d", record.Ref, len(record.Fields)+1),
		Record:         record.Ref,
		Role:           role,
		Path:           path,
		Observed:       observed,
		Classification: class,
		Value:          value,
		ValueType:      valueType,
		ElementCount:   elementCount,
		GroupRef:       group,
	}

	record.Fields = append(record.Fields, field)
	return field
}

func (record *RawRecord) Get(role string) *RawField {
	for _, field := range record.Fields {
		if field.Role == role {
			return field
		}
	}

	return nil
}

func (record *RawRecord) Value(role string) string { return record.Get(role).Text() }

type Case struct {
	Bitwarden, Apple, Supplemental []*RawRecord
	Root                           *RawRecord
	AppleHeaders                   map[string]bool
}

func (caseData *Case) AllRecords() []*RawRecord {
	out := make([]*RawRecord, 0, len(caseData.Bitwarden)+len(caseData.Apple)+len(caseData.Supplemental)+1)
	out = append(out, caseData.Bitwarden...)
	out = append(out, caseData.Apple...)
	out = append(out, caseData.Supplemental...)
	if caseData.Root != nil {
		out = append(out, caseData.Root)
	}

	return out
}

type Record struct {
	Ref            string  `json:"ref"`
	Snapshot       string  `json:"snapshot"`
	Position       int     `json:"position"`
	Kind           string  `json:"kind"`
	NativeIDValid  bool    `json:"native_id_valid"`
	NativeID       *string `json:"native_id"`
	Title          string  `json:"title"`
	Username       string  `json:"username"`
	Domains        string  `json:"domains"`
	WebsiteOrigins string  `json:"website_origins"`
}

type Field struct {
	Ref            string  `json:"ref"`
	Record         string  `json:"record"`
	Role           string  `json:"role"`
	Observed       string  `json:"observed"`
	Classification string  `json:"classification"`
	Length         int     `json:"length"`
	PathDepth      int     `json:"path_depth"`
	ValueType      string  `json:"value_type"`
	ElementCount   int     `json:"element_count"`
	GroupRef       *string `json:"group_ref"`
	DisplayName    string  `json:"display_name"`
}

type Occurrence struct {
	FieldRef  string `json:"field_ref"`
	RecordRef string `json:"record_ref"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Ordinal   int    `json:"ordinal"`
	Start     int    `json:"start"`
	End       int    `json:"end"`
	Line      int    `json:"line"`
	Block     int    `json:"block"`
}

type Match struct {
	SourceField      string `json:"source_field"`
	DestinationField string `json:"destination_field"`
	SourceStart      int    `json:"source_start"`
	SourceEnd        int    `json:"source_end"`
	DestinationStart int    `json:"destination_start"`
	DestinationEnd   int    `json:"destination_end"`
	Method           string `json:"method"`
}

type RecordDomain struct {
	RecordRef string `json:"record_ref"`
	Domain    string `json:"domain"`
}

type SearchLimit struct {
	FieldRef string `json:"field_ref"`
	Cause    string `json:"cause"`
}

type Equality [3]string

type Snapshot struct {
	Ref           string
	SourceType    string
	ObservedCount int
	Coverage      string
}

type IndexLimit struct {
	RecordRef        string
	FieldRef         string
	Indexed, Omitted int
}

type Comparison struct {
	Records       []Record       `json:"records"`
	Fields        []Field        `json:"fields"`
	RecordDomains []RecordDomain `json:"record_domains"`
	Matches       []Match        `json:"matches"`
	SearchLimits  []SearchLimit  `json:"search_limits"`
	Equality      []Equality     `json:"equality"`
	Snapshots     []Snapshot     `json:"snapshots"`
	Occurrences   []Occurrence   `json:"occurrences"`
	IndexLimits   []IndexLimit   `json:"index_limits"`
}

func NewComparison() Comparison {
	return Comparison{
		Records:       []Record{},
		Fields:        []Field{},
		RecordDomains: []RecordDomain{},
		Matches:       []Match{},
		SearchLimits:  []SearchLimit{},
		Equality:      []Equality{},
		Snapshots:     []Snapshot{},
		Occurrences:   []Occurrence{},
		IndexLimits:   []IndexLimit{},
	}
}
