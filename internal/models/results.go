package models

type ResultsModel struct {
	Identity            BinaryIdentity
	Structure           BinaryStructure
	Functions           []FunctionCall
	FunctionDefinitions []FunctionInfo
	Assembly            AssemblyAnalysis
	Security            SecurityAnalysis
	Findings            []Finding
	Sources             map[string]SourceSummary
}

type BinaryIdentity struct {
	Format       string
	Description  string
	Architecture string
	Class        string
	Endianness   string
	Type         string
	EntryPoint   string
}

type BinaryStructure struct {
	Sections    []string
	Segments    []string
	Libraries   []string
	Symbols     []string
	Relocations int
	DebugInfo   bool
}

type Instruction struct {
	Address  string
	Bytes    string
	Mnemonic string
	Operands string
	Function string
	Target   string
	Kind     string
	Indirect bool
}

type AssemblyAnalysis struct {
	Architecture     string
	Instructions     []Instruction
	Calls            int
	Branches         int
	Returns          int
	StackAllocations []StackAllocation
	StackRelations   []StackRelation
	CallFlows        []CallFlow
}

type StackAllocation struct {
	Address  string
	Function string
	Size     uint64
}

type StackRelation struct {
	Function         string
	API              string
	CallSite         string
	InputReference   string
	ReadSite         string
	CheckedReference string
	BranchSite       string
	Distance         int64
	InitializedZero  bool
	SourceReference  string
	ComparedValue    string
	BranchCondition  string
	Confidence       string
}

type FunctionCall struct {
	Name        string
	Address     string
	Caller      string
	Target      string
	Instruction string
	Indirect    bool
}

type FunctionInfo struct {
	Name         string
	Address      string
	Instructions int
	Calls        []string
	Callers      []string
}

type SecurityCheck struct {
	Status   string
	Evidence string
}

type SecurityAnalysis struct {
	NX     SecurityCheck
	PIE    SecurityCheck
	RELRO  SecurityCheck
	Canary SecurityCheck
	ASLR   SecurityCheck
	CFG    SecurityCheck
}

type ArgumentFlow struct {
	Position       int
	Location       string
	Expression     string
	StackReference string
}

type CallFlow struct {
	Function  string
	API       string
	Address   string
	Arguments []ArgumentFlow
}

type Finding struct {
	ID             string
	Category       string
	Severity       string
	Confidence     string
	Description    string
	Evidence       string
	Recommendation string
}

type SourceSummary struct {
	Available bool
	Lines     int
	Bytes     int
}

var Results ResultsModel
