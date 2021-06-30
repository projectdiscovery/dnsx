package runner

type ResumeCfg struct {
	ResumeFrom   string `json:"resume_from,omitempty"`
	Index        int    `json:"index,omitempty"`
	current      string
	currentIndex int
}
