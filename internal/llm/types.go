package llm

// OllamaRequest represents the request body for the Ollama /api/generate endpoint.
type OllamaRequest struct {
	Model   string        `json:"model"`
	Prompt  string        `json:"prompt"`
	System  string        `json:"system,omitempty"`
	Stream  bool          `json:"stream"`
	Options OllamaOptions `json:"options,omitempty"`
	Format  string        `json:"format,omitempty"`
}

// OllamaOptions configures model inference parameters.
type OllamaOptions struct {
	Temperature   float64 `json:"temperature,omitempty"`
	TopP          float64 `json:"top_p,omitempty"`
	NumCtx        int     `json:"num_ctx,omitempty"`
	NumPredict    int     `json:"num_predict,omitempty"`
	RepeatPenalty float64 `json:"repeat_penalty,omitempty"`
}

// OllamaResponse represents the response from the Ollama /api/generate endpoint.
type OllamaResponse struct {
	Model              string `json:"model"`
	CreatedAt          string `json:"created_at"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	TotalDuration      int64  `json:"total_duration,omitempty"`
	LoadDuration       int64  `json:"load_duration,omitempty"`
	PromptEvalCount    int    `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64  `json:"prompt_eval_duration,omitempty"`
	EvalCount          int    `json:"eval_count,omitempty"`
	EvalDuration       int64  `json:"eval_duration,omitempty"`
}

// LLMFinding represents a single finding returned by the LLM.
type LLMFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Resource    string `json:"resource"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// LLMReviewResponse is the expected structured output from the LLM.
type LLMReviewResponse struct {
	Findings []LLMFinding `json:"findings"`
	Summary  string       `json:"summary"`
}

// ClientConfig holds the configuration for the LLM client.
type ClientConfig struct {
	BaseURL     string
	Model       string
	Temperature float64
	TimeoutSecs int
	NumCtx      int
	MaxTokens   int
	MaxRetries  int
}

// DefaultConfig returns sensible defaults for the LLM client.
func DefaultConfig() ClientConfig {
	return ClientConfig{
		BaseURL:     "http://localhost:11434",
		Model:       "llama3.1:8b",
		Temperature: 0.2,
		TimeoutSecs: 15,
		NumCtx:      4096,
		MaxTokens:   2048,
		MaxRetries:  2,
	}
}
