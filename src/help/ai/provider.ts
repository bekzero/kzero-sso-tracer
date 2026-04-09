import type { Finding } from "../../shared/models";
import { logDebug } from "../../shared/debugLog";

export interface AIRequest {
  question: string;
  findings?: Finding[];
  includeFindings: boolean;
}

export interface AIResponse {
  content: string;
  provider: string;
  success: boolean;
  error?: string;
}

export interface AIProvider {
  call(request: AIRequest, apiKey: string): Promise<AIResponse>;
}

const OPENAI_TIMEOUT = 15000;
const OPENAI_MODEL = "gpt-4o-mini";
const OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions";

function buildPrompt(request: AIRequest): string {
  let prompt = `You are an SSO troubleshooting assistant for the KZero Passwordless SSO Tracer extension. `;
  prompt += `Help users understand and fix identity/federation login issues. `;
  prompt += `Keep answers concise, practical, and focused on actionable steps.\n\n`;

  if (request.includeFindings && request.findings && request.findings.length > 0) {
    prompt += `Current findings from user's capture:\n`;
    request.findings.slice(0, 5).forEach(f => {
      prompt += `- ${f.title}: ${f.explanation}\n`;
    });
    prompt += `\n`;
  }

  prompt += `User question: ${request.question}\n\n`;
  prompt += `Provide a helpful, concise answer. If the question is about a specific error, explain what it means and what to check.`;
  return prompt;
}

type AIErrorKind = "missing_key" | "timeout" | "fetch_error" | "http_error" | "parse_error" | "unknown";

interface AIErrorInfo {
  kind: AIErrorKind;
  message: string;
  statusCode?: number;
}

function classifyError(err: unknown, response?: Response): AIErrorInfo {
  if (!err) {
    return { kind: "unknown", message: "Unknown error" };
  }

  const errorMessage = err instanceof Error ? err.message : String(err);

  if (errorMessage.includes("abort")) {
    return { kind: "timeout", message: "Request timed out. Please try again or check your connection." };
  }

  if (errorMessage.includes("Failed to fetch") || errorMessage.includes("fetch") || errorMessage.includes("Content Security Policy")) {
    return { 
      kind: "fetch_error", 
      message: "Network request was blocked. This may be due to firewall, VPN, proxy, or CSP restrictions. Your deterministic answer is shown above." 
    };
  }

  if (response) {
    return { 
      kind: "http_error", 
      message: `API request failed with status ${response.status}: ${response.statusText}. Check your API key and quota.`,
      statusCode: response.status 
    };
  }

  return { kind: "unknown", message: errorMessage };
}

export const openAIProvider: AIProvider = {
  async call(request: AIRequest, apiKey: string): Promise<AIResponse> {
    if (!apiKey || !apiKey.trim()) {
      void logDebug("ai", "AI request skipped - no API key");
      return {
        content: "",
        provider: "OpenAI",
        success: false,
        error: "No API key configured. Add your OpenAI API key in Settings to enable AI assistance."
      };
    }

    const prompt = buildPrompt(request);
    const requestStartTime = Date.now();

    void logDebug("ai", "AI request started", { 
      model: OPENAI_MODEL, 
      promptLength: prompt.length,
      hasFindings: Boolean(request.findings && request.findings.length > 0)
    });

    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
      void logDebug("ai", "AI request timed out", { timeout: OPENAI_TIMEOUT });
    }, OPENAI_TIMEOUT);

    let response: Response | undefined;
    
    try {
      void logDebug("ai", "Sending request to OpenAI", { endpoint: OPENAI_ENDPOINT });
      
      response = await fetch(OPENAI_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey.trim()}`
        },
        body: JSON.stringify({
          model: OPENAI_MODEL,
          messages: [{ role: "user", content: prompt }],
          max_tokens: 500,
          temperature: 0.3
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      const requestDuration = Date.now() - requestStartTime;
      
      void logDebug("ai", "AI response received", { 
        status: response.status, 
        statusText: response.statusText,
        duration: requestDuration 
      });

      if (!response.ok) {
        let errorData: { error?: { message?: string } } | null = null;
        try {
          errorData = await response.json() as { error?: { message?: string } } | null;
        } catch {
          void logDebug("ai", "Failed to parse error response", { status: response.status });
        }
        
        const apiErrorMsg = errorData?.error?.message;
        const errorMsg = apiErrorMsg || `API error: ${response.status}`;
        
        void logDebug("ai", "AI HTTP error", { status: response.status, error: errorMsg });
        
        return {
          content: "",
          provider: "OpenAI",
          success: false,
          error: errorMsg
        };
      }

      let data: unknown;
      try {
        data = await response.json();
      } catch {
        void logDebug("ai", "Failed to parse AI response JSON");
        return {
          content: "",
          provider: "OpenAI",
          success: false,
          error: "Invalid response from AI. Please try again."
        };
      }

      const responseData = data as { choices?: Array<{ message?: { content?: string } }> };
      const content = responseData.choices?.[0]?.message?.content || "";

      void logDebug("ai", "AI request completed", { 
        contentLength: content.length,
        duration: Date.now() - requestStartTime
      });

      return {
        content,
        provider: "OpenAI",
        success: true
      };
    } catch (err) {
      clearTimeout(timeoutId);
      const errorInfo = classifyError(err, response);
      
      void logDebug("ai", "AI request failed", { 
        kind: errorInfo.kind, 
        message: errorInfo.message,
        hasResponse: Boolean(response)
      });

      return {
        content: "",
        provider: "OpenAI",
        success: false,
        error: errorInfo.message
      };
    }
  }
};

export async function callAI(
  request: AIRequest,
  apiKey: string,
  provider: AIProvider = openAIProvider
): Promise<AIResponse> {
  return provider.call(request, apiKey);
}
