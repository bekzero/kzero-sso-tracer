import type { Finding } from "../../shared/models";

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

const OPENAI_TIMEOUT = 10000;

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

export const openAIProvider: AIProvider = {
  async call(request: AIRequest, apiKey: string): Promise<AIResponse> {
    if (!apiKey) {
      return {
        content: "",
        provider: "OpenAI",
        success: false,
        error: "No API key configured"
      };
    }

    const prompt = buildPrompt(request);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), OPENAI_TIMEOUT);

    try {
      const response = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [{ role: "user", content: prompt }],
          max_tokens: 500,
          temperature: 0.3
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          content: "",
          provider: "OpenAI",
          success: false,
          error: errorData.error?.message || `API error: ${response.status}`
        };
      }

      const data = await response.json() as { choices?: Array<{ message?: { content?: string } }> };
      const content = data.choices?.[0]?.message?.content || "";

      return {
        content,
        provider: "OpenAI",
        success: true
      };
    } catch (err) {
      clearTimeout(timeoutId);
      const errorMessage = err instanceof Error ? err.message : "Unknown error";
      
      if (errorMessage.includes("abort")) {
        return {
          content: "",
          provider: "OpenAI",
          success: false,
          error: "Request timed out. Please try again."
        };
      }

      return {
        content: "",
        provider: "OpenAI",
        success: false,
        error: errorMessage
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
