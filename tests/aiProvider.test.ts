import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { openAIProvider, callAI } from "../src/help/ai/provider";

const mockFetch = vi.fn();
global.fetch = mockFetch;

describe("openAIProvider", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("call behavior", () => {
    it("returns error when API key is missing", async () => {
      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        ""
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("No API key configured");
      expect(result.provider).toBe("OpenAI");
    });

    it("returns error when API key is whitespace only", async () => {
      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "   "
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("No API key configured");
    });

    it("handles timeout with clear message", async () => {
      mockFetch.mockImplementation(() => 
        new Promise((_, reject) => {
          setTimeout(() => {
            const err = new Error("The operation was aborted.");
            err.name = "AbortError";
            reject(err);
          }, 100);
        })
      );

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("timed out");
    });

    it("handles fetch rejection with clear message", async () => {
      mockFetch.mockRejectedValue(new Error("Failed to fetch"));

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("Network request");
    });

    it("handles non-OK HTTP response", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        json: vi.fn().mockResolvedValue({ error: { message: "Invalid API key" } })
      });

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid API key");
    });

    it("handles non-OK HTTP response without body", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 429,
        statusText: "Rate Limit Exceeded",
        json: vi.fn().mockRejectedValue(new Error("Invalid JSON"))
      });

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("429");
    });

    it("handles malformed JSON response", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockRejectedValue(new Error("Invalid JSON"))
      });

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid response");
    });

    it("returns successful AI response", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({
          choices: [{ message: { content: "Test AI response" } }]
        })
      });

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(true);
      expect(result.content).toBe("Test AI response");
      expect(result.provider).toBe("OpenAI");
    });

    it("returns empty content when AI response is empty", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({
          choices: [{ message: { content: "" } }]
        })
      });

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(true);
      expect(result.content).toBe("");
    });

    it("handles missing choices in response", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({})
      });

      const result = await openAIProvider.call(
        { question: "test", includeFindings: false },
        "sk-test-key"
      );

      expect(result.success).toBe(true);
      expect(result.content).toBe("");
    });

    it("includes findings when requested", async () => {
      const mockJson = vi.fn().mockResolvedValue({
        choices: [{ message: { content: "Response with findings" } }]
      });
      
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: mockJson
      });

      const findings = [
        {
          id: "f1",
          ruleId: "TEST",
          severity: "error" as const,
          protocol: "SAML" as const,
          likelyOwner: "KZero" as const,
          title: "Test finding",
          explanation: "Test explanation",
          observed: "observed",
          expected: "expected",
          evidence: [],
          likelyFix: { kzeroFields: [], vendorFields: [], action: "fix" },
          confidence: 0.9,
          confidenceLevel: "high" as const
        }
      ];

      const result = await openAIProvider.call(
        { question: "test", findings, includeFindings: true },
        "sk-test-key"
      );

      expect(result.success).toBe(true);
      
      const fetchCall = mockFetch.mock.calls[0];
      const body = JSON.parse(fetchCall[1].body as string);
      expect(body.messages[0].content).toContain("Test finding");
    });

    it("limits findings to 5 items", async () => {
      const mockJson = vi.fn().mockResolvedValue({
        choices: [{ message: { content: "Response" } }]
      });
      
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: mockJson
      });

      const findings = Array.from({ length: 10 }, (_, i) => ({
        id: `f${i}`,
        ruleId: `RULE_${i}`,
        severity: "error" as const,
        protocol: "SAML" as const,
        likelyOwner: "KZero" as const,
        title: `Finding ${i}`,
        explanation: `Explanation ${i}`,
        observed: "observed",
        expected: "expected",
        evidence: [],
        likelyFix: { kzeroFields: [], vendorFields: [], action: "fix" },
        confidence: 0.9,
        confidenceLevel: "high" as const
      }));

      await openAIProvider.call(
        { question: "test", findings, includeFindings: true },
        "sk-test-key"
      );

      const fetchCall = mockFetch.mock.calls[0];
      const body = JSON.parse(fetchCall[1].body as string);
      expect(body.messages[0].content).toContain("Finding 0");
      expect(body.messages[0].content).not.toContain("Finding 5");
    });
  });

  describe("callAI wrapper", () => {
    it("calls the default provider", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({
          choices: [{ message: { content: "Wrapper test" } }]
        })
      });

      const result = await callAI({ question: "test", includeFindings: false }, "sk-key");
      expect(result.content).toBe("Wrapper test");
    });

    it("allows custom provider", async () => {
      const customProvider = {
        call: vi.fn().mockResolvedValue({
          content: "Custom provider response",
          provider: "Custom",
          success: true
        })
      };

      const result = await callAI({ question: "test", includeFindings: false }, "sk-key", customProvider);
      expect(result.content).toBe("Custom provider response");
      expect(customProvider.call).toHaveBeenCalled();
    });
  });
});