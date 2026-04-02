import { describe, expect, it } from "vitest";
import { migrateSettings, isValidHostname, normalizeHostname } from "../src/shared/settings";

describe("migrateSettings", () => {
  it("new install gets auth-only default", () => {
    const result = migrateSettings(undefined);
    expect(result.captureScope).toBe("auth-only");
    expect(result.hasSeenScopeNotice).toBe(true);
  });

  it("existing user without version gets full capture and notice", () => {
    const result = migrateSettings({});
    expect(result.captureScope).toBe("full");
    expect(result.hasSeenScopeNotice).toBe(false);
  });

  it("preserves existing captureScope if set", () => {
    const result = migrateSettings({ captureScope: "auth-plus-allowlist", allowedHosts: ["test.com"] });
    expect(result.captureScope).toBe("auth-plus-allowlist");
    expect(result.allowedHosts).toEqual(["test.com"]);
  });

  it("upgrades old version properly", () => {
    const result = migrateSettings({ settingsVersion: 1, captureScope: "full" });
    expect(result.settingsVersion).toBe(2);
    expect(result.captureScope).toBe("full");
  });
});

describe("isValidHostname", () => {
  it("accepts valid hostnames", () => {
    expect(isValidHostname("accounts.zoho.com")).toBe(true);
    expect(isValidHostname("ca.auth.kzero.com")).toBe(true);
    expect(isValidHostname("localhost")).toBe(true);
    expect(isValidHostname("sub.domain.example.com")).toBe(true);
  });

  it("rejects URLs with scheme", () => {
    expect(isValidHostname("https://accounts.zoho.com")).toBe(false);
    expect(isValidHostname("http://example.com")).toBe(false);
  });

  it("rejects URLs with paths", () => {
    expect(isValidHostname("zoho.com/login")).toBe(false);
    expect(isValidHostname("example.com/path/to/page")).toBe(false);
  });

  it("rejects URLs with ports", () => {
    expect(isValidHostname("localhost:3000")).toBe(false);
    expect(isValidHostname("example.com:8080")).toBe(false);
  });

  it("rejects URLs with query strings", () => {
    expect(isValidHostname("example.com?foo=bar")).toBe(false);
  });

  it("rejects invalid characters", () => {
    expect(isValidHostname("example.com!")).toBe(false);
    expect(isValidHostname("exam ple.com")).toBe(false);
  });

  it("rejects empty labels", () => {
    expect(isValidHostname(".example.com")).toBe(false);
    expect(isValidHostname("example.com.")).toBe(false);
    expect(isValidHostname("example..com")).toBe(false);
  });

  it("handles whitespace via normalize", () => {
    expect(normalizeHostname("  example.com  ")).toBe("example.com");
  });
});

describe("normalizeHostname", () => {
  it("removes scheme", () => {
    expect(normalizeHostname("https://example.com")).toBe("example.com");
    expect(normalizeHostname("http://example.com")).toBe("example.com");
  });

  it("removes path", () => {
    expect(normalizeHostname("example.com/login")).toBe("example.com");
    expect(normalizeHostname("example.com/path/to/page")).toBe("example.com");
  });

  it("lowercases", () => {
    expect(normalizeHostname("EXAMPLE.COM")).toBe("example.com");
    expect(normalizeHostname("ExAmPlE.CoM")).toBe("example.com");
  });

  it("trims whitespace", () => {
    expect(normalizeHostname("  example.com  ")).toBe("example.com");
  });
});