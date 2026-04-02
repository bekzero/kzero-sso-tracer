import { describe, it, expect } from "vitest";
import { loadFixture, listFixtures, runRules, validateSanitization } from "./helpers/fixtures";

describe("fixture sanitization policy", () => {
  const fixtures = listFixtures();

  it.each(fixtures)("fixture %s passes sanitization smoke test", (filename) => {
    const fixture = loadFixture(filename);
    const issues = validateSanitization(fixture, filename);
    const issueMsg = issues.length > 0
      ? `Fixture ${filename}: ${issues.join(", ")}`
      : undefined;
    expect(issues.length, issueMsg).toBe(0);
  });
});

describe("zoho successful late capture regression", () => {
  const fixture = loadFixture("zoho-successful-late-capture.json");

  it("parses nameId from real exported SAML artifact without false positive", () => {
    const findings = runRules(fixture.events);
    expect(findings.some(f => f.ruleId === "SAML_MISSING_NAMEID")).toBe(false);
  });

  it("produces no warning-level missing request noise on successful late capture", () => {
    const findings = runRules(fixture.events);
    const missingRequest = findings.find(f => f.ruleId === "SAML_MISSING_REQUEST");
    expect(missingRequest?.severity).not.toBe("warning");
  });

  it("emits SAML_CAPTURE_STARTED_LATE info note appropriately", () => {
    const findings = runRules(fixture.events);
    expect(findings.some(f => f.ruleId === "SAML_CAPTURE_STARTED_LATE")).toBe(true);
  });
});