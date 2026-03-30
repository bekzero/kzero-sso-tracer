import { describe, expect, it } from "vitest";
import oidcFixture from "../src/fixtures/oidc-redirect-mismatch.json";
import samlFixture from "../src/fixtures/saml-audience-mismatch.json";
import { runFindingsEngine } from "../src/rules";

describe("findings engine", () => {
  it("flags OIDC redirect URI mismatch", () => {
    const findings = runFindingsEngine(oidcFixture.normalizedEvents as any);
    expect(findings.some((f) => f.ruleId === "OIDC_REDIRECT_URI_MISMATCH")).toBe(true);
  });

  it("flags SAML audience mismatch", () => {
    const findings = runFindingsEngine(samlFixture.normalizedEvents as any);
    expect(findings.some((f) => f.ruleId === "SAML_AUDIENCE_MISMATCH")).toBe(true);
  });
});
