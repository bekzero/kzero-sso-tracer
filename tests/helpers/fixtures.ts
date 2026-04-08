import * as fs from "fs";
import * as path from "path";
import type { NormalizedEvent, Finding } from "../../src/shared/models";
import { runFindingsEngine } from "../../src/rules";

export interface FixtureAssertions {
  nameIdPresent?: boolean;
  noFalsePositiveNameId?: boolean;
  noWarningMissingRequest?: boolean;
  captureStartedLateNote?: boolean;
}

export interface SanitizedFixture {
  name: string;
  description: string;
  events: NormalizedEvent[];
  assertions: FixtureAssertions;
}

const FIXTURES_DIR = path.join(__dirname, "..", "fixtures", "real-world");

export const loadFixture = (filename: string): SanitizedFixture => {
  const filePath = path.join(FIXTURES_DIR, filename);
  const content = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(content) as SanitizedFixture;
};

export const listFixtures = (): string[] => {
  return fs.readdirSync(FIXTURES_DIR).filter(f => f.endsWith(".json"));
};

export const runRules = (events: NormalizedEvent[]): Finding[] => {
  return runFindingsEngine(events);
};

export const validateSanitization = (
  fixture: SanitizedFixture,
  _filename: string
): string[] => {
  const issues: string[] = [];
  const json = JSON.stringify(fixture).toLowerCase();

  // Check for real emails (not example.com or example.org)
  if (
    /\b[a-z][a-z0-9.*_-]*@[a-z0-9.-]+\.[a-z]{2,}\b/.test(json) &&
    !json.includes("example.com") &&
    !json.includes("example.org") &&
    !json.includes("test@example")
  ) {
    issues.push("possible real email address");
  }

  // Check for JWT-like tokens
  if (/eyj[a-z0-9_-]{10,}\.eyj[a-z0-9_-]*/.test(json)) {
    issues.push("possible JWT token");
  }

  // Check for sensitive key names in any field value
  const sensitiveKeys = [
    "access_token",
    "refresh_token",
    "client_secret",
    "id_token",
    "password",
    "secret"
  ];
  for (const key of sensitiveKeys) {
    if (json.includes(`"${key}"`)) {
      issues.push(`possible sensitive key: ${key}`);
    }
  }

  // Check for long base64-like blobs in suspicious fields
  if (/"samlresponse":\s*"[a-z0-9+/=]{200,}"/.test(json)) {
    issues.push("large base64 value in samlResponse - verify it's sanitized");
  }

  return issues;
};