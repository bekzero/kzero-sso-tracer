import { describe, expect, it } from "vitest";
import { decodeJwt } from "../src/parsers/jwt";

describe("decodeJwt", () => {
  it("decodes header and payload", () => {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: "https://ca.auth.kzero.com/realms/ACME", sub: "123" })).toString("base64url");
    const token = `${header}.${payload}.sig`;
    const decoded = decodeJwt(token);
    expect(decoded?.header.alg).toBe("RS256");
    expect(decoded?.payload.iss).toBe("https://ca.auth.kzero.com/realms/ACME");
  });
});
