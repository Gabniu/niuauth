// Ownership: exact-origin CORS contract tests for Better Auth consumers.

import assert from "node:assert/strict";
import test from "node:test";

const previousBaseUrl = process.env.BETTER_AUTH_URL;
const previousTrustedOrigins = process.env.AUTH_TRUSTED_ORIGINS;
process.env.BETTER_AUTH_URL = "https://novaauth.niuautomations.com";
process.env.AUTH_TRUSTED_ORIGINS = "https://booking.niuautomations.com";
const { authCorsHeaders, authCorsOriginAllowed, withAuthCors } = await import("./auth-cors.ts");

test.after(() => {
  if (previousBaseUrl === undefined) delete process.env.BETTER_AUTH_URL;
  else process.env.BETTER_AUTH_URL = previousBaseUrl;
  if (previousTrustedOrigins === undefined) delete process.env.AUTH_TRUSTED_ORIGINS;
  else process.env.AUTH_TRUSTED_ORIGINS = previousTrustedOrigins;
});

test("allows only a configured consumer origin and credentials", () => {
  const request = new Request("https://novaauth.niuautomations.com/api/auth/sign-in/email", { headers: { Origin: "https://booking.niuautomations.com", "Access-Control-Request-Headers": "content-type" } });
  const headers = authCorsHeaders(request);
  assert.equal(headers.get("Access-Control-Allow-Origin"), "https://booking.niuautomations.com");
  assert.equal(headers.get("Access-Control-Allow-Credentials"), "true");
  assert.equal(authCorsOriginAllowed(request), true);
});

test("fails closed for an unregistered origin or header", () => {
  const originRequest = new Request("https://novaauth.niuautomations.com/api/auth/sign-in/email", { headers: { Origin: "https://unknown.example", "Access-Control-Request-Headers": "content-type" } });
  assert.equal(authCorsOriginAllowed(originRequest), false);
  const headerRequest = new Request("https://novaauth.niuautomations.com/api/auth/sign-in/email", { headers: { Origin: "https://booking.niuautomations.com", "Access-Control-Request-Headers": "content-type, x-custom" } });
  assert.equal(authCorsOriginAllowed(headerRequest), false);
});

test("preserves Better Auth response headers and adds the consumer contract", async () => {
  const request = new Request("https://novaauth.niuautomations.com/api/auth/sign-in/email", { headers: { Origin: "https://booking.niuautomations.com" } });
  const response = withAuthCors(request, new Response("ok", { headers: { "content-type": "application/json" } }));
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://booking.niuautomations.com");
  assert.equal(await response.text(), "ok");
});

test("does not broaden the consumer to unrelated Better Auth routes", () => {
  const request = new Request("https://novaauth.niuautomations.com/api/auth/get-session", { headers: { Origin: "https://booking.niuautomations.com" } });
  assert.equal(authCorsOriginAllowed(request), false);
});
