// Ownership: narrow cross-origin boundary for approved Better Auth consumers.

import { authRuntimeConfig } from "./runtime-config.ts";

const allowedRequestHeaders = new Set(["content-type", "x-requested-with", "x-better-auth-client"]);
const credentialedConsumerPaths = new Set(["/api/auth/sign-in/email"]);

function allowedPath(request: Request): boolean {
  const path = new URL(request.url).pathname.replace(/\/$/u, "");
  return credentialedConsumerPaths.has(path);
}

function allowedOrigin(origin: string | null): origin is string {
  if (!origin) return false;
  return new Set([authRuntimeConfig.baseUrl, ...authRuntimeConfig.trustedOrigins].filter(Boolean)).has(origin);
}

function requestedHeaders(request: Request): string[] {
  return (request.headers.get("access-control-request-headers") ?? "content-type")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

export function authCorsHeaders(request: Request): Headers {
  const headers = new Headers();
  const origin = request.headers.get("origin");
  if (!allowedPath(request) || !allowedOrigin(origin)) return headers;
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", requestedHeaders(request).join(", "));
  headers.set("Vary", "Origin");
  return headers;
}

export function authCorsOriginAllowed(request: Request): boolean {
  const headers = authCorsHeaders(request);
  if (!headers.has("Access-Control-Allow-Origin")) return false;
  return requestedHeaders(request).every((header) => allowedRequestHeaders.has(header));
}

export function withAuthCors(request: Request, response: Response): Response {
  const headers = new Headers(response.headers);
  if (authCorsOriginAllowed(request)) {
    for (const [key, value] of authCorsHeaders(request)) headers.set(key, value);
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
