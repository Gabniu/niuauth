import { toNextJsHandler } from "better-auth/next-js";

import { auth } from "@/lib/auth";
import { authCorsHeaders, authCorsOriginAllowed, withAuthCors } from "@/lib/auth-cors";

const handler = toNextJsHandler(auth);

export async function GET(request: Request): Promise<Response> {
  return withAuthCors(request, await handler.GET(request));
}

export async function POST(request: Request): Promise<Response> {
  return withAuthCors(request, await handler.POST(request));
}

export function OPTIONS(request: Request): Response {
  if (!authCorsOriginAllowed(request)) return new Response(null, { status: 403 });
  return new Response(null, { status: 204, headers: authCorsHeaders(request) });
}
