import { type NextRequest, NextResponse } from 'next/server'
import { updateSession } from '@/lib/supabase/middleware'

/**
 * Middleware that ensures the incoming request has an updated session for protected routes.
 *
 * Delegates session handling to `updateSession(request)`. If `updateSession` succeeds,
 * its resulting `NextResponse` is returned; on error, the middleware logs the error
 * and returns `NextResponse.next()` as a safe fallback.
 *
 * @returns The `NextResponse` produced by `updateSession` or `NextResponse.next()` on error.
 */
export async function middleware(request: NextRequest): Promise<NextResponse> {
  try {
    return await updateSession(request)
  } catch (error) {
    console.error('Middleware error:', error)
    // Return a fallback response in case of errors
    return NextResponse.next()
  }
}

/**
 * Configuration object that defines which routes should be processed by the middleware.
 * Excludes static assets, API routes, and other Next.js internal paths for performance.
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - Files with extensions (images, etc.)
     */
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js)$).*)',
  ],
} as const