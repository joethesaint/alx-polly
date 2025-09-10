import { type NextRequest, NextResponse } from 'next/server'
import { updateSession } from '@/lib/supabase/middleware'

/**
 * Middleware function that handles session management and authentication
 * for protected routes in the application.
 * 
 * @param request - The incoming Next.js request object
 * @returns Promise<NextResponse> - The response with updated session
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