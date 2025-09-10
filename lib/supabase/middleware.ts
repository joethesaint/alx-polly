import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

// Define protected routes that require authentication
const PROTECTED_ROUTES = [
  '/dashboard',
  '/polls/create',
  '/admin',
  '/profile',
  '/settings'
];

// Define admin-only routes
const ADMIN_ROUTES = [
  '/admin'
];

// Define public routes that don't require authentication
const PUBLIC_ROUTES = [
  '/',
  '/login',
  '/auth/login',
  '/register', 
  '/auth/register',
  '/unauthorized',
  '/polls' // Public poll viewing
];

/**
 * Returns true if the given pathname matches any pattern in `routes`.
 *
 * Supports two pattern forms:
 * - Trailing wildcard (e.g., `/api/*`): matches any pathname that starts with the pattern's prefix (`/api/`, `/api/foo`, etc.).
 * - Exact or sub-route (e.g., `/admin`): matches exactly `/admin` or any nested path that begins with `/admin/`.
 *
 * @param pathname - The request pathname to test (should begin with `/`).
 * @param routes - Array of route patterns to match against. A pattern ending with `*` is treated as a prefix wildcard; otherwise the pattern matches either exactly or as a parent path.
 * @returns `true` if `pathname` matches at least one pattern in `routes`, otherwise `false`.
 */
function isPathMatchingRoutes(pathname: string, routes: readonly string[]): boolean {
  return routes.some(routePattern => {
    // Handle wildcard patterns (e.g., '/api/*')
    if (routePattern.endsWith('*')) {
      const baseRoute = routePattern.slice(0, -1);
      return pathname.startsWith(baseRoute);
    }
    
    // Handle exact matches and sub-routes
    return pathname === routePattern || pathname.startsWith(`${routePattern}/`);
  });
}

/**
 * Fetches the user's role from the `user_profiles` table.
 *
 * Queries the `user_profiles` table for the record with id equal to `userId`
 * and returns the `role` field. If no role is found or an error occurs, the
 * function returns the default role `'user'`. Errors are logged but not thrown.
 *
 * @param userId - The user's ID to look up.
 * @returns The user's role (for example `'admin'` or `'user'`), or `'user'` if missing or on error.
 */
async function getUserRole(supabase: any, userId: string): Promise<string | null> {
  try {
    const { data, error } = await supabase
      .from('user_profiles')
      .select('role')
      .eq('id', userId)
      .single();
    
    if (error || !data) {
      return 'user'; // Default role
    }
    
    return data.role;
  } catch (error) {
    console.error('Error fetching user role:', error);
    return 'user';
  }
}

/**
 * Enforces session-based access control and synchronizes Supabase auth cookies for an incoming Next.js request.
 *
 * Evaluates the request pathname against configured route lists (public, protected, admin) and:
 * - Initializes a server-side Supabase client that bridges request/response cookies.
 * - Redirects unauthenticated users trying to access protected routes to `/login` (adds `redirectTo`).
 * - Redirects authenticated users away from auth pages to `/dashboard`.
 * - For admin-only routes, verifies the user's role and redirects non-admins to `/unauthorized`.
 * - Allows anonymous access to poll viewing routes (`/polls/*` except `/polls/create`).
 * - Treats routes that are neither public nor explicitly protected as protected by default (redirects to `/login`).
 *
 * Side effects:
 * - May set cookies on the response to synchronize Supabase session state.
 * - May return redirect responses to `/login`, `/dashboard`, or `/unauthorized` depending on access rules.
 *
 * @param request - The incoming NextRequest to evaluate.
 * @returns A NextResponse representing either the original response (possibly with synced cookies) or a redirect.
 */
export async function updateSession(request: NextRequest) {
  let supabaseResponse = NextResponse.next({
    request,
  })

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll()
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) => request.cookies.set(name, value))
          supabaseResponse = NextResponse.next({
            request,
          })
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          )
        },
      },
    }
  )

  const pathname = request.nextUrl.pathname;

  // Skip middleware for static files and API routes
  if (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/api/') ||
    pathname.includes('.') ||
    pathname === '/favicon.ico'
  ) {
    return supabaseResponse;
  }

  try {
    const {
      data: { user },
      error: authError
    } = await supabase.auth.getUser();

    // Handle authentication errors
    if (authError) {
      console.error('Authentication error in middleware:', authError);
      if (!isPathMatchingRoutes(pathname, PUBLIC_ROUTES)) {
        const url = request.nextUrl.clone();
        url.pathname = '/login';
        url.searchParams.set('redirectTo', pathname);
        return NextResponse.redirect(url);
      }
    }

    // Check if route requires authentication
    const isProtectedRoute = isPathMatchingRoutes(pathname, PROTECTED_ROUTES);
    const isPublicRoute = isPathMatchingRoutes(pathname, PUBLIC_ROUTES);
    
    // If user is not authenticated and trying to access protected route
    if (!user && isProtectedRoute) {
      const url = request.nextUrl.clone();
      url.pathname = '/login';
      url.searchParams.set('redirectTo', pathname);
      return NextResponse.redirect(url);
    }

    // If user is authenticated and trying to access auth pages, redirect to dashboard
    if (user && (pathname === '/login' || pathname === '/auth/login' || pathname === '/register' || pathname === '/auth/register')) {
      const url = request.nextUrl.clone();
      url.pathname = '/dashboard';
      return NextResponse.redirect(url);
    }

    // Check admin routes
    if (user && isPathMatchingRoutes(pathname, ADMIN_ROUTES)) {
      const userRole = await getUserRole(supabase, user.id);
      
      if (userRole !== 'admin') {
        const url = request.nextUrl.clone();
        url.pathname = '/unauthorized';
        return NextResponse.redirect(url);
      }
    }

    // For poll viewing routes, allow both authenticated and anonymous users
    if (pathname.startsWith('/polls/') && pathname !== '/polls/create') {
      return supabaseResponse;
    }

    // If route is not explicitly public or protected, require authentication by default
    if (!user && !isPublicRoute && !isProtectedRoute) {
      const url = request.nextUrl.clone();
      url.pathname = '/login';
      url.searchParams.set('redirectTo', pathname);
      return NextResponse.redirect(url);
    }

  } catch (error) {
    console.error('Middleware error:', error);
    
    // On error, redirect to login for protected routes
    if (isPathMatchingRoutes(pathname, PROTECTED_ROUTES)) {
      const url = request.nextUrl.clone();
      url.pathname = '/login';
      url.searchParams.set('error', 'session_error');
      return NextResponse.redirect(url);
    }
  }

  return supabaseResponse;
}