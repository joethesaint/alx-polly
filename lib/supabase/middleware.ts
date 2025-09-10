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
 * Checks if a pathname matches any of the provided route patterns.
 * Supports exact matches and wildcard patterns (ending with '*').
 * 
 * @param pathname - The pathname to check
 * @param routes - Array of route patterns to match against
 * @returns true if pathname matches any route pattern
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

// Get user role from user_profiles table
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