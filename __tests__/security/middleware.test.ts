import { NextRequest } from 'next/server';
import { updateSession } from '@/lib/supabase/middleware';

// Mock Supabase client
jest.mock('@/lib/supabase/server', () => ({
  createServerClient: jest.fn(() => ({
    auth: {
      getUser: jest.fn()
    },
    from: jest.fn(() => ({
      select: jest.fn(() => ({
        eq: jest.fn(() => ({
          single: jest.fn()
        }))
      }))
    }))
  }))
}));

// Mock NextResponse
jest.mock('next/server', () => ({
  NextResponse: {
    next: jest.fn(() => ({
      cookies: {
        set: jest.fn()
      }
    })),
    redirect: jest.fn()
  }
}));

describe('Middleware Security Tests', () => {
  let mockRequest: Partial<NextRequest>;
  let mockSupabase: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockRequest = {
      nextUrl: {
        pathname: '/dashboard',
        clone: jest.fn(() => ({
          pathname: '',
          searchParams: {
            set: jest.fn()
          }
        }))
      },
      cookies: {
        getAll: jest.fn(() => []),
        set: jest.fn()
      }
    };
  });

  describe('Route Protection', () => {
    test('should redirect unauthenticated users from protected routes', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: null
      });

      mockRequest.nextUrl!.pathname = '/dashboard';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).toHaveBeenCalled();
    });

    test('should allow authenticated users to access protected routes', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: 'user123' } },
        error: null
      });

      mockRequest.nextUrl!.pathname = '/dashboard';
      
      const result = await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).not.toHaveBeenCalled();
      expect(NextResponse.next).toHaveBeenCalled();
    });

    test('should allow public access to public routes', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: null
      });

      mockRequest.nextUrl!.pathname = '/polls';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).not.toHaveBeenCalled();
    });

    test('should redirect authenticated users away from auth pages', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: 'user123' } },
        error: null
      });

      mockRequest.nextUrl!.pathname = '/login';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).toHaveBeenCalled();
    });
  });

  describe('Admin Route Protection', () => {
    test('should block non-admin users from admin routes', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: 'user123' } },
        error: null
      });
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { role: 'user' },
              error: null
            }))
          }))
        }))
      });

      mockRequest.nextUrl!.pathname = '/admin';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).toHaveBeenCalled();
    });

    test('should allow admin users to access admin routes', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: 'admin123' } },
        error: null
      });
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { role: 'admin' },
              error: null
            }))
          }))
        }))
      });

      mockRequest.nextUrl!.pathname = '/admin';
      
      const result = await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).not.toHaveBeenCalled();
    });
  });

  describe('Static File Handling', () => {
    test('should skip middleware for static files', async () => {
      const { NextResponse } = require('next/server');
      
      mockRequest.nextUrl!.pathname = '/_next/static/css/app.css';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.next).toHaveBeenCalled();
      expect(NextResponse.redirect).not.toHaveBeenCalled();
    });

    test('should skip middleware for API routes', async () => {
      const { NextResponse } = require('next/server');
      
      mockRequest.nextUrl!.pathname = '/api/polls';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.next).toHaveBeenCalled();
      expect(NextResponse.redirect).not.toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    test('should handle authentication errors gracefully', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: { message: 'Auth error' }
      });

      mockRequest.nextUrl!.pathname = '/dashboard';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).toHaveBeenCalled();
    });

    test('should handle database errors when fetching user role', async () => {
      const { createServerClient } = require('@/lib/supabase/server');
      const { NextResponse } = require('next/server');
      
      mockSupabase = createServerClient();
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: 'user123' } },
        error: null
      });
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: null,
              error: { message: 'Database error' }
            }))
          }))
        }))
      });

      mockRequest.nextUrl!.pathname = '/admin';
      
      await updateSession(mockRequest as NextRequest);
      
      expect(NextResponse.redirect).toHaveBeenCalled();
    });
  });
});