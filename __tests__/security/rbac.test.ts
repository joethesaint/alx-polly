import { 
  requireAuth, 
  requireAdmin, 
  requireModerator, 
  canAccessResource,
  getCurrentUserProfile,
  isAdmin,
  isModerator
} from '@/app/lib/rbac';

// Mock Supabase client
jest.mock('@/lib/supabase/server', () => ({
  createClient: jest.fn(() => ({
    auth: {
      getUser: jest.fn()
    },
    from: jest.fn(() => ({
      select: jest.fn(() => ({
        eq: jest.fn(() => ({
          single: jest.fn()
        }))
      })),
      insert: jest.fn(() => ({
        select: jest.fn(() => ({
          single: jest.fn()
        }))
      }))
    }))
  }))
}));

describe('RBAC Security Tests', () => {
  let mockSupabase: any;

  beforeEach(() => {
    jest.clearAllMocks();
    const { createClient } = require('@/lib/supabase/server');
    mockSupabase = createClient();
  });

  describe('Authentication Requirements', () => {
    test('requireAuth should throw error for unauthenticated users', async () => {
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: null
      });

      await expect(requireAuth()).rejects.toThrow('Authentication required');
    });

    test('requireAuth should return user ID for authenticated users', async () => {
      const userId = 'user123';
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: userId } },
        error: null
      });

      const result = await requireAuth();
      expect(result).toBe(userId);
    });

    test('requireAuth should throw error on auth error', async () => {
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: { message: 'Auth error' }
      });

      await expect(requireAuth()).rejects.toThrow('Authentication required');
    });
  });

  describe('Admin Authorization', () => {
    test('requireAdmin should throw error for non-admin users', async () => {
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

      await expect(requireAdmin()).rejects.toThrow('Admin access required');
    });

    test('requireAdmin should return user ID for admin users', async () => {
      const userId = 'admin123';
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: userId } },
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

      const result = await requireAdmin();
      expect(result).toBe(userId);
    });

    test('isAdmin should return true for admin users', async () => {
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

      const result = await isAdmin();
      expect(result).toBe(true);
    });

    test('isAdmin should return false for non-admin users', async () => {
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

      const result = await isAdmin();
      expect(result).toBe(false);
    });
  });

  describe('Moderator Authorization', () => {
    test('requireModerator should throw error for regular users', async () => {
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

      await expect(requireModerator()).rejects.toThrow('Moderator access required');
    });

    test('requireModerator should return user ID for moderator users', async () => {
      const userId = 'mod123';
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: userId } },
        error: null
      });

      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { role: 'moderator' },
              error: null
            }))
          }))
        }))
      });

      const result = await requireModerator();
      expect(result).toBe(userId);
    });

    test('isModerator should return true for moderator users', async () => {
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: 'mod123' } },
        error: null
      });

      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { role: 'moderator' },
              error: null
            }))
          }))
        }))
      });

      const result = await isModerator();
      expect(result).toBe(true);
    });
  });

  describe('Resource Access Control', () => {
    test('canAccessResource should allow users to access their own resources', async () => {
      const userId = 'user123';
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: userId } },
        error: null
      });

      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { id: userId, role: 'user' },
              error: null
            }))
          }))
        }))
      });

      const result = await canAccessResource(userId);
      expect(result).toBe(true);
    });

    test('canAccessResource should deny users access to other users resources', async () => {
      const userId = 'user123';
      const resourceUserId = 'user456';
      
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: userId } },
        error: null
      });

      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { id: userId, role: 'user' },
              error: null
            }))
          }))
        }))
      });

      const result = await canAccessResource(resourceUserId);
      expect(result).toBe(false);
    });

    test('canAccessResource should allow admins to access any resource', async () => {
      const adminId = 'admin123';
      const resourceUserId = 'user456';
      
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: adminId } },
        error: null
      });

      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { id: adminId, role: 'admin' },
              error: null
            }))
          }))
        }))
      });

      const result = await canAccessResource(resourceUserId);
      expect(result).toBe(true);
    });

    test('canAccessResource should return false on authentication error', async () => {
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: { message: 'Auth error' }
      });

      const result = await canAccessResource('user123');
      expect(result).toBe(false);
    });
  });

  describe('User Profile Management', () => {
    test('getCurrentUserProfile should create default profile if none exists', async () => {
      const userId = 'user123';
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: { id: userId } },
        error: null
      });

      // First call returns no profile
      mockSupabase.from.mockReturnValueOnce({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: null,
              error: { message: 'No profile found' }
            }))
          }))
        }))
      });

      // Second call (insert) returns new profile
      mockSupabase.from.mockReturnValueOnce({
        insert: jest.fn(() => ({
          select: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: { id: userId, role: 'user' },
              error: null
            }))
          }))
        }))
      });

      const result = await getCurrentUserProfile();
      expect(result).toEqual({ id: userId, role: 'user' });
    });

    test('getCurrentUserProfile should return null for unauthenticated users', async () => {
      mockSupabase.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: null
      });

      const result = await getCurrentUserProfile();
      expect(result).toBeNull();
    });
  });
});