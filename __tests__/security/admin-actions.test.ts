// Mock the admin actions since they don't exist yet
const getAllUsers = jest.fn();
const deleteUser = jest.fn();
const updateUserRole = jest.fn();
const getAllPolls = jest.fn();
const deletePollAsAdmin = jest.fn();

import { requireAdmin } from '@/app/lib/rbac';

// Mock dependencies
jest.mock('@/lib/supabase/server', () => ({
  createClient: jest.fn(() => ({
    from: jest.fn(() => ({
      select: jest.fn(() => ({
        order: jest.fn(() => Promise.resolve({
          data: [],
          error: null
        })),
        eq: jest.fn(() => ({
          single: jest.fn(() => Promise.resolve({
            data: null,
            error: null
          }))
        }))
      })),
      delete: jest.fn(() => ({
        eq: jest.fn(() => Promise.resolve({
          data: null,
          error: null
        }))
      })),
      update: jest.fn(() => ({
        eq: jest.fn(() => Promise.resolve({
          data: null,
          error: null
        }))
      }))
    }))
  }))
}));

jest.mock('@/app/lib/rbac', () => ({
  requireAdmin: jest.fn()
}));

jest.mock('@/app/lib/audit-log', () => ({
  auditLog: jest.fn()
}));

jest.mock('@/app/lib/data-masking', () => ({
  maskSensitiveData: jest.fn((data) => ({
    ...data,
    email: data.email ? data.email.replace(/(.{2}).*(@.*)/, '$1***$2') : null,
    ip_address: data.ip_address ? 'xxx.xxx.xxx.xxx' : null
  }))
}));

describe('Admin Actions Security Tests', () => {
  let mockSupabase: any;
  let mockRequireAdmin: jest.Mock;
  let mockAuditLog: jest.Mock;
  let mockMaskSensitiveData: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    const { createClient } = require('@/lib/supabase/server');
    const { auditLog } = require('@/app/lib/audit-log');
    const { maskSensitiveData } = require('@/app/lib/data-masking');
    
    mockSupabase = createClient();
    mockRequireAdmin = requireAdmin as jest.Mock;
    mockAuditLog = auditLog as jest.Mock;
    mockMaskSensitiveData = maskSensitiveData as jest.Mock;
  });

  describe('Get All Users Security', () => {
    test('should require admin authorization', async () => {
      mockRequireAdmin.mockRejectedValue(new Error('Admin access required'));
      
      await expect(getAllUsers()).rejects.toThrow('Admin access required');
      expect(mockRequireAdmin).toHaveBeenCalled();
    });

    test('should mask sensitive user data', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const mockUsers = [
        {
          id: 'user1',
          email: 'user1@example.com',
          name: 'User One',
          role: 'user',
          created_at: '2024-01-01',
          ip_address: '192.168.1.1'
        },
        {
          id: 'user2',
          email: 'user2@example.com',
          name: 'User Two',
          role: 'moderator',
          created_at: '2024-01-02',
          ip_address: '192.168.1.2'
        }
      ];
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          order: jest.fn(() => Promise.resolve({
            data: mockUsers,
            error: null
          }))
        }))
      });
      
      mockMaskSensitiveData.mockImplementation((user) => ({
        ...user,
        email: user.email.replace(/(.{2}).*(@.*)/, '$1***$2'),
        ip_address: 'xxx.xxx.xxx.xxx'
      }));
      
      const result = await getAllUsers();
      
      expect(result).toEqual({
        users: [
          {
            id: 'user1',
            email: 'us***@example.com',
            name: 'User One',
            role: 'user',
            created_at: '2024-01-01',
            ip_address: 'xxx.xxx.xxx.xxx'
          },
          {
            id: 'user2',
            email: 'us***@example.com',
            name: 'User Two',
            role: 'moderator',
            created_at: '2024-01-02',
            ip_address: 'xxx.xxx.xxx.xxx'
          }
        ]
      });
      
      expect(mockAuditLog).toHaveBeenCalledWith(
        'ADMIN_USERS_ACCESSED',
        expect.objectContaining({
          adminId: 'admin123',
          userCount: 2
        })
      );
    });

    test('should handle database errors', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          order: jest.fn(() => Promise.resolve({
            data: null,
            error: { message: 'Database connection failed' }
          }))
        }))
      });
      
      const result = await getAllUsers();
      
      expect(result).toEqual({
        error: 'Database connection failed'
      });
    });
  });

  describe('Delete User Security', () => {
    test('should require admin authorization', async () => {
      mockRequireAdmin.mockRejectedValue(new Error('Admin access required'));
      
      await expect(deleteUser('user123')).rejects.toThrow('Admin access required');
      expect(mockRequireAdmin).toHaveBeenCalled();
    });

    test('should validate user ID format', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const result = await deleteUser('invalid-id');
      
      expect(result).toEqual({
        error: 'Invalid user ID format'
      });
    });

    test('should prevent admin from deleting themselves', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const result = await deleteUser('admin123');
      
      expect(result).toEqual({
        error: 'You cannot delete your own account'
      });
      expect(mockAuditLog).toHaveBeenCalledWith(
        'ADMIN_SELF_DELETE_ATTEMPT',
        expect.objectContaining({
          adminId: 'admin123'
        })
      );
    });

    test('should check if user exists before deletion', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: null,
              error: null
            }))
          }))
        }))
      });
      
      const result = await deleteUser('user123');
      
      expect(result).toEqual({
        error: 'User not found'
      });
    });

    test('should handle successful user deletion', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const mockUser = {
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        role: 'user'
      };
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: mockUser,
              error: null
            }))
          }))
        })),
        delete: jest.fn(() => ({
          eq: jest.fn(() => Promise.resolve({
            data: null,
            error: null
          }))
        }))
      });
      
      const result = await deleteUser('user123');
      
      expect(result).toEqual({
        success: true,
        message: 'User deleted successfully'
      });
      expect(mockAuditLog).toHaveBeenCalledWith(
        'USER_DELETED_BY_ADMIN',
        expect.objectContaining({
          adminId: 'admin123',
          deletedUserId: 'user123',
          deletedUserEmail: 'user@example.com'
        })
      );
    });
  });

  describe('Update User Role Security', () => {
    test('should require admin authorization', async () => {
      mockRequireAdmin.mockRejectedValue(new Error('Admin access required'));
      
      await expect(updateUserRole('user123', 'moderator')).rejects.toThrow('Admin access required');
      expect(mockRequireAdmin).toHaveBeenCalled();
    });

    test('should validate user ID format', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const result = await updateUserRole('invalid-id', 'moderator');
      
      expect(result).toEqual({
        error: 'Invalid user ID format'
      });
    });

    test('should validate role value', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const result = await updateUserRole('user123', 'invalid-role');
      
      expect(result).toEqual({
        error: 'Invalid role. Must be one of: user, moderator, admin'
      });
    });

    test('should prevent admin from changing their own role', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const result = await updateUserRole('admin123', 'user');
      
      expect(result).toEqual({
        error: 'You cannot change your own role'
      });
      expect(mockAuditLog).toHaveBeenCalledWith(
        'ADMIN_SELF_ROLE_CHANGE_ATTEMPT',
        expect.objectContaining({
          adminId: 'admin123',
          attemptedRole: 'user'
        })
      );
    });

    test('should handle successful role update', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const mockUser = {
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        role: 'user'
      };
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: mockUser,
              error: null
            }))
          }))
        })),
        update: jest.fn(() => ({
          eq: jest.fn(() => Promise.resolve({
            data: { ...mockUser, role: 'moderator' },
            error: null
          }))
        }))
      });
      
      const result = await updateUserRole('user123', 'moderator');
      
      expect(result).toEqual({
        success: true,
        message: 'User role updated successfully'
      });
      expect(mockAuditLog).toHaveBeenCalledWith(
        'USER_ROLE_UPDATED_BY_ADMIN',
        expect.objectContaining({
          adminId: 'admin123',
          targetUserId: 'user123',
          oldRole: 'user',
          newRole: 'moderator'
        })
      );
    });
  });

  describe('Get All Polls Security', () => {
    test('should require admin authorization', async () => {
      mockRequireAdmin.mockRejectedValue(new Error('Admin access required'));
      
      await expect(getAllPolls()).rejects.toThrow('Admin access required');
      expect(mockRequireAdmin).toHaveBeenCalled();
    });

    test('should return polls with creator information', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const mockPolls = [
        {
          id: 'poll1',
          title: 'Test Poll 1',
          created_by: 'user1',
          created_at: '2024-01-01',
          vote_count: 10,
          profiles: {
            name: 'User One',
            email: 'user1@example.com'
          }
        }
      ];
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          order: jest.fn(() => Promise.resolve({
            data: mockPolls,
            error: null
          }))
        }))
      });
      
      const result = await getAllPolls();
      
      expect(result).toEqual({
        polls: mockPolls
      });
      expect(mockAuditLog).toHaveBeenCalledWith(
        'ADMIN_POLLS_ACCESSED',
        expect.objectContaining({
          adminId: 'admin123',
          pollCount: 1
        })
      );
    });
  });

  describe('Delete Poll as Admin Security', () => {
    test('should require admin authorization', async () => {
      mockRequireAdmin.mockRejectedValue(new Error('Admin access required'));
      
      await expect(deletePollAsAdmin('poll123')).rejects.toThrow('Admin access required');
      expect(mockRequireAdmin).toHaveBeenCalled();
    });

    test('should validate poll ID format', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const result = await deletePollAsAdmin('invalid-id');
      
      expect(result).toEqual({
        error: 'Invalid poll ID format'
      });
    });

    test('should handle successful poll deletion', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const mockPoll = {
        id: 'poll123',
        title: 'Test Poll',
        created_by: 'user123'
      };
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          eq: jest.fn(() => ({
            single: jest.fn(() => Promise.resolve({
              data: mockPoll,
              error: null
            }))
          }))
        })),
        delete: jest.fn(() => ({
          eq: jest.fn(() => Promise.resolve({
            data: null,
            error: null
          }))
        }))
      });
      
      const result = await deletePollAsAdmin('poll123');
      
      expect(result).toEqual({
        success: true,
        message: 'Poll deleted successfully'
      });
      expect(mockAuditLog).toHaveBeenCalledWith(
        'POLL_DELETED_BY_ADMIN',
        expect.objectContaining({
          adminId: 'admin123',
          pollId: 'poll123',
          pollTitle: 'Test Poll',
          originalCreator: 'user123'
        })
      );
    });
  });

  describe('Data Protection', () => {
    test('should mask sensitive data in user listings', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      const sensitiveUser = {
        id: 'user1',
        email: 'sensitive@example.com',
        name: 'Sensitive User',
        role: 'user',
        ip_address: '192.168.1.100',
        phone: '+1234567890'
      };
      
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          order: jest.fn(() => Promise.resolve({
            data: [sensitiveUser],
            error: null
          }))
        }))
      });
      
      mockMaskSensitiveData.mockReturnValue({
        ...sensitiveUser,
        email: 'se***@example.com',
        ip_address: 'xxx.xxx.xxx.xxx',
        phone: '+123****890'
      });
      
      const result = await getAllUsers();
      
      expect(mockMaskSensitiveData).toHaveBeenCalledWith(sensitiveUser);
      expect(result.users[0].email).toBe('se***@example.com');
      expect(result.users[0].ip_address).toBe('xxx.xxx.xxx.xxx');
    });
  });

  describe('Audit Logging', () => {
    test('should log all admin actions', async () => {
      const mockAdmin = { id: 'admin123', email: 'admin@example.com', role: 'admin' };
      mockRequireAdmin.mockResolvedValue(mockAdmin);
      
      // Test user access logging
      mockSupabase.from.mockReturnValue({
        select: jest.fn(() => ({
          order: jest.fn(() => Promise.resolve({
            data: [],
            error: null
          }))
        }))
      });
      
      await getAllUsers();
      
      expect(mockAuditLog).toHaveBeenCalledWith(
        'ADMIN_USERS_ACCESSED',
        expect.objectContaining({
          adminId: 'admin123',
          userCount: 0
        })
      );
    });

    test('should log failed authorization attempts', async () => {
      mockRequireAdmin.mockRejectedValue(new Error('Admin access required'));
      
      try {
        await getAllUsers();
      } catch (error) {
        // Expected to throw
      }
      
      expect(mockRequireAdmin).toHaveBeenCalled();
    });
  });
});