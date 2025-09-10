'use server';

import { createClient } from '@/lib/supabase/server';
import { cache } from 'react';

export type UserRole = 'user' | 'admin' | 'moderator';

export interface UserProfile {
  id: string;
  role: UserRole;
  created_at: string;
  updated_at: string;
}

/**
 * Get the current user's profile including role
 * Cached to avoid multiple database calls
 */
export const getCurrentUserProfile = cache(async (): Promise<UserProfile | null> => {
  const supabase = await createClient();
  
  const { data: { user }, error: userError } = await supabase.auth.getUser();
  
  if (userError || !user) {
    return null;
  }

  const { data: profile, error: profileError } = await supabase
    .from('user_profiles')
    .select('*')
    .eq('id', user.id)
    .single();

  if (profileError || !profile) {
    // If no profile exists, create one with default role
    const { data: newProfile, error: createError } = await supabase
      .from('user_profiles')
      .insert({ id: user.id, role: 'user' })
      .select()
      .single();
    
    if (createError) {
      console.error('Error creating user profile:', createError);
      return null;
    }
    
    return newProfile;
  }

  return profile;
});

/**
 * Check if the current user has admin role
 */
export async function isAdmin(): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile?.role === 'admin';
}

/**
 * Check if the current user has moderator or admin role
 */
export async function isModerator(): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile?.role === 'moderator' || profile?.role === 'admin';
}

/**
 * Check if the current user has a specific role
 */
export async function hasRole(role: UserRole): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile?.role === role;
}

/**
 * Check if the current user has any of the specified roles
 */
export async function hasAnyRole(roles: UserRole[]): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile ? roles.includes(profile.role) : false;
}

/**
 * Get user profile by ID (admin only)
 */
export async function getUserProfile(userId: string): Promise<UserProfile | null> {
  const isUserAdmin = await isAdmin();
  
  if (!isUserAdmin) {
    throw new Error('Unauthorized: Admin access required');
  }

  const supabase = await createClient();
  
  const { data: profile, error } = await supabase
    .from('user_profiles')
    .select('*')
    .eq('id', userId)
    .single();

  if (error) {
    console.error('Error fetching user profile:', error);
    return null;
  }

  return profile;
}

/**
 * Update user role (admin only)
 */
export async function updateUserRole(userId: string, newRole: UserRole): Promise<{ success: boolean; error?: string }> {
  const isUserAdmin = await isAdmin();
  
  if (!isUserAdmin) {
    return { success: false, error: 'Unauthorized: Admin access required' };
  }

  const supabase = await createClient();
  
  const { error } = await supabase
    .from('user_profiles')
    .update({ role: newRole, updated_at: new Date().toISOString() })
    .eq('id', userId);

  if (error) {
    console.error('Error updating user role:', error);
    return { success: false, error: error.message };
  }

  return { success: true };
}

/**
 * Get all user profiles (admin only)
 */
export async function getAllUserProfiles(): Promise<UserProfile[]> {
  const isUserAdmin = await isAdmin();
  
  if (!isUserAdmin) {
    throw new Error('Unauthorized: Admin access required');
  }

  const supabase = await createClient();
  
  const { data: profiles, error } = await supabase
    .from('user_profiles')
    .select('*')
    .order('created_at', { ascending: false });

  if (error) {
    console.error('Error fetching user profiles:', error);
    return [];
  }

  return profiles || [];
}

/**
 * Authorization middleware for server actions
 */
export async function requireAuth(): Promise<string> {
  const supabase = await createClient();
  const { data: { user }, error } = await supabase.auth.getUser();
  
  if (error || !user) {
    throw new Error('Authentication required');
  }
  
  return user.id;
}

/**
 * Authorization middleware for admin actions
 */
export async function requireAdmin(): Promise<string> {
  const userId = await requireAuth();
  const isUserAdmin = await isAdmin();
  
  if (!isUserAdmin) {
    throw new Error('Admin access required');
  }
  
  return userId;
}

/**
 * Authorization middleware for moderator actions
 */
export async function requireModerator(): Promise<string> {
  const userId = await requireAuth();
  const isUserModerator = await isModerator();
  
  if (!isUserModerator) {
    throw new Error('Moderator access required');
  }
  
  return userId;
}

/**
 * Check if user can access resource (owner or admin)
 */
export async function canAccessResource(resourceUserId: string): Promise<boolean> {
  try {
    const currentProfile = await getCurrentUserProfile();
    
    if (!currentProfile) {
      return false;
    }
    
    // User can access their own resources or admin can access any resource
    return currentProfile.id === resourceUserId || currentProfile.role === 'admin';
  } catch (error) {
    console.error('Error checking resource access:', error);
    return false;
  }
}

/**
 * Audit log for security-sensitive operations
 */
export async function auditLog(action: string, details: Record<string, any> = {}): Promise<void> {
  try {
    const profile = await getCurrentUserProfile();
    const supabase = await createClient();
    
    // Log to console for now - in production, this should go to a proper audit log table
    console.log('AUDIT LOG:', {
      timestamp: new Date().toISOString(),
      userId: profile?.id || 'anonymous',
      userRole: profile?.role || 'unknown',
      action,
      details,
      ip: 'unknown', // Would need to be passed from request
      userAgent: 'unknown' // Would need to be passed from request
    });
    
    // TODO: Implement proper audit log table and storage
  } catch (error) {
    console.error('Error writing audit log:', error);
  }
}