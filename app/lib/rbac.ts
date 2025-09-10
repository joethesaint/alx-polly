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
 * Returns whether the current authenticated user has the 'admin' role.
 *
 * If there is no authenticated user or no profile, this returns `false`.
 *
 * @returns `true` when the current user's role is `'admin'`; otherwise `false`.
 */
export async function isAdmin(): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile?.role === 'admin';
}

/**
 * Determine whether the current user has moderator or admin privileges.
 *
 * @returns `true` if the current user's profile role is `'moderator'` or `'admin'`; otherwise `false`.
 */
export async function isModerator(): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile?.role === 'moderator' || profile?.role === 'admin';
}

/**
 * Return true if the current authenticated user's profile has the specified role.
 *
 * Retrieves the current user's profile and compares its `role` to the provided `role`.
 * Returns `false` if there is no authenticated profile or the roles do not match.
 *
 * @param role - The role to check against the current user's profile
 * @returns `true` if the current user's role equals `role`, otherwise `false`
 */
export async function hasRole(role: UserRole): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile?.role === role;
}

/**
 * Return true if the current authenticated user's role is included in `roles`.
 *
 * If there is no authenticated user or no profile, this returns false.
 *
 * @param roles - Roles to check membership against.
 * @returns True when the current user's role matches any entry in `roles`; otherwise false.
 */
export async function hasAnyRole(roles: UserRole[]): Promise<boolean> {
  const profile = await getCurrentUserProfile();
  return profile ? roles.includes(profile.role) : false;
}

/**
 * Retrieve a user's profile by ID. Requires the caller to have the `admin` role.
 *
 * Throws an Error if the current user is not an admin.
 *
 * @param userId - The ID of the user whose profile to fetch.
 * @returns The user's profile on success, or `null` if the profile could not be fetched.
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
 * Change a user's role in the user_profiles table (admin-only).
 *
 * Verifies the caller has admin privileges, updates the target user's `role`
 * and `updated_at` timestamp in the database, and returns a success flag.
 *
 * @param userId - ID of the user whose role will be changed
 * @param newRole - New role to assign to the user
 * @returns An object with `success: true` on success, or `success: false` and
 * an `error` message on failure (e.g. unauthorized or database error)
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
 * Retrieve all user profiles, ordered by newest first.
 *
 * Throws an Error if the caller is not an admin.
 *
 * On success returns an array of UserProfile objects ordered by `created_at` descending.
 * If a database fetch error occurs the function logs the error and returns an empty array.
 *
 * @returns An array of user profiles (empty array on fetch error)
 * @throws Error - 'Unauthorized: Admin access required' when the caller is not an admin
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
 * Ensures a user is authenticated and returns their user ID.
 *
 * Throws an Error with message "Authentication required" if there is no authenticated user or if retrieving the user fails.
 *
 * @returns The authenticated user's ID.
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
 * Ensures the caller is authenticated and has admin privileges.
 *
 * @returns The authenticated user's ID.
 * @throws Error Throws 'Admin access required' when the current user is not an admin.
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
 * Ensure the caller is authenticated and has moderator privileges, and return their user ID.
 *
 * Calls requireAuth() to verify authentication and isModerator() to verify role membership.
 *
 * @returns The authenticated user's ID.
 * @throws `Authentication required` if the caller is not authenticated.
 * @throws `Moderator access required` if the authenticated user is not a moderator.
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
 * Determine whether the current user is allowed to access a resource owned by `resourceUserId`.
 *
 * Returns true if the current user is the resource owner or has the 'admin' role; otherwise false.
 *
 * @param resourceUserId - ID of the resource owner to check against the current user
 * @returns True when access is allowed, false otherwise (also false on errors or if no authenticated user)
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
 * Record a security-relevant audit entry for the current user.
 *
 * Attempts to capture who performed `action` along with optional structured `details`.
 * Currently the entry is written to the server console (placeholder) and a TODO remains
 * to store audit entries in a persistent audit log table. If available, include request
 * metadata (e.g., ip, userAgent) in `details` since this function does not extract them.
 *
 * @param action - A short identifier or description of the action being audited.
 * @param details - Optional structured metadata about the action (defaults to an empty object).
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