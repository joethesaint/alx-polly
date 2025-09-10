'use server';

import { createClient } from '@/lib/supabase/server';
import { LoginFormData, RegisterFormData } from '../types';
import { z } from 'zod';
import { auditLog } from '../rbac';

// Rate limiting storage (in production, use Redis or database)
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();
const registrationAttempts = new Map<string, { count: number; lastAttempt: number }>();

// Password policy schema
const passwordSchema = z.string()
  .min(8, 'Password must be at least 8 characters long')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character');

// Enhanced validation schemas
const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required')
});

const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(50, 'Name must be less than 50 characters'),
  email: z.string().email('Invalid email address'),
  password: passwordSchema
});

/**
 * Enforces a simple sliding window rate limit for an identifier using an in-memory map.
 *
 * Uses the provided `attempts` map to track counts and timestamps. If no prior record
 * exists or the time window has elapsed, the count is reset and the attempt is allowed.
 * Otherwise the count is incremented and the attempt is allowed until `maxAttempts`
 * within `windowMs` is reached.
 *
 * Mutates the `attempts` map by creating, resetting, or updating the entry for `identifier`.
 *
 * @param identifier - Key used to track attempts (e.g., user email or IP)
 * @param maxAttempts - Maximum allowed attempts within the time window (default: 5)
 * @param windowMs - Time window in milliseconds for rate limiting (default: 15 minutes)
 * @returns True if the attempt is permitted; false if the rate limit has been exceeded.
 */
function checkRateLimit(attempts: Map<string, { count: number; lastAttempt: number }>, identifier: string, maxAttempts: number = 5, windowMs: number = 15 * 60 * 1000): boolean {
  const now = Date.now();
  const userAttempts = attempts.get(identifier);
  
  if (!userAttempts) {
    attempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }
  
  // Reset if window has passed
  if (now - userAttempts.lastAttempt > windowMs) {
    attempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }
  
  // Check if limit exceeded
  if (userAttempts.count >= maxAttempts) {
    return false;
  }
  
  // Increment count
  userAttempts.count++;
  userAttempts.lastAttempt = now;
  return true;
}

/**
 * Remove the rate-limit entry for an identifier, resetting its attempt state.
 *
 * Clears the provided `attempts` map entry for `identifier` (if present), typically used after
 * a successful authentication or registration to reset the per-identifier failure count and timestamp.
 *
 * @param attempts - Map tracking attempt metadata keyed by identifier (e.g., email)
 * @param identifier - The key whose rate-limit entry should be cleared
 */
function clearRateLimit(attempts: Map<string, { count: number; lastAttempt: number }>, identifier: string): void {
  attempts.delete(identifier);
}

/**
 * Authenticate a user with email and password.
 *
 * Validates the provided credentials, enforces a per-email rate limit (5 attempts per 15 minutes),
 * attempts sign-in with Supabase, records audit-log events for validation failures, rate-limit hits,
 * failures, successes, and unexpected errors, and clears the rate limit on successful authentication.
 *
 * @param data - Login payload; must include `email` and `password`.
 * @returns An object with `error` set to `null` on success or a user-facing error message on failure.
 */
export async function login(data: LoginFormData) {
  try {
    // Validate input
    const validationResult = loginSchema.safeParse(data);
    if (!validationResult.success) {
      const errors = validationResult.error.errors.map(e => e.message).join(', ');
      await auditLog('auth', 'login_validation_failed', null, { email: data.email, errors });
      return { error: errors };
    }

    const { email, password } = validationResult.data;
    
    // Check rate limiting
    if (!checkRateLimit(loginAttempts, email, 5, 15 * 60 * 1000)) {
      await auditLog('auth', 'login_rate_limited', null, { email });
      return { error: 'Too many login attempts. Please try again in 15 minutes.' };
    }

    const supabase = await createClient();

    const { data: authData, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      await auditLog('auth', 'login_failed', null, { email, error: error.message });
      return { error: error.message };
    }

    // Clear rate limit on successful login
    clearRateLimit(loginAttempts, email);
    
    // Log successful login
    await auditLog('auth', 'login_success', authData.user?.id, { email });
    
    return { error: null };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Login failed';
    await auditLog('auth', 'login_error', null, { email: data.email, error: errorMessage });
    return { error: errorMessage };
  }
}

/**
 * Register a new user with email, password, and name.
 *
 * Validates input against the register schema, enforces per-email rate limiting
 * (3 attempts per hour), creates a Supabase user (including `name` in user metadata),
 * and records audit logs for validation failures, rate limiting, failures, successes,
 * and unexpected errors.
 *
 * On validation failure or when rate limited, returns an object with `error` set
 * to a user-facing message. On successful registration returns `{ error: null }`.
 *
 * Side effects:
 * - Calls Supabase to create the user.
 * - Writes audit logs via `auditLog`.
 * - Updates the in-memory rate-limit store and clears it on success.
 *
 * @param data - Registration data containing `name`, `email`, and `password`.
 * @returns An object `{ error: string | null }` where `error` is null on success or
 *          contains a human-readable error message on failure.
 */
export async function register(data: RegisterFormData) {
  try {
    // Validate input
    const validationResult = registerSchema.safeParse(data);
    if (!validationResult.success) {
      const errors = validationResult.error.errors.map(e => e.message).join(', ');
      await auditLog('auth', 'register_validation_failed', null, { email: data.email, errors });
      return { error: errors };
    }

    const { name, email, password } = validationResult.data;
    
    // Check rate limiting (3 registrations per hour per email)
    if (!checkRateLimit(registrationAttempts, email, 3, 60 * 60 * 1000)) {
      await auditLog('auth', 'register_rate_limited', null, { email });
      return { error: 'Too many registration attempts. Please try again in 1 hour.' };
    }

    const supabase = await createClient();

    const { data: authData, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          name,
        },
      },
    });

    if (error) {
      await auditLog('auth', 'register_failed', null, { email, error: error.message });
      return { error: error.message };
    }

    // Clear rate limit on successful registration
    clearRateLimit(registrationAttempts, email);
    
    // Log successful registration
    await auditLog('auth', 'register_success', authData.user?.id, { email, name });
    
    return { error: null };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Registration failed';
    await auditLog('auth', 'register_error', null, { email: data.email, error: errorMessage });
    return { error: errorMessage };
  }
}

/**
 * Signs out the current user and records audit logs for success or failure.
 *
 * Retrieves the current authenticated user to capture their id and email for auditing, then calls Supabase to sign out.
 * On sign-out failure the function logs a `logout_failed` audit event with the user id/email and returns `{ error: string }`.
 * On success it logs `logout_success` and returns `{ error: null }`.
 *
 * @returns An object with an `error` field: `null` when logout succeeded, or a string error message when it failed.
 */
export async function logout() {
  try {
    const supabase = await createClient();
    
    // Get current user before logout for audit logging
    const { data: { user } } = await supabase.auth.getUser();
    const userId = user?.id;
    const userEmail = user?.email;
    
    const { error } = await supabase.auth.signOut();
    
    if (error) {
      await auditLog('auth', 'logout_failed', userId, { email: userEmail, error: error.message });
      return { error: error.message };
    }
    
    // Log successful logout
    await auditLog('auth', 'logout_success', userId, { email: userEmail });
    
    return { error: null };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Logout failed';
    return { error: errorMessage };
  }
}

/**
 * Retrieves the currently authenticated user from Supabase.
 *
 * @returns The authenticated user object, or `null` if there is no signed-in user.
 */
export async function getCurrentUser() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

export async function getSession() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getSession();
  return data.session;
}
