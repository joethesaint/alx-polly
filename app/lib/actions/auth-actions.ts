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

// Rate limiting helper
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

// Clear successful attempts
function clearRateLimit(attempts: Map<string, { count: number; lastAttempt: number }>, identifier: string): void {
  attempts.delete(identifier);
}

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
