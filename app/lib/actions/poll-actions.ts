"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";
import { requireAuth, requireAdmin, canAccessResource, auditLog, isAdmin } from "@/lib/rbac";
import { z } from "zod";
import DOMPurify from "isomorphic-dompurify";

/**
 * Poll Management Actions Module
 * 
 * This module provides comprehensive poll management functionality for the ALX Polly application.
 * It handles poll creation, voting, retrieval, updates, and deletion with robust security measures.
 * 
 * Key features:
 * - Input validation and sanitization to prevent XSS attacks
 * - Role-based access control (RBAC) for administrative functions
 * - Rate limiting to prevent spam and abuse
 * - Comprehensive audit logging for security monitoring
 * - Support for both authenticated and anonymous voting
 * - Proper error handling and user feedback
 * 
 * All functions are server actions that run securely on the server side.
 */

/**
 * Poll Creation Validation Schema
 * 
 * Validates poll creation data with comprehensive constraints:
 * - Question: 1-500 characters, trimmed for consistency
 * - Options: 2-10 options, each 1-200 characters, all non-empty
 * 
 * These limits prevent abuse while allowing flexible poll creation.
 */
const createPollSchema = z.object({
  question: z.string().min(1, "Question is required").max(500, "Question too long").trim(),
  options: z.array(z.string().min(1, "Option cannot be empty").max(200, "Option too long").trim())
    .min(2, "At least 2 options required")
    .max(10, "Maximum 10 options allowed"),
  expires_at: z.string().optional(),
});

/**
 * Vote Submission Validation Schema
 * 
 * Validates vote data to ensure integrity:
 * - Poll ID: Must be a valid UUID format
 * - Option Index: Non-negative integer for array indexing
 * 
 * Prevents invalid votes and potential security issues.
 */
const voteSchema = z.object({
  pollId: z.string().uuid("Invalid poll ID"),
  optionIndex: z.number().int().min(0, "Invalid option index")
});

/**
 * Input Sanitization Function
 * 
 * Sanitizes user input to prevent XSS (Cross-Site Scripting) attacks.
 * Removes all HTML tags and attributes from user-provided content.
 * 
 * @param input - Raw user input string
 * @returns Sanitized string safe for database storage and display
 * 
 * Security: Essential for preventing malicious script injection in poll content.
 */
function sanitizeInput(input: string): string {
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
}

/**
 * Create Poll Server Action
 * 
 * Creates a new poll with comprehensive validation, sanitization, and security measures.
 * Requires user authentication and implements rate limiting to prevent spam.
 * 
 * @param formData - FormData containing poll question and options
 * @returns Promise<{error: string | null, pollId?: string}> - Success/error response with poll ID
 * 
 * Security features:
 * - Authentication requirement via requireAuth()
 * - Input validation using Zod schema
 * - XSS prevention through input sanitization
 * - Rate limiting (5 polls per minute per user)
 * - Comprehensive audit logging
 * 
 * Flow:
 * 1. Authenticate user and extract form data
 * 2. Validate input format and constraints
 * 3. Sanitize all user inputs to prevent XSS
 * 4. Check rate limiting to prevent spam
 * 5. Create poll in database with sanitized data
 * 6. Log creation event and return poll ID
 */
export async function createPoll(formData: FormData) {
  try {
    // Ensure user is authenticated before allowing poll creation
    const userId = await requireAuth();
    
    const supabase = await createClient();

    // Extract form data with proper type casting
    const rawQuestion = formData.get("question") as string;
    const rawOptions = formData.getAll("options").filter(Boolean) as string[];
    const expires_at = formData.get("expires_at") as string | null;

    // Validate input data against schema constraints
    const validationResult = createPollSchema.safeParse({
      question: rawQuestion,
      options: rawOptions,
      expires_at: expires_at || undefined,
    });

    if (!validationResult.success) {
      const errors = validationResult.error.issues.map(e => e.message).join(", ");
      return { error: `Validation failed: ${errors}` };
    }

    const { question, options } = validationResult.data;

    // Sanitize all inputs to prevent XSS attacks
    const sanitizedQuestion = sanitizeInput(question);
    const sanitizedOptions = options.map(option => sanitizeInput(option));

    // Implement rate limiting: max 5 polls per minute per user
    const { data: recentPolls, error: countError } = await supabase
      .from("polls")
      .select("id")
      .eq("user_id", userId)
      .gte("created_at", new Date(Date.now() - 60000).toISOString()); // Last minute

    if (countError) {
      console.error("Error checking rate limit:", countError);
    } else if (recentPolls && recentPolls.length >= 5) {
      return { error: "Rate limit exceeded. Please wait before creating another poll." };
    }

    // Handle expiration date
    let expirationDate: string | null = null;
    if (expires_at) {
      const date = new Date(expires_at);
      if (isNaN(date.getTime())) {
        return { error: "Invalid date format for expiration." };
      }
      if (date <= new Date()) {
        return { error: "Expiration date must be in the future." };
      }
      expirationDate = date.toISOString();
    }

    // Create poll record with sanitized data
    const { data: pollData, error } = await supabase.from("polls").insert([
      {
        user_id: userId,
        question: sanitizedQuestion,
        options: sanitizedOptions,
        expires_at: expirationDate,
      },
    ]).select().single();

    if (error) {
      await auditLog("poll_creation_failed", { error: error.message });
      return { error: error.message };
    }

    // Audit log successful poll creation
    await auditLog("poll_created", { 
      pollId: pollData.id, 
      questionLength: sanitizedQuestion.length,
      optionsCount: sanitizedOptions.length,
      expires_at: expirationDate
    });

    revalidatePath("/polls");
    return { error: null, pollId: pollData.id };
  } catch (error) {
    console.error("Error in createPoll:", error);
    await auditLog("poll_creation_error", { error: error instanceof Error ? error.message : "Unknown error" });
    return { error: "An unexpected error occurred while creating the poll." };
  }
}

/**
 * Get User Polls Server Action
 * 
 * Retrieves all polls created by the currently authenticated user.
 * Returns polls in descending order by creation date (newest first).
 * 
 * @returns Promise<{polls: Poll[], error: string | null}> - User's polls or error
 * 
 * Features:
 * - Authentication check before data retrieval
 * - Ordered results for better user experience
 * - Proper error handling and user feedback
 * 
 * Used in:
 * - User dashboard to display created polls
 * - Poll management interfaces
 */
export async function getUserPolls() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  
  // Ensure user is authenticated before showing their polls
  if (!user) return { polls: [], error: "Not authenticated" };

  // Fetch user's polls ordered by creation date (newest first)
  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return { polls: [], error: error.message };
  return { polls: data ?? [], error: null };
}

/**
 * Get Poll By ID Server Action
 * 
 * Retrieves a specific poll by its unique identifier.
 * Used for displaying individual poll details and voting interfaces.
 * 
 * @param id - Unique poll identifier (UUID)
 * @returns Promise<{poll: Poll | null, error: string | null}> - Poll data or error
 * 
 * Features:
 * - Public access (no authentication required for viewing)
 * - Single poll retrieval for efficient data fetching
 * - Proper error handling for non-existent polls
 * 
 * Used in:
 * - Poll viewing pages
 * - Voting interfaces
 * - Poll sharing via direct links
 */
export async function getPollById(id: string) {
  const supabase = await createClient();
  
  // Retrieve specific poll by ID (public access)
  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("id", id)
    .single();

  if (error) return { poll: null, error: error.message };
  return { poll: data, error: null };
}

/**
 * Submit Vote Server Action
 * 
 * Handles vote submission for polls with comprehensive validation and security measures.
 * Supports both authenticated and anonymous voting with appropriate rate limiting.
 * 
 * @param pollId - Unique identifier of the poll to vote on
 * @param optionIndex - Index of the selected option (0-based)
 * @returns Promise<{error: string | null}> - Success/error response
 * 
 * Security features:
 * - Input validation using Zod schema
 * - Poll existence verification
 * - Option index bounds checking
 * - Duplicate vote prevention for authenticated users
 * - Rate limiting for anonymous votes (10 per 5 minutes per poll)
 * - Comprehensive audit logging
 * 
 * Voting rules:
 * - Authenticated users: One vote per poll (enforced by database)
 * - Anonymous users: Rate limited to prevent spam
 * - All votes are permanently recorded for poll integrity
 * 
 * Flow:
 * 1. Validate input parameters
 * 2. Verify poll exists and option is valid
 * 3. Check for duplicate votes (authenticated users)
 * 4. Apply rate limiting (anonymous users)
 * 5. Record vote in database
 * 6. Log voting activity for monitoring
 */
export async function submitVote(pollId: string, optionIndex: number) {
  try {
    const supabase = await createClient();
    
    // Get user information (supports both authenticated and anonymous voting)
    const { data: { user } } = await supabase.auth.getUser();
    const userId = user?.id || null;

    // Validate input parameters against schema
    const validationResult = voteSchema.safeParse({ pollId, optionIndex });
    if (!validationResult.success) {
      const errors = validationResult.error.issues.map(e => e.message).join(", ");
      return { error: `Validation failed: ${errors}` };
    }

    // Verify poll exists and retrieve poll details
    const { data: poll, error: pollError } = await supabase
      .from("polls")
      .select("id, question, options, user_id, expires_at")
      .eq("id", pollId)
      .single();

    if (pollError || !poll) {
      return { error: "Poll not found" };
    }

    // Check if the poll is expired
    if (poll.expires_at && new Date(poll.expires_at) < new Date()) {
      return { error: "This poll has expired and is no longer accepting votes." };
    }

    // Validate option index is within bounds of available options
    if (optionIndex >= poll.options.length || optionIndex < 0) {
      return { error: "Invalid option selected" };
    }

    // Prevent duplicate votes for authenticated users
    if (userId) {
      const { data: existingVote, error: voteCheckError } = await supabase
        .from("votes")
        .select("id")
        .eq("poll_id", pollId)
        .eq("user_id", userId)
        .single();

      // Handle database errors (PGRST116 = no rows found, which is expected for new votes)
      if (voteCheckError && voteCheckError.code !== 'PGRST116') {
        console.error("Error checking existing vote:", voteCheckError);
        return { error: "Error checking vote status" };
      }

      // Reject duplicate votes to maintain poll integrity
      if (existingVote) {
        return { error: "You have already voted on this poll" };
      }
    }

    // Apply rate limiting for anonymous votes to prevent spam
    // Note: In production, IP-based rate limiting would be more effective
    if (!userId) {
      const { data: recentAnonymousVotes, error: rateLimitError } = await supabase
        .from("votes")
        .select("id")
        .eq("poll_id", pollId)
        .is("user_id", null)
        .gte("created_at", new Date(Date.now() - 300000).toISOString()); // Last 5 minutes

      if (rateLimitError) {
        console.error("Error checking rate limit:", rateLimitError);
      } else if (recentAnonymousVotes && recentAnonymousVotes.length >= 10) {
        return { error: "Too many anonymous votes. Please try again later." };
      }
    }

    // Record the vote in the database
    const { error } = await supabase.from("votes").insert([
      {
        poll_id: pollId,
        user_id: userId, // null for anonymous votes
        option_index: optionIndex,
      },
    ]);

    if (error) {
      await auditLog("vote_submission_failed", userId || '', { 
        pollId, 
        optionIndex, 
        error: error.message 
      });
      return { error: error.message };
    }

    // Log successful vote for security monitoring and analytics
    await auditLog("vote_submitted", userId || "anonymous", { 
      pollId, 
      optionIndex,
      pollOwnerId: poll.user_id
    });

    // Revalidate the poll page to show updated results
    revalidatePath(`/polls/${pollId}`);
    return { error: null };
  } catch (error) {
    console.error("Error in submitVote:", error);
    await auditLog("vote_submission_error", "", { 
      pollId, 
      optionIndex, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
    return { error: "An unexpected error occurred while submitting your vote." };
  }
}

// DELETE POLL
/**
 * Delete Poll Server Action
 * 
 * Permanently removes a poll from the system with proper authorization checks.
 * Only poll owners and administrators can delete polls.
 * 
 * @param id - UUID of the poll to delete
 * @returns Promise<{error: string | null}> - Success/error response
 * 
 * Security features:
 * - Authentication required (no anonymous deletions)
 * - UUID format validation
 * - Poll existence verification
 * - Authorization checks (owner or admin only)
 * - Comprehensive audit logging for security monitoring
 * - Unauthorized attempt tracking
 * 
 * Authorization rules:
 * - Poll owners can delete their own polls
 * - Administrators can delete any poll (logged separately)
 * - All deletion attempts are audited for security
 * 
 * Database effects:
 * - Cascading deletion removes associated votes
 * - Poll data is permanently removed (no soft delete)
 * - Related cache entries are invalidated
 * 
 * Flow:
 * 1. Authenticate user
 * 2. Validate poll ID format
 * 3. Verify poll exists and get ownership info
 * 4. Check authorization (owner or admin)
 * 5. Delete poll from database
 * 6. Log deletion activity
 * 7. Revalidate affected pages
 */
export async function deletePoll(id: string) {
  try {
    // Ensure user is authenticated before allowing deletion
    const userId = await requireAuth();
    
    const supabase = await createClient();

    // Validate poll ID is a proper UUID format
    if (!z.string().uuid().safeParse(id).success) {
      return { error: "Invalid poll ID format" };
    }

    // Verify poll exists and retrieve ownership information
    const { data: poll, error: fetchError } = await supabase
      .from("polls")
      .select("id, user_id, question")
      .eq("id", id)
      .single();

    if (fetchError || !poll) {
      return { error: "Poll not found" };
    }

    // Check authorization - only poll owner or admin can delete
    const userIsAdmin = await isAdmin(userId);
    const canDelete = poll.user_id === userId || userIsAdmin;

    if (!canDelete) {
      // Log unauthorized deletion attempts for security monitoring
      await auditLog("unauthorized_poll_delete_attempt", userId, { 
        pollId: id, 
        pollOwnerId: poll.user_id 
      });
      return { error: "Unauthorized: You can only delete your own polls" };
    }

    // Permanently delete the poll (cascades to votes)
    const { error } = await supabase.from("polls").delete().eq("id", id);
    
    if (error) {
      await auditLog("poll_deletion_failed", userId, { 
        pollId: id, 
        error: error.message 
      });
      return { error: error.message };
    }

    // Log successful deletion with context for audit trail
    await auditLog("poll_deleted", userId, { 
      pollId: id, 
      pollOwnerId: poll.user_id,
      deletedByAdmin: userIsAdmin && poll.user_id !== userId,
      pollQuestion: poll.question.substring(0, 100) // Log first 100 chars for reference
    });

    // Invalidate cached pages that might show this poll
    revalidatePath("/polls");
    revalidatePath("/admin");
    return { error: null };
  } catch (error) {
    console.error("Error in deletePoll:", error);
    await auditLog("poll_deletion_error", "", { 
      pollId: id, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
    return { error: "An unexpected error occurred while deleting the poll." };
  }
}

/**
 * Update Poll Server Action
 * 
 * Modifies an existing poll's question and options with strict validation and authorization.
 * Updates are only allowed for polls without votes to maintain data integrity.
 * 
 * @param id - UUID of the poll to update
 * @param question - New poll question (1-500 characters)
 * @param options - Array of new poll options (2-10 options, max 200 chars each)
 * @returns Promise<{error: string | null}> - Success/error response
 * 
 * Security features:
 * - Authentication required (no anonymous updates)
 * - Input validation using Zod schema
 * - XSS protection via input sanitization
 * - UUID format validation
 * - Authorization checks (owner or admin only)
 * - Vote existence check to prevent data corruption
 * - Comprehensive audit logging
 * 
 * Business rules:
 * - Only poll owners and admins can update polls
 * - Polls with existing votes cannot be modified
 * - All inputs are sanitized to prevent XSS attacks
 * - Updates are tracked with before/after values
 * 
 * Data integrity:
 * - Prevents modification of polls with votes
 * - Maintains referential integrity
 * - Updates timestamp for change tracking
 * - Invalidates relevant cached pages
 * 
 * Flow:
 * 1. Authenticate user
 * 2. Validate input format and content
 * 3. Sanitize inputs for security
 * 4. Verify poll exists and get ownership info
 * 5. Check authorization (owner or admin)
 * 6. Ensure no votes exist (data integrity)
 * 7. Update poll in database
 * 8. Log update activity
 * 9. Revalidate affected pages
 */
export async function updatePoll(id: string, question: string, options: string[]) {
  try {
    // Ensure user is authenticated before allowing updates
    const userId = await requireAuth();
    
    const supabase = await createClient();

    // Validate input using the same strict schema as poll creation
    const validationResult = createPollSchema.safeParse({ question, options });
    if (!validationResult.success) {
      const errors = validationResult.error.issues.map(e => e.message).join(", ");
      return { error: `Validation failed: ${errors}` };
    }

    // Validate poll ID is a proper UUID format
    if (!z.string().uuid().safeParse(id).success) {
      return { error: "Invalid poll ID format" };
    }

    // Sanitize inputs to prevent XSS attacks
    const sanitizedQuestion = sanitizeInput(question);
    const sanitizedOptions = options.map(option => sanitizeInput(option));

    // Verify poll exists and retrieve ownership information
    const { data: poll, error: fetchError } = await supabase
      .from("polls")
      .select("id, user_id, question")
      .eq("id", id)
      .single();

    if (fetchError || !poll) {
      return { error: "Poll not found" };
    }

    // Check authorization - only poll owner or admin can update
    const userIsAdmin = await isAdmin(userId);
    const canUpdate = poll.user_id === userId || userIsAdmin;

    if (!canUpdate) {
      // Log unauthorized update attempts for security monitoring
      await auditLog("unauthorized_poll_update_attempt", userId, { 
        pollId: id, 
        pollOwnerId: poll.user_id 
      });
      return { error: "Unauthorized: You can only update your own polls" };
    }

    // Prevent updates to polls with votes to maintain data integrity
    const { data: votes, error: voteCheckError } = await supabase
      .from("votes")
      .select("id")
      .eq("poll_id", id)
      .limit(1);

    if (voteCheckError) {
      console.error("Error checking votes:", voteCheckError);
      return { error: "Error checking poll status" };
    }

    if (votes && votes.length > 0) {
      return { error: "Cannot update poll that already has votes" };
    }

    // Update the poll with sanitized data and timestamp
    const { error } = await supabase
      .from("polls")
      .update({ 
        question: sanitizedQuestion, 
        options: sanitizedOptions,
        updated_at: new Date().toISOString()
      })
      .eq("id", id);
      
    if (error) {
      await auditLog("poll_update_failed", userId, { 
        pollId: id, 
        error: error.message 
      });
      return { error: error.message };
    }

    // Log successful update with before/after context for audit trail
    await auditLog("poll_updated", userId, { 
      pollId: id, 
      pollOwnerId: poll.user_id,
      updatedByAdmin: userIsAdmin && poll.user_id !== userId,
      oldQuestion: poll.question.substring(0, 100),
      newQuestion: sanitizedQuestion.substring(0, 100)
    });

    // Invalidate cached pages that display this poll
    revalidatePath("/polls");
    revalidatePath(`/polls/${id}`);
    revalidatePath(`/polls/${id}/edit`);
    return { error: null };
  } catch (error) {
    console.error("Error in updatePoll:", error);
    await auditLog("poll_update_error", "", { 
      pollId: id, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
    return { error: "An unexpected error occurred while updating the poll." };
  }
}
