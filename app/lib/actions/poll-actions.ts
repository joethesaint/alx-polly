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
 * Strip all HTML tags and attributes from a string to prevent XSS.
 *
 * Returns a plain string with any HTML removed, suitable for safe storage and display.
 *
 * @param input - The raw user-provided string to sanitize
 * @returns The sanitized string with no HTML tags or attributes
 */
function sanitizeInput(input: string): string {
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
}

/**
 * Create a new poll for the authenticated user.
 *
 * Validates and sanitizes form input, enforces a per-user rate limit (max 5 polls per minute),
 * ensures an optional `expires_at` is a future date, inserts the poll into the database,
 * records audit logs, and revalidates the polls listing on success.
 *
 * @param formData - FormData with keys:
 *   - "question": string
 *   - "options": one or more option strings (repeated)
 *   - "expires_at" (optional): a date string parseable by Date
 * @returns A promise resolving to an object with `error` (null on success) and `pollId` when created.
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
 * Fetches polls created by the currently authenticated user, ordered newest-first.
 *
 * If the caller is not authenticated the function returns `{ polls: [], error: "Not authenticated" }`.
 *
 * @returns An object containing `polls` (array of Poll) and `error` (string | null). On success `error` is `null`.
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
 * Retrieve a poll by its UUID.
 *
 * Returns the poll record if found; otherwise returns `poll: null` and an `error` message.
 *
 * @param id - Poll UUID
 * @returns An object with `poll` (Poll | null) and `error` (string | null)
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
 * Permanently deletes a poll by ID if the caller is the poll owner or an administrator.
 *
 * Validates the poll ID (UUID), requires authentication, verifies existence and ownership,
 * performs the deletion (cascades to votes), records audit events for success/failure/unauthorized attempts,
 * and revalidates cache paths affected by the change.
 *
 * @param id - The poll's UUID
 * @returns An object with `error` set to null on success or an error message on failure
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
 * Update an existing poll's question and options.
 *
 * Performs validation, sanitization, and authorization; only the poll owner or an admin may update a poll,
 * and polls that already have votes cannot be modified. On success the poll record is updated and related
 * cached pages are revalidated; audit entries are written for important events.
 *
 * @param id - Poll UUID to update
 * @param question - New poll question (validated and sanitized; 1–500 characters)
 * @param options - New poll options (validated and sanitized; 2–10 items, each up to 200 characters)
 * @returns An object with `error` set to null on success or a string message describing the failure.
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
