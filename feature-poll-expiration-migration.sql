-- Feature: Poll Expiration Dates
-- Adds an optional expiration date to polls.

ALTER TABLE public.polls
ADD COLUMN expires_at TIMESTAMPTZ;
