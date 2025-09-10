-- Security RBAC Migration
-- Add role-based access control to the application

-- Create user_roles enum type
CREATE TYPE user_role AS ENUM ('user', 'admin', 'moderator');

-- Add role column to auth.users metadata or create a separate profiles table
-- Since we can't modify auth.users directly, we'll create a user_profiles table
CREATE TABLE IF NOT EXISTS public.user_profiles (
    id UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
    role user_role DEFAULT 'user' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS on user_profiles
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

-- RLS Policies for user_profiles
-- Users can read their own profile
CREATE POLICY "Users can read own profile" ON public.user_profiles
    FOR SELECT USING (auth.uid() = id);

-- Only admins can read all profiles
CREATE POLICY "Admins can read all profiles" ON public.user_profiles
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM public.user_profiles
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Users can update their own profile (except role)
CREATE POLICY "Users can update own profile" ON public.user_profiles
    FOR UPDATE USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id AND role = (SELECT role FROM public.user_profiles WHERE id = auth.uid()));

-- Only admins can update user roles
CREATE POLICY "Admins can update user roles" ON public.user_profiles
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM public.user_profiles
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Auto-create user profile on user registration
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_profiles (id, role)
    VALUES (NEW.id, 'user');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to create profile on user signup
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Function to check if user is admin
CREATE OR REPLACE FUNCTION public.is_admin(user_id UUID DEFAULT auth.uid())
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.user_profiles
        WHERE id = user_id AND role = 'admin'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get user role
CREATE OR REPLACE FUNCTION public.get_user_role(user_id UUID DEFAULT auth.uid())
RETURNS user_role AS $$
DECLARE
    user_role_result user_role;
BEGIN
    SELECT role INTO user_role_result
    FROM public.user_profiles
    WHERE id = user_id;
    
    RETURN COALESCE(user_role_result, 'user');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Update existing polls table RLS policies to include admin access
-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Users can read own polls" ON public.polls;
DROP POLICY IF EXISTS "Users can create polls" ON public.polls;
DROP POLICY IF EXISTS "Users can update own polls" ON public.polls;
DROP POLICY IF EXISTS "Users can delete own polls" ON public.polls;

-- Create new policies with admin access
CREATE POLICY "Users can read own polls" ON public.polls
    FOR SELECT USING (
        user_id = auth.uid() OR 
        public.is_admin()
    );

CREATE POLICY "Users can create polls" ON public.polls
    FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can update own polls" ON public.polls
    FOR UPDATE USING (
        user_id = auth.uid() OR 
        public.is_admin()
    );

CREATE POLICY "Users can delete own polls" ON public.polls
    FOR DELETE USING (
        user_id = auth.uid() OR 
        public.is_admin()
    );

-- Update poll_options RLS policies
DROP POLICY IF EXISTS "Users can read poll options" ON public.poll_options;
DROP POLICY IF EXISTS "Users can create poll options" ON public.poll_options;
DROP POLICY IF EXISTS "Users can update poll options" ON public.poll_options;
DROP POLICY IF EXISTS "Users can delete poll options" ON public.poll_options;

CREATE POLICY "Users can read poll options" ON public.poll_options
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM public.polls
            WHERE polls.id = poll_options.poll_id
            AND (polls.user_id = auth.uid() OR public.is_admin())
        )
    );

CREATE POLICY "Users can create poll options" ON public.poll_options
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.polls
            WHERE polls.id = poll_options.poll_id
            AND polls.user_id = auth.uid()
        )
    );

CREATE POLICY "Users can update poll options" ON public.poll_options
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM public.polls
            WHERE polls.id = poll_options.poll_id
            AND (polls.user_id = auth.uid() OR public.is_admin())
        )
    );

CREATE POLICY "Users can delete poll options" ON public.poll_options
    FOR DELETE USING (
        EXISTS (
            SELECT 1 FROM public.polls
            WHERE polls.id = poll_options.poll_id
            AND (polls.user_id = auth.uid() OR public.is_admin())
        )
    );

-- Update votes RLS policies
DROP POLICY IF EXISTS "Users can read votes" ON public.votes;
DROP POLICY IF EXISTS "Users can create votes" ON public.votes;

CREATE POLICY "Users can read votes" ON public.votes
    FOR SELECT USING (
        user_id = auth.uid() OR 
        public.is_admin() OR
        EXISTS (
            SELECT 1 FROM public.polls p
            JOIN public.poll_options po ON p.id = po.poll_id
            WHERE po.id = votes.option_id
            AND (p.user_id = auth.uid() OR public.is_admin())
        )
    );

CREATE POLICY "Users can create votes" ON public.votes
    FOR INSERT WITH CHECK (user_id = auth.uid());

-- Create admin user (replace with actual admin email)
-- This should be run manually with the correct admin email
-- INSERT INTO auth.users (email, encrypted_password, email_confirmed_at, created_at, updated_at)
-- VALUES ('admin@example.com', crypt('admin_password', gen_salt('bf')), NOW(), NOW(), NOW());
-- 
-- INSERT INTO public.user_profiles (id, role)
-- SELECT id, 'admin' FROM auth.users WHERE email = 'admin@example.com';

COMMIT;