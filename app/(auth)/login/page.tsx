'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertCircle, Info } from 'lucide-react';
import { login } from '@/app/lib/actions/auth-actions';

/**
 * Login page component for ALX Polly.
 *
 * Renders a login form, shows an informational alert when redirected from a protected page
 * and a session/error alert when present in the query string, and handles authentication.
 *
 * On submit it calls the `login` action with the provided email and password, displays any
 * returned error, and on success performs a full page navigation to the original destination
 * (query param `redirectTo`) or to `/polls` to ensure the authenticated session is picked up.
 *
 * Displays a loading state that disables inputs and the submit button while the request is in progress.
 *
 * @returns The login page JSX.
 */
export default function LoginPage() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [redirectMessage, setRedirectMessage] = useState<string | null>(null);
  const searchParams = useSearchParams();
  
  useEffect(() => {
    const redirectTo = searchParams.get('redirectTo');
    const sessionError = searchParams.get('error');
    
    if (redirectTo) {
      setRedirectMessage(`Please log in to access ${redirectTo}`);
    }
    
    if (sessionError === 'session_error') {
      setError('Your session has expired. Please log in again.');
    }
  }, [searchParams]);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);

    const formData = new FormData(event.currentTarget);
    const email = formData.get('email') as string;
    const password = formData.get('password') as string;

    const result = await login({ email, password });

    if (result?.error) {
      setError(result.error);
      setLoading(false);
    } else {
      // Redirect to the original destination or default to polls
      const redirectTo = searchParams.get('redirectTo') || '/polls';
      window.location.href = redirectTo; // Full reload to pick up session
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-slate-50">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-center">Login to ALX Polly</CardTitle>
          <CardDescription className="text-center">Enter your credentials to access your account</CardDescription>
        </CardHeader>
        <CardContent>
          {redirectMessage && (
            <Alert className="mb-4 border-blue-200 bg-blue-50">
              <Info className="h-4 w-4 text-blue-600" />
              <AlertDescription className="text-blue-700">
                {redirectMessage}
              </AlertDescription>
            </Alert>
          )}
          
          {error && (
            <Alert className="mb-4 border-red-200 bg-red-50">
              <AlertCircle className="h-4 w-4 text-red-600" />
              <AlertDescription className="text-red-700">
                {error}
              </AlertDescription>
            </Alert>
          )}
          
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input 
                id="email" 
                name="email"
                type="email" 
                placeholder="your@email.com" 
                required
                autoComplete="email"
                disabled={loading}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input 
                id="password" 
                name="password"
                type="password" 
                required
                autoComplete="current-password"
                disabled={loading}
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
        </CardContent>
        <CardFooter className="flex justify-center">
          <p className="text-sm text-slate-500">
            Don&apos;t have an account?{' '}
            <Link href="/register" className="text-blue-600 hover:underline">
              Register
            </Link>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}