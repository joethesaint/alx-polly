import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { deletePoll } from "@/app/lib/actions/poll-actions";
import { createClient } from "@/lib/supabase/server";
import { requireAdmin, getAllUserProfiles } from "@/lib/rbac";
import { redirect } from "next/navigation";
import { AdminDeleteButton } from "./AdminDeleteButton";

interface Poll {
  id: string;
  question: string;
  user_id: string;
  created_at: string;
  updated_at?: string;
  options: string[];
  vote_count?: number;
}

interface UserProfile {
  id: string;
  email?: string;
  role: string;
}

export default async function AdminPage() {
  try {
    // Require admin access - this will redirect if not admin
    await requireAdmin();
  } catch (error) {
    redirect('/unauthorized');
  }

  const supabase = await createClient();

  // Fetch all polls with vote counts and user information
  const { data: polls, error: pollsError } = await supabase
    .from("polls")
    .select(`
      *,
      votes(count)
    `)
    .order("created_at", { ascending: false });

  if (pollsError) {
    console.error("Error fetching polls:", pollsError);
    return (
      <div className="p-6">
        <Alert variant="destructive">
          <AlertDescription>
            Error loading polls: {pollsError.message}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // Get user profiles for displaying user information
  const userProfiles = await getAllUserProfiles();
  const userProfileMap = new Map(userProfiles.map(profile => [profile.id, profile]));

  // Process polls to include vote counts
  const processedPolls: (Poll & { vote_count: number })[] = polls?.map(poll => ({
    ...poll,
    vote_count: Array.isArray(poll.votes) ? poll.votes.length : 0
  })) || [];

  return (
    <div className="p-6 space-y-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-red-600">🔒 Admin Panel</h1>
        <p className="text-gray-600 mt-2">
          Secure administrative access to view and manage all polls in the system.
        </p>
        <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
          <p className="text-sm text-yellow-800">
            <strong>Security Notice:</strong> This panel provides administrative access to all polls. 
            All actions are logged for security auditing.
          </p>
        </div>
      </div>

      <div className="grid gap-4">
        {processedPolls.map((poll) => {
          const userProfile = userProfileMap.get(poll.user_id);
          return (
            <Card key={poll.id} className="border-l-4 border-l-red-500">
              <CardHeader>
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <CardTitle className="text-lg">{poll.question}</CardTitle>
                      <Badge variant="secondary">
                        {poll.vote_count} vote{poll.vote_count !== 1 ? 's' : ''}
                      </Badge>
                    </div>
                    <CardDescription>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                        <div>
                          <strong>Poll ID:</strong>{" "}
                          <code className="bg-gray-100 px-2 py-1 rounded text-xs font-mono">
                            {poll.id.substring(0, 8)}...
                          </code>
                        </div>
                        <div>
                          <strong>Owner:</strong>{" "}
                          <span className="text-sm">
                            {userProfile?.email || 'Unknown User'}
                          </span>
                          {userProfile?.role && (
                            <Badge variant="outline" className="ml-2 text-xs">
                              {userProfile.role}
                            </Badge>
                          )}
                        </div>
                        <div>
                          <strong>Created:</strong>{" "}
                          {new Date(poll.created_at).toLocaleDateString()}
                        </div>
                        {poll.updated_at && poll.updated_at !== poll.created_at && (
                          <div>
                            <strong>Updated:</strong>{" "}
                            {new Date(poll.updated_at).toLocaleDateString()}
                          </div>
                        )}
                      </div>
                    </CardDescription>
                  </div>
                  <AdminDeleteButton pollId={poll.id} />
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <h4 className="font-medium">Poll Options:</h4>
                  <ul className="list-disc list-inside space-y-1">
                    {poll.options.map((option, index) => (
                      <li key={index} className="text-gray-700">
                        {option}
                      </li>
                    ))}
                  </ul>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {processedPolls.length === 0 && (
        <div className="text-center py-8 text-gray-500">
          <p>No polls found in the system.</p>
          <p className="text-sm mt-2">All polls will appear here for administrative review.</p>
        </div>
      )}
    </div>
  );
}
