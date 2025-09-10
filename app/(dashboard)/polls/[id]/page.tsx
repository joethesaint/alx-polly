'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { getPollById, submitVote } from '@/app/lib/actions/poll-actions';
import { Poll } from '@/app/lib/types'; /**
 * Renders a poll details page for the poll identified by `params.id`, allowing users to view the question, select an option, and submit a vote.
 *
 * This client-side React component:
 * - Fetches poll data via `getPollById(params.id)` on mount / when `params.id` changes.
 * - Shows loading and error states while fetching.
 * - Displays poll options for voting unless the poll is expired or a vote has been cast, in which case a results placeholder is shown.
 * - Submits votes via `submitVote(poll.id, selectedOption)`, refreshes the poll on success, and marks that results should be shown.
 *
 * Note: Detailed result calculation/display is not implemented in this version.
 *
 * @param params - Route params containing the poll `id`.
 * @returns A React element rendering the poll detail UI.
 */

export default function PollDetailPage({ params }: { params: { id: string } }) {
  const [poll, setPoll] = useState<Poll | null>(null);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<any | null>(null); // To show results after voting

  useEffect(() => {
    const fetchPoll = async () => {
      const { poll: data, error } = await getPollById(params.id);
      if (error) {
        setError("Poll not found.");
      } else {
        setPoll(data);
      }
    };
    fetchPoll();
  }, [params.id]);

  const handleVote = async () => {
    if (selectedOption === null || !poll) return;
    
    setIsSubmitting(true);
    setError(null);

    const res = await submitVote(poll.id, selectedOption);

    if (res.error) {
      setError(res.error);
    } else {
      // Vote successful, fetch updated results
      const updatedPoll = await getPollById(params.id);
      if (updatedPoll.poll) {
        setPoll(updatedPoll.poll);
        // A real implementation would calculate results here or fetch them
        setResults({ voted: true }); 
      }
    }
    setIsSubmitting(false);
  };

  if (error) {
    return <div className="text-red-500 text-center">{error}</div>;
  }

  if (!poll) {
    return <div className="text-center">Loading poll...</div>;
  }

  const isExpired = poll.expires_at && new Date(poll.expires_at) < new Date();

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <Link href="/polls" className="text-blue-600 hover:underline">
          &larr; Back to Polls
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-2xl">{poll.question}</CardTitle>
          {poll.expires_at && (
            <CardDescription>
              {isExpired ? "Poll closed on" : "Poll closes on"}: {new Date(poll.expires_at).toLocaleString()}
            </CardDescription>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          {isExpired || results ? (
            <div>
              <h3 className="font-medium mb-2">Results:</h3>
              <p className="text-sm text-slate-500">(Result calculation is not implemented in this version)</p>
              {/* A full implementation would show vote counts and percentages here */}
            </div>
          ) : (
            <div className="space-y-3">
              {poll.options.map((option, idx) => (
                <div 
                  key={idx} 
                  className={`p-3 border rounded-md cursor-pointer transition-colors ${selectedOption === idx ? 'border-blue-500 bg-blue-50' : 'hover:bg-slate-50'}`}
                  onClick={() => setSelectedOption(idx)}
                >
                  {option}
                </div>
              ))}
              <Button 
                onClick={handleVote} 
                disabled={selectedOption === null || isSubmitting} 
                className="mt-4"
              >
                {isSubmitting ? 'Submitting...' : 'Submit Vote'}
              </Button>
            </div>
          )}
        </CardContent>
        <CardFooter className="text-sm text-slate-500 flex justify-between">
          <span>Created at: {new Date(poll.created_at).toLocaleDateString()}</span>
        </CardFooter>
      </Card>
    </div>
  );
}