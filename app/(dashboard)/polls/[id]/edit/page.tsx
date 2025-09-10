import { getPollById } from '@/app/lib/actions/poll-actions';
import { notFound } from 'next/navigation';
// Import the client component
import EditPollForm from './EditPollForm';

/**
 * Server component that renders the poll edit page for a given poll ID.
 *
 * Awaits the provided `params` promise to obtain `id`, loads the poll via `getPollById(id)`,
 * and triggers a 404 (via `notFound()`) if the poll is missing or an error occurs.
 * When successful, renders a container with a heading and the `EditPollForm` populated with the poll.
 *
 * @param params - A promise that resolves to an object containing the route `id` string.
 * @returns The JSX for the edit-poll page.
 */
export default async function EditPollPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { poll, error } = await getPollById(id);

  if (error || !poll) {
    notFound();
  }

  return (
    <div className="max-w-md mx-auto py-8">
      <h1 className="text-2xl font-bold mb-6">Edit Poll</h1>
      <EditPollForm poll={poll} />
    </div>
  );
}