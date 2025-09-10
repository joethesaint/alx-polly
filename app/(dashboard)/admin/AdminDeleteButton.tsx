"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { deletePoll } from "@/app/lib/actions/poll-actions";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

interface AdminDeleteButtonProps {
  pollId: string;
}

export function AdminDeleteButton({ pollId }: AdminDeleteButtonProps) {
  const [isDeleting, setIsDeleting] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const router = useRouter();

  const handleDelete = async () => {
    setIsDeleting(true);
    
    try {
      const result = await deletePoll(pollId);
      
      if (result.error) {
        toast.error(`Failed to delete poll: ${result.error}`);
      } else {
        toast.success("Poll deleted successfully");
        setIsOpen(false);
        router.refresh(); // Refresh the page to show updated data
      }
    } catch (error) {
      console.error("Error deleting poll:", error);
      toast.error("An unexpected error occurred while deleting the poll");
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <AlertDialog open={isOpen} onOpenChange={setIsOpen}>
      <AlertDialogTrigger asChild>
        <Button
          variant="destructive"
          size="sm"
          disabled={isDeleting}
        >
          {isDeleting ? "Deleting..." : "Delete"}
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>⚠️ Confirm Poll Deletion</AlertDialogTitle>
          <AlertDialogDescription className="space-y-2">
            <p>
              Are you sure you want to delete this poll? This action cannot be undone.
            </p>
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-sm text-red-800">
                <strong>Warning:</strong> This will permanently delete:
              </p>
              <ul className="text-sm text-red-700 mt-1 ml-4 list-disc">
                <li>The poll and all its options</li>
                <li>All votes associated with this poll</li>
                <li>Any related data or statistics</li>
              </ul>
            </div>
            <p className="text-sm text-gray-600">
              <strong>Poll ID:</strong> <code className="bg-gray-100 px-1 rounded">{pollId.substring(0, 8)}...</code>
            </p>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={isDeleting}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={handleDelete}
            disabled={isDeleting}
            className="bg-red-600 hover:bg-red-700 focus:ring-red-600"
          >
            {isDeleting ? "Deleting..." : "Delete Poll"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}