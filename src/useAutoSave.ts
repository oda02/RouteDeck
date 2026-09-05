import { useEffect, useRef, useState } from "react";
import { toPublicActionError } from "./actionErrors";

// Owned by App, so navigating away cannot discard a pending edit. Serial saves
// never replace a newer draft with an older completion or retry a failure forever.
export function useAutoSave<T>(persisted: T, save: (value: T) => Promise<void>) {
  const [edit, setEdit] = useState<{ value: T; revision: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const revision = useRef(0);
  const busy = useRef(false);
  const change = (value: T) => {
    setError("");
    setEdit({ value, revision: ++revision.current });
  };
  useEffect(() => {
    if (!edit || error || busy.current) return;
    const timer = window.setTimeout(() => {
      busy.current = true;
      setRunning(true);
      void save(edit.value).then(() => {
        setEdit((latest) => latest?.revision === edit.revision ? null : latest);
      }).catch((failure: unknown) => {
        if (revision.current === edit.revision) setError(toPublicActionError(failure).message);
      }).finally(() => {
        busy.current = false;
        setRunning(false);
      });
    }, 500);
    return () => window.clearTimeout(timer);
  }, [edit, error, running, save]);
  return {
    draft: edit?.value ?? persisted, change, error,
    pending: Boolean(edit), running,
    retry: () => setError(""),
    discard: () => { revision.current++; setEdit(null); setError(""); },
  };
}
