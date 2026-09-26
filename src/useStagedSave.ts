import { useRef, useState } from "react";
import { toPublicActionError } from "./actionErrors";

// App owns this draft across navigation. Only Apply submits it; a later edit
// must survive completion of a previously submitted batch.
export function useStagedSave<T>(persisted: T, save: (value: T) => Promise<void>) {
  const [edit, setEdit] = useState<{ value: T; revision: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const revision = useRef(0);
  const busy = useRef(false);
  const change = (value: T) => {
    setError("");
    setEdit({ value, revision: ++revision.current });
  };
  const apply = async () => {
    if (!edit || busy.current) return;
    busy.current = true;
    setRunning(true);
    setError("");
    try {
      await save(edit.value);
      setEdit((latest) => latest?.revision === edit.revision ? null : latest);
    } catch (failure) {
      if (revision.current === edit.revision) setError(toPublicActionError(failure).message);
    } finally {
      busy.current = false;
      setRunning(false);
    }
  };
  return {
    draft: edit?.value ?? persisted, change, error, running,
    pending: Boolean(edit), apply, retry: () => { void apply(); },
    discard: () => {
      if (busy.current) return;
      revision.current++;
      setEdit(null);
      setError("");
    },
  };
}
