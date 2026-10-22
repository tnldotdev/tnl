import { FeedbackError } from "./errors.ts";

/** a separate tab keeps the current report, evidence, reply and mutation key intact. */
export function FeedbackSignIn({ error, path }: { error: unknown; path: string }) {
  if (!(error instanceof FeedbackError) || error.code !== "sign_in_required") return null;
  return (
    <p>
      <a
        href={"/__tnl/team/login?return=" + encodeURIComponent(path)}
        target="_blank"
        rel="noopener noreferrer"
      >
        sign in in another tab
      </a>{" "}
      then return here and send again
    </p>
  );
}
