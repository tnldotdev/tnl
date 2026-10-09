import type { z } from "zod";
import type { BrowserFeedbackAccess } from "../publisherapi/model.gen.ts";
import { FeedbackError, safeFeedbackMessage } from "./errors.ts";

export type Access = z.infer<typeof BrowserFeedbackAccess>;
export type Posting = {
  access: Access | undefined;
  error: unknown;
  authorize: (author: string) => Promise<void>;
  refresh: () => void;
  signIn: (event: MouseEvent) => void;
  path: string;
};

export function authorKey(access: Access | undefined): string {
  return access?.identity_state === "signed_in" && access.identity
    ? "identity:" + access.identity.identity_id
    : access?.identity_state === "anonymous"
      ? "anonymous"
      : "unknown";
}

export function canPost(access: Access | undefined): boolean {
  return (
    !!access &&
    access.identity_state !== "expired" &&
    (!access.require_sign_in || access.identity_state === "signed_in")
  );
}

export function checkPosting(access: Access, author: string): void {
  if (!canPost(access)) throw new FeedbackError("sign_in_required");
  if (authorKey(access) !== author) throw new FeedbackError("author_changed");
}

export function SignInLink({ posting }: { posting: Posting }) {
  return (
    <a
      class="account-link"
      href={"/__tnl/team/login?return=" + encodeURIComponent(posting.path)}
      onClick={posting.signIn}
    >
      [ sign in ]
    </a>
  );
}

export function PostingIdentity({ posting }: { posting: Posting }) {
  const access = posting.access;
  if (!access)
    return (
      <p role="status" class="muted">
        {posting.error
          ? safeFeedbackMessage(posting.error)
          : "checking sign-in and feedback policy…"}
      </p>
    );
  if (access.identity_state === "signed_in" && access.identity)
    return <small>posting as {access.identity.display_name} (verified)</small>;
  const required = access.require_sign_in || access.identity_state === "expired";
  return (
    <div class="posting-identity">
      <small>
        {access.identity_state === "expired"
          ? "your sign-in expired; sign in again to leave feedback"
          : required
            ? "sign in to leave feedback"
            : "posting anonymously; optional names are unverified"}
      </small>{" "}
      {access.sign_in_available ? (
        <SignInLink posting={posting} />
      ) : required ? (
        <small>sign-in is unavailable here</small>
      ) : null}
    </div>
  );
}
