export type FeedbackErrorCode =
  | "sign_in_required"
  | "author_changed"
  | "access_expired"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "unavailable"
  | "response_invalid"
  | "input_invalid"
  | "text_too_long"
  | "name_too_long";
const definitions: Record<FeedbackErrorCode, { retryable: boolean; message: string }> = {
  sign_in_required: {
    retryable: false,
    message: "sign in to leave feedback; your draft is still here",
  },
  author_changed: {
    retryable: false,
    message:
      "your posting identity changed; check the feedback list before starting a new submission",
  },
  access_expired: {
    retryable: false,
    message: "preview access was denied; check sign-in or reopen your share link",
  },
  not_found: { retryable: false, message: "feedback was not found; refresh the preview" },
  conflict: { retryable: false, message: "feedback changed; refresh and try again" },
  rate_limited: { retryable: true, message: "too many feedback requests; wait and try again" },
  unavailable: { retryable: true, message: "could not save or load feedback; try again" },
  response_invalid: {
    retryable: false,
    message: "the server returned invalid feedback; refresh and try again",
  },
  input_invalid: {
    retryable: false,
    message: "feedback input is invalid; check the report and try again",
  },
  text_too_long: { retryable: false, message: "feedback must be at most 4000 bytes" },
  name_too_long: { retryable: false, message: "the name must be at most 64 bytes" },
};
export class FeedbackError extends Error {
  readonly code: FeedbackErrorCode;
  readonly retryable: boolean;
  constructor(code: FeedbackErrorCode, options?: ErrorOptions) {
    super(definitions[code].message, options);
    this.name = "FeedbackError";
    this.code = code;
    this.retryable = definitions[code].retryable;
  }
}
export function safeFeedbackMessage(error: unknown): string {
  return definitions[error instanceof FeedbackError ? error.code : "unavailable"].message;
}
export function retryFeedback(count: number, error: unknown): boolean {
  return count < 2 && error instanceof FeedbackError && error.retryable;
}
