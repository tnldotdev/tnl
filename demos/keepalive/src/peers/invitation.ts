export class InvitationUnavailable extends Error {
  constructor(busy: boolean) {
    super(busy ? "The host couldn't accept this upload." : "The hosting invitation expired.");
  }
}
