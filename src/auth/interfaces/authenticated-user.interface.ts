export interface AuthenticatedUser {
  userId: string;
  email: string;
  sessionId: string;
  type: string;
}
