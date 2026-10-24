/** Lightweight input validation helpers. */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 322 && EMAIL_RE.test(value);
}

export function isNonEmptyString(value: unknown, maxLength = 255): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= maxLength;
}

export function isValidPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}

export interface SignInBody {
  email: string;
  password: string;
}

export interface SignUpBody {
  firstName: string;
  lastName?: string;
  email: string;
  password: string;
}

export interface AuthorizeCallbackBody {
  email: string;
  password: string;
  client_id: string;
  redirect_uri: string;
  state?: string;
  scope?: string;
}

export interface TokenBody {
  grant_type: string;
  client_id: string;
  client_secret: string;
  code?: string;
  redirect_uri?: string;
  refresh_token?: string;
}

export interface OrgRegisterBody {
  name: string;
}

export interface ClientRegisterBody {
  client_name: string;
  redirect_uris: string[];
}
