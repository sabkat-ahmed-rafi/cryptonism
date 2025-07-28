import { AttemptTrackerConfig } from "../types/types";

const getAttemptKey = (id: string) => `vault_decrypt_attempts_${id}`;

export const trackFailedAttempt = (config: AttemptTrackerConfig): {
  attempts: number;
  reset: boolean;
} => {
  const key = getAttemptKey(config.id);
  const raw = localStorage.getItem(key);
  let attempts = raw ? parseInt(raw) : 0;

  attempts += 1;

  if (attempts >= config.maxAttempts) {
    localStorage.removeItem(key);
    return { attempts, reset: true };
  } else {
    localStorage.setItem(key, attempts.toString());
    return { attempts, reset: false };
  }
};

export const resetAttempts = (id: string): void => {
  localStorage.removeItem(getAttemptKey(id));
};

export const getAttemptCount = (id: string): number => {
  const raw = localStorage.getItem(getAttemptKey(id));
  return raw ? parseInt(raw) : 0;
};
