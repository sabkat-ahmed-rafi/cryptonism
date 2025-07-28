export type ArgonOptions = {
  time?: number;
  mem?: number;
  hashLen?: number;
}

export interface TrackAttemptsOptions {
  enable: true;
  id: string;
  maxAttempts: number;
}

export type AttemptTrackerConfig = {
  id: string;
  maxAttempts: number;
};