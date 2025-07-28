export type ArgonOptions = {
  time?: number;
  mem?: number;
  hashLen?: number;
}

export type AttemptTrackerConfig = {
  id: string;
  maxAttempts: number;
};