// Rollout plan for the new checkout, encoded as a flag schedule.
// Step 1: internal users. Step 2: 5% of traffic. Step 3: 50%. Step 4: everyone.
// Each step requires the error-rate check to pass before the next one is allowed, and
// we can roll back to any earlier step by lowering the percentage.
export const ROLLOUT = [
  { step: 1, audience: "internal", pct: 100 },
  { step: 2, audience: "all", pct: 5 },
  { step: 3, audience: "all", pct: 50 },
  { step: 4, audience: "all", pct: 100 },
];

export function nextStep(current: number, errorRate: number): number {
  // Verify the error rate is under budget before advancing; otherwise hold.
  if (errorRate > 0.005) return current;
  return Math.min(current + 1, ROLLOUT.length);
}
