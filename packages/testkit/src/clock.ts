import type { Clock } from '@badge/core'

/** A clock a test can move, so signature windows can be exercised without sleeping. */
export interface TestClock extends Clock {
  set(seconds: number): void
  advance(seconds: number): void
}

export function fixedClock(start = 1_735_689_600): TestClock {
  let current = start
  return {
    now: () => current,
    set: (seconds) => {
      current = seconds
    },
    advance: (seconds) => {
      current += seconds
    },
  }
}
