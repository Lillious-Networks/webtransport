/**
 * A minimal testharness.js, enough to run the WPT WebTransport tests under Bun.
 *
 * WPT tests are written for a browser: they call `promise_test`/`test` and the
 * `assert_*` family, which a browser supplies from testharness.js. That file
 * also drags in the whole browser harness (window globals, message channels,
 * the results reporter), so instead of loading it this reimplements only the
 * assertions the WebTransport tests actually use, over the same signatures.
 *
 * Divergence from the real harness is the risk here, so each assertion mirrors
 * testharness.js semantics rather than an approximation: `assert_equals` is
 * SameValue, `promise_rejects_exactly` compares object identity, and
 * `assert_throws_dom` checks the DOMException name rather than the message.
 */

export interface WptTest {
  name: string;
  fn: (t: TestCase) => unknown;
  isPromise: boolean;
}

/** The `t` handed to each test: cleanup registration and step helpers. */
export class TestCase {
  readonly cleanups: Array<() => unknown> = [];

  constructor(readonly name: string) {}

  add_cleanup(fn: () => unknown): void {
    this.cleanups.push(fn);
  }

  /** Wraps a callback so a throw inside it fails the test. */
  step_func<T extends (...args: any[]) => any>(fn: T): T {
    return ((...args: any[]) => fn(...args)) as T;
  }

  step_func_done<T extends (...args: any[]) => any>(fn: T): T {
    return this.step_func(fn);
  }

  step<T>(fn: () => T): T {
    return fn();
  }

  step_timeout(fn: () => void, ms: number): ReturnType<typeof setTimeout> {
    return setTimeout(fn, ms);
  }

  unreached_func(message = "unreached"): () => never {
    return () => {
      throw new AssertionError(message);
    };
  }
}

export class AssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AssertionError";
  }
}

const collected: WptTest[] = [];

export function promise_test(fn: (t: TestCase) => Promise<unknown>, name: string): void {
  collected.push({ name, fn, isPromise: true });
}

export function test(fn: (t: TestCase) => unknown, name: string): void {
  collected.push({ name, fn, isPromise: false });
}

export function takeTests(): WptTest[] {
  return collected.splice(0, collected.length);
}

function fail(message: string, description?: string): never {
  throw new AssertionError(description ? `${description}: ${message}` : message);
}

/** testharness.js compares with SameValue, so NaN equals NaN and 0 !== -0. */
export function assert_equals(actual: unknown, expected: unknown, description?: string): void {
  if (!Object.is(actual, expected)) {
    fail(`expected ${format(expected)} but got ${format(actual)}`, description);
  }
}

export function assert_not_equals(actual: unknown, expected: unknown, description?: string): void {
  if (Object.is(actual, expected)) {
    fail(`got disallowed value ${format(actual)}`, description);
  }
}

export function assert_true(actual: unknown, description?: string): void {
  if (actual !== true) fail(`expected true but got ${format(actual)}`, description);
}

export function assert_false(actual: unknown, description?: string): void {
  if (actual !== false) fail(`expected false but got ${format(actual)}`, description);
}

export function assert_array_equals(actual: ArrayLike<unknown>, expected: ArrayLike<unknown>, description?: string): void {
  if (actual == null || actual.length !== expected.length) {
    fail(`expected length ${expected?.length} but got ${(actual as any)?.length}`, description);
  }
  for (let i = 0; i < expected.length; i++) {
    if (!Object.is(actual[i], expected[i])) {
      fail(`at index ${i}: expected ${format(expected[i])} but got ${format(actual[i])}`, description);
    }
  }
}

export function assert_greater_than(actual: number, expected: number, description?: string): void {
  if (!(actual > expected)) fail(`expected a number greater than ${expected} but got ${actual}`, description);
}

export function assert_greater_than_equal(actual: number, expected: number, description?: string): void {
  if (!(actual >= expected)) fail(`expected a number at least ${expected} but got ${actual}`, description);
}

export function assert_less_than_equal(actual: number, expected: number, description?: string): void {
  if (!(actual <= expected)) fail(`expected a number at most ${expected} but got ${actual}`, description);
}

export function assert_less_than(actual: number, expected: number, description?: string): void {
  if (!(actual < expected)) fail(`expected a number less than ${expected} but got ${actual}`, description);
}

export function assert_unreached(description?: string): never {
  fail("reached unreachable code", description);
}

export function assert_implements_optional(condition: unknown, description?: string): void {
  if (!condition) throw new OptionalFeatureUnsupported(description ?? "optional feature not supported");
}

/** Signals a skip rather than a failure, as testharness.js does. */
export class OptionalFeatureUnsupported extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OptionalFeatureUnsupported";
  }
}

export function assert_throws_js(
  constructor: new (...args: any[]) => Error,
  fn: () => unknown,
  description?: string,
): void {
  try {
    fn();
  } catch (err) {
    if (!(err instanceof constructor)) {
      fail(`expected ${constructor.name} but got ${(err as Error)?.name}`, description);
    }
    return;
  }
  fail(`expected ${constructor.name} but no exception was thrown`, description);
}

export function assert_throws_dom(name: string, fn: () => unknown, description?: string): void {
  try {
    fn();
  } catch (err) {
    assertDomName(err, name, description);
    return;
  }
  fail(`expected DOMException ${name} but no exception was thrown`, description);
}

export async function promise_rejects_js(
  _t: TestCase,
  constructor: new (...args: any[]) => Error,
  promise: Promise<unknown>,
  description?: string,
): Promise<void> {
  try {
    await promise;
  } catch (err) {
    if (!(err instanceof constructor)) {
      fail(`expected ${constructor.name} but got ${describeError(err)}`, description);
    }
    return;
  }
  fail(`expected ${constructor.name} but the promise resolved`, description);
}

export async function promise_rejects_dom(
  _t: TestCase,
  name: string,
  promise: Promise<unknown>,
  description?: string,
): Promise<void> {
  try {
    await promise;
  } catch (err) {
    assertDomName(err, name, description);
    return;
  }
  fail(`expected DOMException ${name} but the promise resolved`, description);
}

/** Rejection with one specific value, compared by identity. */
export async function promise_rejects_exactly(
  _t: TestCase,
  expected: unknown,
  promise: Promise<unknown>,
  description?: string,
): Promise<void> {
  try {
    await promise;
  } catch (err) {
    if (!Object.is(err, expected)) {
      fail(`expected rejection with ${format(expected)} but got ${format(err)}`, description);
    }
    return;
  }
  fail("expected a rejection but the promise resolved", description);
}

function assertDomName(err: unknown, name: string, description?: string): void {
  const actual = (err as { name?: string })?.name;
  if (actual !== name) {
    fail(`expected DOMException ${name} but got ${describeError(err)}`, description);
  }
}

function describeError(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return format(err);
}

function format(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "bigint") return `${value}n`;
  if (value instanceof Error) return `${value.name}`;
  if (value === null) return "null";
  if (typeof value === "object") return Object.prototype.toString.call(value);
  return String(value);
}

export function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
