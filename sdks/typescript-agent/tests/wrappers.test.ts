import { withGuard, sandboxed } from '../src/wrappers';

// Mock fetch globally
const mockFetch = jest.fn().mockRejectedValue(new Error('no daemon'));
(global as any).fetch = mockFetch;

describe('withGuard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockRejectedValue(new Error('no daemon'));
  });

  test('wraps a function with guard protection', async () => {
    const fn = async (x: number) => x * 2;
    const wrapped = withGuard({ allowedPaths: ['/tmp/**'] }, fn);
    const result = await wrapped(5);
    expect(result).toBe(10);
  });

  test('returns the function result', async () => {
    const fn = async () => 'hello';
    const wrapped = withGuard({}, fn);
    expect(await wrapped()).toBe('hello');
  });

  test('deactivates guard even on error', async () => {
    const fn = async () => {
      throw new Error('test error');
    };
    const wrapped = withGuard({}, fn);
    await expect(wrapped()).rejects.toThrow('test error');
  });

  test('passes arguments through', async () => {
    const fn = async (a: string, b: string) => `${a}-${b}`;
    const wrapped = withGuard({}, fn);
    expect(await wrapped('foo', 'bar')).toBe('foo-bar');
  });

  test('uses function name for guard', async () => {
    async function myAgent() {
      return 42;
    }
    const wrapped = withGuard({}, myAgent);
    expect(await wrapped()).toBe(42);
  });

  test('handles anonymous functions', async () => {
    const wrapped = withGuard({}, async () => 'anon');
    expect(await wrapped()).toBe('anon');
  });
});

describe('sandboxed', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockRejectedValue(new Error('no daemon'));
  });

  test('executes function in sandbox', async () => {
    const fn = async () => 'result';
    const wrapped = sandboxed({ timeout: 5000 }, fn);
    expect(await wrapped()).toBe('result');
  });

  test('times out long-running functions', async () => {
    const fn = async () => {
      return new Promise<string>((resolve) =>
        setTimeout(() => resolve('late'), 10000),
      );
    };
    const wrapped = sandboxed({ timeout: 50 }, fn);
    await expect(wrapped()).rejects.toThrow('timed out');
  });

  test('passes arguments through', async () => {
    const fn = async (n: number) => n + 1;
    const wrapped = sandboxed({}, fn);
    expect(await wrapped(10)).toBe(11);
  });
});
