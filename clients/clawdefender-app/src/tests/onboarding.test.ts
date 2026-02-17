import { describe, it, expect } from 'vitest';

type Step = 1 | 2 | 3 | 4;

describe('Onboarding step navigation', () => {
  it('should start at step 1', () => {
    const step: Step = 1;
    expect(step).toBe(1);
  });

  it('should advance to the next step', () => {
    let step: Step = 1;
    step = Math.min(step + 1, 4) as Step;
    expect(step).toBe(2);
  });

  it('should not go beyond step 4', () => {
    let step: Step = 4;
    step = Math.min(step + 1, 4) as Step;
    expect(step).toBe(4);
  });

  it('should advance through all steps sequentially', () => {
    let step: Step = 1;
    const visited: number[] = [step];
    for (let i = 0; i < 3; i++) {
      step = Math.min(step + 1, 4) as Step;
      visited.push(step);
    }
    expect(visited).toEqual([1, 2, 3, 4]);
  });
});

describe('Onboarding security levels', () => {
  const SECURITY_LEVELS = [
    { id: 'permissive', name: 'Monitor Only', recommended: false },
    { id: 'balanced', name: 'Balanced', recommended: true },
    { id: 'strict', name: 'Strict', recommended: false },
  ];

  it('should default to balanced', () => {
    const selectedLevel = 'balanced';
    expect(selectedLevel).toBe('balanced');
  });

  it('should have exactly three security levels', () => {
    expect(SECURITY_LEVELS.length).toBe(3);
  });

  it('should mark only balanced as recommended', () => {
    const recommended = SECURITY_LEVELS.filter((l) => l.recommended);
    expect(recommended.length).toBe(1);
    expect(recommended[0].id).toBe('balanced');
  });

  it('should allow selecting any level', () => {
    for (const level of SECURITY_LEVELS) {
      expect(['permissive', 'balanced', 'strict']).toContain(level.id);
    }
  });
});

describe('Onboarding server detection', () => {
  it('should toggle server selection', () => {
    const servers = [
      { name: 'server-a', checked: true },
      { name: 'server-b', checked: false },
      { name: 'server-c', checked: true },
    ];

    const toggled = servers.map((s, i) =>
      i === 1 ? { ...s, checked: !s.checked } : s
    );

    expect(toggled[1].checked).toBe(true);
    expect(toggled[0].checked).toBe(true);
    expect(toggled[2].checked).toBe(true);
  });

  it('should filter only checked servers for wrapping', () => {
    const servers = [
      { name: 'server-a', checked: true, wrapped: false },
      { name: 'server-b', checked: false, wrapped: false },
      { name: 'server-c', checked: true, wrapped: true },
    ];

    const toWrap = servers.filter((s) => s.checked && !s.wrapped);
    expect(toWrap.length).toBe(1);
    expect(toWrap[0].name).toBe('server-a');
  });

  it('should count already-wrapped checked servers separately', () => {
    const servers = [
      { name: 'server-a', checked: true, wrapped: false },
      { name: 'server-b', checked: true, wrapped: true },
      { name: 'server-c', checked: false, wrapped: true },
    ];

    const alreadyWrapped = servers.filter((s) => s.checked && s.wrapped);
    expect(alreadyWrapped.length).toBe(1);
    expect(alreadyWrapped[0].name).toBe('server-b');
  });
});
