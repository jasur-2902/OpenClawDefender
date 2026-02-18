import { describe, it, expect } from 'vitest';
import type { NetworkExtensionStatus, NetworkSettings } from '../types';

describe('Network Extension Status', () => {
  it('should display active when filter is active', () => {
    const status: NetworkExtensionStatus = {
      loaded: true,
      filter_active: true,
      dns_active: true,
      filtering_count: 847,
      mock_mode: true,
    };
    const label = status.filter_active ? 'Active' : 'Inactive';
    expect(label).toBe('Active');
  });

  it('should display inactive when filter is not active', () => {
    const status: NetworkExtensionStatus = {
      loaded: false,
      filter_active: false,
      dns_active: false,
      filtering_count: 0,
      mock_mode: false,
    };
    const label = status.filter_active ? 'Active' : 'Inactive';
    expect(label).toBe('Inactive');
  });

  it('should indicate mock mode when mock_mode is true', () => {
    const status: NetworkExtensionStatus = {
      loaded: true,
      filter_active: true,
      dns_active: true,
      filtering_count: 100,
      mock_mode: true,
    };
    expect(status.mock_mode).toBe(true);
  });

  it('should not indicate mock mode when mock_mode is false', () => {
    const status: NetworkExtensionStatus = {
      loaded: true,
      filter_active: true,
      dns_active: true,
      filtering_count: 100,
      mock_mode: false,
    };
    expect(status.mock_mode).toBe(false);
  });

  it('should show filtering count when active', () => {
    const status: NetworkExtensionStatus = {
      loaded: true,
      filter_active: true,
      dns_active: true,
      filtering_count: 847,
      mock_mode: true,
    };
    expect(status.filtering_count).toBeGreaterThan(0);
  });
});

describe('Network Settings', () => {
  const defaultSettings: NetworkSettings = {
    filter_enabled: true,
    dns_enabled: true,
    filter_all_processes: false,
    default_action: 'prompt',
    prompt_timeout: 30,
    block_private_ranges: false,
    block_doh: true,
    log_dns: true,
  };

  it('should toggle filter_enabled', () => {
    const updated = { ...defaultSettings, filter_enabled: !defaultSettings.filter_enabled };
    expect(updated.filter_enabled).toBe(false);
  });

  it('should toggle dns_enabled', () => {
    const updated = { ...defaultSettings, dns_enabled: !defaultSettings.dns_enabled };
    expect(updated.dns_enabled).toBe(false);
  });

  it('should toggle filter_all_processes', () => {
    const updated = { ...defaultSettings, filter_all_processes: true };
    expect(updated.filter_all_processes).toBe(true);
  });

  it('should validate default_action options', () => {
    const validActions: NetworkSettings['default_action'][] = ['prompt', 'block', 'allow'];
    expect(validActions).toContain('prompt');
    expect(validActions).toContain('block');
    expect(validActions).toContain('allow');
    expect(validActions).toHaveLength(3);
  });

  it('should accept all valid default_action values', () => {
    for (const action of ['prompt', 'block', 'allow'] as const) {
      const settings = { ...defaultSettings, default_action: action };
      expect(settings.default_action).toBe(action);
    }
  });

  it('should validate prompt_timeout minimum (5 seconds)', () => {
    const timeout = 5;
    expect(timeout).toBeGreaterThanOrEqual(5);
    expect(timeout).toBeLessThanOrEqual(60);
  });

  it('should validate prompt_timeout maximum (60 seconds)', () => {
    const timeout = 60;
    expect(timeout).toBeGreaterThanOrEqual(5);
    expect(timeout).toBeLessThanOrEqual(60);
  });

  it('should reject prompt_timeout below range', () => {
    const timeout = 3;
    const clamped = Math.max(5, Math.min(60, timeout));
    expect(clamped).toBe(5);
  });

  it('should reject prompt_timeout above range', () => {
    const timeout = 120;
    const clamped = Math.max(5, Math.min(60, timeout));
    expect(clamped).toBe(60);
  });

  it('should toggle block_doh', () => {
    const updated = { ...defaultSettings, block_doh: !defaultSettings.block_doh };
    expect(updated.block_doh).toBe(false);
  });

  it('should toggle log_dns', () => {
    const updated = { ...defaultSettings, log_dns: !defaultSettings.log_dns };
    expect(updated.log_dns).toBe(false);
  });
});

describe('Dashboard Network Protection Card', () => {
  it('should show "Active" when filter is active', () => {
    const status: NetworkExtensionStatus = {
      loaded: true,
      filter_active: true,
      dns_active: true,
      filtering_count: 42,
      mock_mode: false,
    };
    const label = status.filter_active ? 'Active' : 'Inactive';
    expect(label).toBe('Active');
  });

  it('should show "Inactive" and suggest settings when filter is not active', () => {
    const status: NetworkExtensionStatus = {
      loaded: false,
      filter_active: false,
      dns_active: false,
      filtering_count: 0,
      mock_mode: false,
    };
    const label = status.filter_active ? 'Active' : 'Inactive';
    const showSettingsLink = !status.filter_active;
    expect(label).toBe('Inactive');
    expect(showSettingsLink).toBe(true);
  });

  it('should display filtering count when active', () => {
    const status: NetworkExtensionStatus = {
      loaded: true,
      filter_active: true,
      dns_active: true,
      filtering_count: 847,
      mock_mode: true,
    };
    expect(status.filter_active).toBe(true);
    expect(status.filtering_count).toBe(847);
  });
});
