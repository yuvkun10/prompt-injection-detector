import { describe, expect, it } from 'vitest';
import { VERSION } from '../src/index';

describe('package', () => {
  it('exposes a semver version string', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
