#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { Command } from 'commander';
import { detect, resolveJudge, DEFAULT_THRESHOLDS, VERSION } from './index';
import type { DetectionResult, DetectionSignal, Thresholds, Verdict } from './types';

/** Process exit codes chosen so the verdict composes in shell pipelines. */
const EXIT_CODE: Record<Verdict, number> = {
  allow: 0,
  flag: 1,
  block: 2,
};

interface ScanOptions {
  file?: string;
  json?: boolean;
  flagThreshold?: string;
  blockThreshold?: string;
}

/** Read every byte from stdin; resolves to '' when nothing is piped. */
function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    // A TTY with no redirection would block forever, so treat it as empty.
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

/**
 * Resolve the text to scan in priority order: positional argument, then
 * --file, then stdin. Returns null when no input source produced anything.
 */
async function resolveInput(
  positional: string | undefined,
  options: ScanOptions,
): Promise<string | null> {
  if (positional !== undefined) {
    return positional;
  }
  if (options.file !== undefined) {
    return readFile(options.file, 'utf8');
  }
  const piped = await readStdin();
  return piped.length > 0 ? piped : null;
}

/**
 * Parse a threshold flag onto a 0-100 scale. Rejects non-finite or
 * out-of-range values so a typo cannot silently disable blocking.
 */
function parseThreshold(raw: string, flag: string): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0 || value > 100) {
    throw new Error(`${flag} must be a number between 0 and 100, got '${raw}'`);
  }
  return value;
}

function buildThresholds(options: ScanOptions): Thresholds {
  const flag =
    options.flagThreshold !== undefined
      ? parseThreshold(options.flagThreshold, '--flag-threshold')
      : DEFAULT_THRESHOLDS.flag;
  const block =
    options.blockThreshold !== undefined
      ? parseThreshold(options.blockThreshold, '--block-threshold')
      : DEFAULT_THRESHOLDS.block;
  if (flag > block) {
    throw new Error(`--flag-threshold (${flag}) cannot exceed --block-threshold (${block})`);
  }
  return { flag, block };
}

function formatSignal(signal: DetectionSignal): string {
  const score = Math.round(signal.score * 100);
  const head = `  [${signal.severity}] ${signal.id} (${signal.category}) score=${score} src=${signal.source}`;
  const lines = [head, `    ${signal.message}`];
  if (signal.evidence !== undefined && signal.evidence.length > 0) {
    lines.push(`    evidence: ${signal.evidence}`);
  }
  return lines.join('\n');
}

function formatHuman(result: DetectionResult): string {
  const lines = [
    `verdict:  ${result.verdict}`,
    `score:    ${result.score}/100`,
    `severity: ${result.severity}`,
    `length:   ${result.length}`,
    `elapsed:  ${result.elapsedMs}ms`,
  ];
  if (result.decoded.length > 0) {
    const methods = result.decoded.map((layer) => layer.method).join(', ');
    lines.push(`decoded:  ${methods}`);
  }
  if (result.signals.length === 0) {
    lines.push('signals:  none');
  } else {
    lines.push(`signals:  ${result.signals.length}`);
    for (const signal of result.signals) {
      lines.push(formatSignal(signal));
    }
  }
  return lines.join('\n');
}

async function runScan(positional: string | undefined, options: ScanOptions): Promise<void> {
  const thresholds = buildThresholds(options);
  const input = await resolveInput(positional, options);
  if (input === null) {
    process.stderr.write(
      'error: no input provided (pass text, --file <path>, or pipe via stdin)\n',
    );
    process.exitCode = 64;
    return;
  }

  const judge = resolveJudge();
  const result = await detect(input, { thresholds, judge });

  const rendered = options.json ? JSON.stringify(result) : formatHuman(result);
  process.stdout.write(`${rendered}\n`);
  process.exitCode = EXIT_CODE[result.verdict];
}

const program = new Command();

program
  .name('pid')
  .description('Detect prompt-injection and jailbreak attempts in text.')
  .version(VERSION);

program
  .command('scan')
  .description('Scan text for prompt-injection signals.')
  .argument('[text]', 'text to scan; omit to read from --file or stdin')
  .option('-f, --file <path>', 'read input from a file instead of an argument')
  .option('-j, --json', 'emit machine-readable JSON instead of a human report')
  .option('--flag-threshold <n>', 'score (0-100) at or above which the verdict is flag')
  .option('--block-threshold <n>', 'score (0-100) at or above which the verdict is block')
  .action(async (text: string | undefined, options: ScanOptions) => {
    await runScan(text, options);
  });

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`error: ${message}\n`);
    process.exitCode = 64;
  }
}

void main();
