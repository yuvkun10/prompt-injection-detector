import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import { VERSION, detect, resolveJudge } from './index';
import type { DetectionResult, LlmJudge, Thresholds } from './types';

/** Request body accepted by POST /detect. */
interface DetectBody {
  text: unknown;
  thresholds?: unknown;
}

/** Outcome of validating a thresholds field: absent, invalid, or a valid pair. */
type ThresholdParse =
  | { kind: 'absent' }
  | { kind: 'invalid' }
  | { kind: 'value'; thresholds: Thresholds };

/** Validate an unknown value as an optional {flag, block} threshold pair. */
function parseThresholds(value: unknown): ThresholdParse {
  if (value === undefined) return { kind: 'absent' };
  if (typeof value !== 'object' || value === null) return { kind: 'invalid' };
  const candidate = value as Record<string, unknown>;
  const { flag, block } = candidate;
  if (typeof flag !== 'number' || typeof block !== 'number') return { kind: 'invalid' };
  if (!Number.isFinite(flag) || !Number.isFinite(block)) return { kind: 'invalid' };
  if (flag < 0 || flag > 100 || block < 0 || block > 100) return { kind: 'invalid' };
  if (flag > block) return { kind: 'invalid' };
  return { kind: 'value', thresholds: { flag, block } };
}

/** Parse an environment value as a positive integer, or undefined if it is not one. */
function parsePort(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return undefined;
  return parsed;
}

/**
 * Build the Fastify instance with routes wired but no listener bound, so tests
 * can drive it through `inject` without occupying a port.
 */
export function createServer(options?: { judge?: LlmJudge }): FastifyInstance {
  const app = Fastify({ bodyLimit: 64 * 1024 });
  const judge = options?.judge ?? resolveJudge();

  app.get('/health', () => ({ status: 'ok', version: VERSION }));

  app.post<{ Body: DetectBody }>('/detect', async (request, reply) => {
    const body = request.body;
    const text = body?.text;
    if (typeof text !== 'string') {
      return reply.code(400).send({ error: 'Field "text" is required and must be a string.' });
    }

    const parsed = parseThresholds(body?.thresholds);
    if (parsed.kind === 'invalid') {
      return reply.code(400).send({
        error: 'Field "thresholds" must have finite flag/block in [0,100] with flag <= block.',
      });
    }

    const thresholds = parsed.kind === 'value' ? parsed.thresholds : undefined;
    const result: DetectionResult = await detect(text, { thresholds, judge });
    return reply.send(result);
  });

  return app;
}

/** Create the server and bind it to a port for standalone HTTP serving. */
export async function start(port?: number): Promise<FastifyInstance> {
  const resolvedPort = port ?? parsePort(process.env.PORT) ?? 3000;
  const app = createServer();
  await app.listen({ port: resolvedPort, host: '0.0.0.0' });
  return app;
}

// Bind a port only when this module is executed directly, not when imported.
if (process.argv[1] && import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
  start().catch((error: unknown) => {
    process.stderr.write(
      `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
    );
    process.exitCode = 1;
  });
}
