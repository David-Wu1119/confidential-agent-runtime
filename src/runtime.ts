import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { openSecret } from "./seal.js";
import type { RunEvidence, RuntimePolicy, SealedSecret } from "./types.js";

export function defaultPolicy(): RuntimePolicy {
  return {
    version: "0.1",
    name: "local-private-agent",
    allow_env: ["PATH", "HOME", "TMPDIR"],
    deny_env: [
      "OPENAI_API_KEY",
      "ANTHROPIC_API_KEY",
      "GITHUB_TOKEN",
      "AWS_SECRET_ACCESS_KEY",
    ],
    network: "deny_not_enforced",
    redact_stdout_patterns: [],
  };
}

export async function runWithPolicy(input: {
  command: string[];
  policy: RuntimePolicy;
  secrets?: SealedSecret[];
  passphrase?: string;
  cwd?: string;
}): Promise<{ evidence: RunEvidence; stdout: string; stderr: string }> {
  if (!input.command.length) throw new Error("command is required.");
  validatePolicy(input.policy);
  const env: NodeJS.ProcessEnv = {};
  for (const name of input.policy.allow_env) {
    if (input.policy.deny_env.includes(name)) continue;
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }

  const injected: string[] = [];
  if (input.secrets?.length) {
    if (!input.passphrase)
      throw new Error("passphrase is required to inject sealed secrets.");
    for (const secret of input.secrets) {
      if (input.policy.deny_env.includes(secret.name))
        throw new Error(`policy denies secret env ${secret.name}`);
      env[secret.name] = await openSecret(secret, input.passphrase);
      injected.push(secret.name);
    }
  }

  const startedAt = new Date().toISOString();
  const result = await runCommand(
    input.command,
    env,
    input.cwd ?? process.cwd(),
  );
  const finishedAt = new Date().toISOString();
  const stdout = redact(
    result.stdout,
    input.policy.redact_stdout_patterns,
    injected.map((name) => env[name]).filter(Boolean) as string[],
  );
  const stderr = redact(
    result.stderr,
    input.policy.redact_stdout_patterns,
    injected.map((name) => env[name]).filter(Boolean) as string[],
  );
  const evidence: RunEvidence = {
    version: "0.1",
    run_id: `run_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    command: input.command,
    policy_name: input.policy.name,
    started_at: startedAt,
    finished_at: finishedAt,
    exit_code: result.exitCode,
    signal: result.signal,
    injected_secret_names: injected,
    allowed_env_names: Object.keys(env).sort(),
    stdout_sha256: sha256(stdout),
    stderr_sha256: sha256(stderr),
  };
  return { evidence, stdout, stderr };
}

export async function readJson<T>(file: string): Promise<T> {
  return JSON.parse(await fs.readFile(file, "utf8")) as T;
}

export async function writeJson(file: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function validatePolicy(policy: RuntimePolicy): void {
  if (policy.version !== "0.1") throw new Error("policy.version must be 0.1.");
  if (!policy.name.trim()) throw new Error("policy.name is required.");
  if (!Array.isArray(policy.allow_env) || !Array.isArray(policy.deny_env))
    throw new Error("policy allow_env and deny_env must be arrays.");
}

function runCommand(
  command: string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
): Promise<{
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(command[0] ?? "", command.slice(1), {
      cwd,
      env,
      shell: false,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) =>
      reject(
        new Error(
          `Failed to run command ${command.join(" ")}: ${error.message}`,
        ),
      ),
    );
    child.on("close", (exitCode, signal) => {
      resolve({
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        exitCode,
        signal,
      });
    });
  });
}

function redact(value: string, patterns: string[], secrets: string[]): string {
  let output = value;
  for (const secret of secrets)
    output = output.split(secret).join("[REDACTED_SECRET]");
  for (const pattern of patterns)
    output = output.replace(new RegExp(pattern, "g"), "[REDACTED]");
  return output;
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}
