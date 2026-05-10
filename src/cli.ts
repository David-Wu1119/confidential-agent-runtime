#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import {
  defaultPolicy,
  readJson,
  runWithPolicy,
  sealSecret,
  writeJson,
  type RuntimePolicy,
  type SealedSecret,
} from "./index.js";

type SealOptions = {
  name: string;
  value?: string;
  valueFile?: string;
  passphraseEnv: string;
  out: string;
};

type RunOptions = {
  policy: string;
  secret: string[];
  passphraseEnv?: string;
  evidence: string;
};

async function main(): Promise<void> {
  const program = new Command()
    .name("confagent")
    .description("Local confidential-agent runtime prototype.")
    .version("0.1.0");

  program
    .command("init")
    .description("Write a default local runtime policy.")
    .argument("[path]", "Policy path.", ".confagent/policy.json")
    .action(async (target: string) => {
      await writeJson(target, defaultPolicy());
      console.log(pc.green("Wrote policy"));
      console.log(target);
    });

  program
    .command("seal")
    .description(
      "Seal a secret with AES-256-GCM using a passphrase from an environment variable.",
    )
    .requiredOption("--name <name>", "Secret/env name.")
    .option("--value <value>", "Secret value.")
    .option("--value-file <path>", "Read secret value from file.")
    .option(
      "--passphrase-env <name>",
      "Environment variable containing passphrase.",
      "CONFAGENT_PASSPHRASE",
    )
    .requiredOption("--out <path>", "Output sealed secret JSON.")
    .action(async (options: SealOptions) => {
      const passphrase = process.env[options.passphraseEnv];
      if (!passphrase)
        throw new Error(`missing passphrase env ${options.passphraseEnv}`);
      const value = options.valueFile
        ? await fs.readFile(options.valueFile, "utf8")
        : options.value;
      if (!value) throw new Error("--value or --value-file is required.");
      await writeJson(
        options.out,
        await sealSecret(options.name, value, passphrase),
      );
      console.log(pc.green("Sealed secret"));
      console.log(options.out);
    });

  program
    .command("run [command...]")
    .description(
      "Run a command with policy-filtered environment and optional sealed secrets.",
    )
    .allowUnknownOption(true)
    .requiredOption("--policy <path>", "Runtime policy JSON.")
    .option(
      "--secret <name=path>",
      "Inject sealed secret. Repeatable.",
      collect,
      [],
    )
    .option(
      "--passphrase-env <name>",
      "Environment variable containing passphrase.",
    )
    .option(
      "--evidence <path>",
      "Evidence output path.",
      ".confagent/evidence/run.json",
    )
    .action(async (command: string[], options: RunOptions) => {
      const policy = await readJson<RuntimePolicy>(options.policy);
      const passphrase = options.passphraseEnv
        ? process.env[options.passphraseEnv]
        : undefined;
      const secrets = await Promise.all(options.secret.map(loadSecretMapping));
      const result = await runWithPolicy({
        command,
        policy,
        secrets,
        passphrase,
      });
      await writeJson(options.evidence, result.evidence);
      process.stdout.write(result.stdout);
      process.stderr.write(result.stderr);
      console.error(pc.green(`Evidence: ${options.evidence}`));
      if (result.evidence.exit_code && result.evidence.exit_code !== 0)
        process.exitCode = result.evidence.exit_code;
    });

  await program.parseAsync(process.argv);
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

async function loadSecretMapping(mapping: string): Promise<SealedSecret> {
  const [name, file] = mapping.split("=");
  if (!name || !file) throw new Error("--secret must use name=path.");
  const secret = await readJson<SealedSecret>(file);
  if (secret.name !== name)
    throw new Error(
      `secret mapping name ${name} does not match sealed secret ${secret.name}`,
    );
  return secret;
}

main().catch((error: unknown) => {
  console.error(pc.red(error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
});
