import { describe, expect, it } from "vitest";
import {
  defaultPolicy,
  openSecret,
  runWithPolicy,
  sealSecret,
} from "../src/index.js";

describe("Confidential Agent Runtime", () => {
  it("seals, opens, injects, and redacts a secret", async () => {
    const passphrase = "correct horse battery staple";
    const sealed = await sealSecret("DEMO_TOKEN", "super-secret", passphrase);
    await expect(openSecret(sealed, passphrase)).resolves.toBe("super-secret");

    const policy = defaultPolicy();
    policy.allow_env.push("DEMO_TOKEN");
    const result = await runWithPolicy({
      command: [process.execPath, "-e", "console.log(process.env.DEMO_TOKEN)"],
      policy,
      secrets: [sealed],
      passphrase,
    });

    expect(result.stdout).toContain("[REDACTED_SECRET]");
    expect(result.stdout).not.toContain("super-secret");
    expect(result.evidence.injected_secret_names).toEqual(["DEMO_TOKEN"]);
    expect(result.evidence.allowed_env_names).toContain("DEMO_TOKEN");
  });

  it("blocks denied secret injection", async () => {
    const passphrase = "correct horse battery staple";
    const sealed = await sealSecret("OPENAI_API_KEY", "secret", passphrase);
    await expect(
      runWithPolicy({
        command: [process.execPath, "-e", "console.log('x')"],
        policy: defaultPolicy(),
        secrets: [sealed],
        passphrase,
      }),
    ).rejects.toThrow("policy denies secret env OPENAI_API_KEY");
  });
});
