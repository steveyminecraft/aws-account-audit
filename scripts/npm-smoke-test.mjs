import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

async function run() {
  const tempDir = await mkdtemp(join(tmpdir(), "aws-account-audit-mmdc-"));
  try {
    const mermaidInput = join(tempDir, "graph.mmd");
    const pngOutput = join(tempDir, "graph.png");
    const puppeteerConfig = "aws_network_map/puppeteer-config.json";

    const diagram = `flowchart LR
    A["Smoke"] --> B["Test"]
`;
    await writeFile(mermaidInput, diagram, "utf8");

    await execFileAsync(
      "npx",
      [
        "-y",
        "@mermaid-js/mermaid-cli",
        "-i",
        mermaidInput,
        "-o",
        pngOutput,
        "-b",
        "white",
        "-p",
        puppeteerConfig,
      ],
      { cwd: process.cwd() },
    );

    const outputStats = await stat(pngOutput);
    if (!outputStats.isFile() || outputStats.size === 0) {
      throw new Error("mmdc smoke test failed: output PNG missing or empty.");
    }

    console.log(`mmdc smoke test passed: ${pngOutput} (${outputStats.size} bytes)`);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
