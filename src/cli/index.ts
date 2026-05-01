#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { VulnClass } from "../types/index.js";
import type { ScanConfig } from "../types/index.js";
import { runOrchestrator } from "../orchestrator/index.js";
import { generateExploits } from "../exploit/index.js";

const program = new Command();

program
  .name("nico")
  .description("Autonomous AI pentester for web applications and APIs")
  .version("0.1.0");

program
  .command("scan")
  .description("Run an autonomous pentest against a target application")
  .requiredOption("-t, --target <url>", "Target application URL")
  .requiredOption("-s, --source <path>", "Path to application source code")
  .option(
    "--scope <vulns>",
    "Comma-separated vuln classes (sqli,xss,auth,ssrf,idor)",
    "sqli"
  )
  .option("-o, --output <dir>", "Output directory for reports", "./reports")
  .option("--timeout <ms>", "Sandbox timeout per exploit (ms)", "30000")
  .option("--retries <n>", "Max retries on ambiguous results", "2")
  .action(async (opts) => {
    const rawScope = opts.scope.split(",").map((s: string) => s.trim());
    const scopeResults = rawScope.map((s: string) => VulnClass.safeParse(s));
    const invalid = rawScope.filter((_: string, i: number) => !scopeResults[i].success);
    if (invalid.length > 0) {
      console.error(chalk.red(`Invalid vuln class(es): ${invalid.join(", ")}`));
      console.error(`Valid: ${VulnClass.options.join(", ")}`);
      process.exit(1);
    }
    const scope = scopeResults.map((r) => (r as { success: true; data: typeof VulnClass._type }).data);

    const config: ScanConfig = {
      targetUrl: opts.target,
      sourcePath: opts.source,
      scope,
      outputDir: opts.output,
      maxRetries: parseInt(opts.retries),
      timeoutMs: parseInt(opts.timeout),
    };

    console.log(chalk.bold.cyan("\n  Nico — Autonomous AI Pentester\n"));
    console.log(`  Target : ${config.targetUrl}`);
    console.log(`  Source : ${config.sourcePath}`);
    console.log(`  Scope  : ${config.scope.join(", ")}\n`);

    const spinner = ora("Analyzing attack surface...").start();
    let vectors;
    try {
      vectors = await runOrchestrator(config);
      spinner.succeed(`Found ${vectors.length} attack vector${vectors.length !== 1 ? "s" : ""}`);
    } catch (err) {
      spinner.fail("Orchestrator failed");
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }

    console.log();
    for (const v of vectors) {
      const risk = v.riskScore >= 8 ? chalk.red : v.riskScore >= 5 ? chalk.yellow : chalk.gray;
      console.log(
        risk(`  [${v.vulnClass.toUpperCase()}] ${v.method} ${v.route}`) +
        chalk.dim(` — ${v.inputName} (${v.inputType}) — risk ${v.riskScore}`)
      );
      if (v.notes) console.log(chalk.dim(`         ${v.notes}`));
    }

    const spinner2 = ora(`Generating exploits for ${vectors.length} vector${vectors.length !== 1 ? "s" : ""}...`).start();
    let scripts;
    try {
      scripts = await generateExploits(vectors, config.targetUrl);
      spinner2.succeed(`Generated ${scripts.length} exploit script${scripts.length !== 1 ? "s" : ""}`);
    } catch (err) {
      spinner2.fail("Exploit generation failed");
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }

    console.log();
    for (const s of scripts) {
      const vector = vectors.find((v) => v.id === s.vectorId);
      console.log(
        chalk.dim(`  [${s.type}]`) + ` ${vector?.route ?? s.vectorId}` +
        (s.payload ? chalk.dim(` — payload: ${s.payload.slice(0, 40)}`) : "")
      );
    }

    console.log(chalk.dim("\n  Execution sandbox: Sprint 3\n"));
  });

program.parse();
