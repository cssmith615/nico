#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { VulnClass } from "../types/index.js";
import type { ScanConfig } from "../types/index.js";
import { runOrchestrator } from "../orchestrator/index.js";
import { generateExploits } from "../exploit/index.js";
import { ensureSandbox, runExploits } from "../execution/index.js";
import { validateResults, confirmedOnly } from "../validation/index.js";

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

    const spinner3 = ora("Preparing sandbox...").start();
    try {
      await ensureSandbox();
      spinner3.succeed("Sandbox ready");
    } catch (err) {
      spinner3.fail("Sandbox build failed — is Docker running?");
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }

    const spinner4 = ora(`Running ${scripts.length} exploit${scripts.length !== 1 ? "s" : ""} in sandbox...`).start();
    let results;
    try {
      results = await runExploits(scripts, config.timeoutMs, config.maxRetries);
      const confirmed = results.filter((r) => r.confirmed).length;
      spinner4.succeed(`Sandbox complete — ${confirmed} confirmed, ${results.length - confirmed} unconfirmed`);
    } catch (err) {
      spinner4.fail("Sandbox execution failed");
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }

    console.log();
    for (const r of results) {
      const vector = vectors.find((v) => v.id === r.vectorId);
      if (r.confirmed) {
        console.log(chalk.red.bold(`  ✗ CONFIRMED`) + chalk.dim(` ${vector?.route ?? r.vectorId}`));
        if (r.evidence.responseBody) {
          console.log(chalk.dim(`    ${r.evidence.responseBody.slice(0, 120)}`));
        }
      } else {
        console.log(chalk.green(`  ✓ not exploitable`) + chalk.dim(` ${vector?.route ?? r.vectorId}`));
      }
    }

    const spinner5 = ora("Validating results...").start();
    let findings;
    try {
      findings = await validateResults(results, vectors, scripts);
      const confirmed = confirmedOnly(findings);
      spinner5.succeed(
        `Validation complete — ${confirmed.length} confirmed finding${confirmed.length !== 1 ? "s" : ""} of ${findings.length} total`
      );
    } catch (err) {
      spinner5.fail("Validation failed");
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }

    console.log();
    for (const f of findings) {
      if (f.verdict === "confirmed") {
        console.log(chalk.red.bold(`  [CONFIRMED]  `) + `${f.vector.method} ${f.vector.route}`);
        console.log(chalk.dim(`               ${f.reasoning}`));
      } else if (f.verdict === "inconclusive") {
        console.log(chalk.yellow(`  [INCONCLUSIVE] `) + `${f.vector.method} ${f.vector.route}`);
        console.log(chalk.dim(`               ${f.reasoning}`));
      } else {
        console.log(chalk.green(`  [CLEAN]      `) + chalk.dim(`${f.vector.method} ${f.vector.route}`));
      }
    }

    console.log(chalk.dim("\n  Reporter: Sprint 5\n"));
  });

program.parse();
