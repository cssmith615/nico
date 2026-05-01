#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { VulnClass } from "../types/index.js";

function loadDotenv(path: string): void {
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch {
    return;
  }
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

loadDotenv(resolve(process.cwd(), ".env"));
import type { ScanConfig } from "../types/index.js";
import { runOrchestrator } from "../orchestrator/index.js";
import { generateExploitsWithFailures } from "../exploit/index.js";
import { ensureSandbox, runExploits } from "../execution/index.js";
import { validateResults, confirmedOnly, type ValidatedFinding } from "../validation/index.js";
import { generateReport } from "../reporter/index.js";
import { preflight } from "./preflight.js";

const program = new Command();
type ParsedVulnClass = typeof VulnClass._type;

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
    const scope: ParsedVulnClass[] = [];
    const invalid: string[] = [];
    for (const entry of rawScope) {
      const result = VulnClass.safeParse(entry);
      if (result.success) {
        scope.push(result.data);
      } else {
        invalid.push(entry);
      }
    }
    if (invalid.length > 0) {
      console.error(chalk.red(`Invalid vuln class(es): ${invalid.join(", ")}`));
      console.error(`Valid: ${VulnClass.options.join(", ")}`);
      process.exit(1);
    }

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

    const preflightSpinner = ora("Running pre-flight checks...").start();
    const pre = await preflight(config);
    if (!pre.ok) {
      preflightSpinner.fail("Pre-flight failed");
      for (const err of pre.errors) console.error(chalk.red(`  • ${err}`));
      process.exit(1);
    }
    preflightSpinner.succeed("Pre-flight checks passed");
    for (const warn of pre.warnings) console.log(chalk.yellow(`  ! ${warn}`));

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
    let generationFailures;
    try {
      const generated = await generateExploitsWithFailures(vectors, config.targetUrl);
      scripts = generated.scripts;
      generationFailures = generated.failures;
      spinner2.succeed(
        `Generated ${scripts.length} exploit script${scripts.length !== 1 ? "s" : ""}` +
        (generationFailures.length > 0 ? `, ${generationFailures.length} failed` : "")
      );
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
      const generationFindings: ValidatedFinding[] = generationFailures.map((failure) => ({
        verdict: "inconclusive",
        reasoning: `Exploit generation failed: ${failure.error}`,
        vector: failure.vector,
        script: {
          vectorId: failure.vector.id,
          type: failure.vector.vulnClass === "xss" || failure.vector.vulnClass === "auth" ? "playwright" : "curl",
          script: "",
          payload: "",
        },
        result: {
          vectorId: failure.vector.id,
          confirmed: false,
          evidence: { errorMessage: failure.error },
          retryCount: 0,
        },
      }));
      findings.push(...generationFindings);
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

    const spinner6 = ora("Writing report...").start();
    try {
      const report = await generateReport(findings, config);
      spinner6.succeed(
        `Report written — ${report.confirmedCount} confirmed, ${report.inconclusiveCount} inconclusive`
      );
      console.log();
      console.log(chalk.bold("  Markdown:") + ` ${report.markdownPath}`);
      console.log(chalk.bold("  JSON:    ") + ` ${report.jsonPath}`);
      console.log();
    } catch (err) {
      spinner6.fail("Report generation failed");
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }
  });

program.parse();
