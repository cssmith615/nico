#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { VulnClass } from "../types/index.js";

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
    "Comma-separated vuln classes to test (sqli,xss,auth,ssrf,idor)",
    "sqli"
  )
  .option("-o, --output <dir>", "Output directory for reports", "./reports")
  .option("--timeout <ms>", "Sandbox timeout per exploit (ms)", "30000")
  .option("--retries <n>", "Max retries on ambiguous results", "2")
  .action(async (opts) => {
    const scope = opts.scope.split(",").map((s: string) => s.trim());
    const parsed = scope.map((s: string) => VulnClass.safeParse(s));
    const invalid = parsed.filter((r) => !r.success);
    if (invalid.length > 0) {
      console.error(chalk.red(`Invalid vuln class(es): ${scope.filter((_: string, i: number) => !parsed[i].success).join(", ")}`));
      console.error(`Valid: ${VulnClass.options.join(", ")}`);
      process.exit(1);
    }

    console.log(chalk.bold.cyan("\n  Nico — Autonomous AI Pentester\n"));
    console.log(`  Target : ${opts.target}`);
    console.log(`  Source : ${opts.source}`);
    console.log(`  Scope  : ${scope.join(", ")}`);
    console.log(`  Output : ${opts.output}\n`);

    // TODO Sprint 1: wire orchestrator
    console.log(chalk.yellow("  Orchestrator not yet implemented. Sprint 1."));
  });

program.parse();
