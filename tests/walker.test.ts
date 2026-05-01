import { describe, it, expect } from "vitest";
import { walkSource } from "../src/orchestrator/walker.js";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(__dirname, "fixtures/simple-express");

describe("walkSource", () => {
  it("returns source files", async () => {
    const files = await walkSource(FIXTURE);
    expect(files.length).toBeGreaterThan(0);
  });

  it("skips node_modules and dist", async () => {
    const files = await walkSource(FIXTURE);
    expect(files.every((f) => !f.relativePath.includes("node_modules"))).toBe(true);
    expect(files.every((f) => !f.relativePath.includes("dist"))).toBe(true);
  });

  it("prioritizes route files first", async () => {
    const files = await walkSource(FIXTURE);
    const routeIdx = files.findIndex((f) => f.relativePath.includes("route"));
    const middlewareIdx = files.findIndex((f) => f.relativePath.includes("middleware"));
    if (routeIdx !== -1 && middlewareIdx !== -1) {
      expect(routeIdx).toBeLessThan(middlewareIdx);
    }
  });

  it("detects TypeScript language", async () => {
    const files = await walkSource(FIXTURE);
    const tsFiles = files.filter((f) => f.relativePath.endsWith(".ts"));
    expect(tsFiles.every((f) => f.language === "typescript")).toBe(true);
  });

  it("returns non-empty file content", async () => {
    const files = await walkSource(FIXTURE);
    expect(files.every((f) => f.content.length > 0)).toBe(true);
  });
});
