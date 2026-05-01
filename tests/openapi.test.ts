import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ingestOpenAPI } from "../src/orchestrator/openapi.js";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "Test API", version: "1.0.0" },
  paths: {
    "/api/users": {
      get: {
        parameters: [
          { name: "q", in: "query" },
          { name: "limit", in: "query" },
        ],
      },
      post: {
        requestBody: { content: { "application/json": {} } },
      },
    },
    "/api/users/{id}": {
      parameters: [{ name: "id", in: "path" }],
      get: {},
      delete: {},
    },
    "/api/webhooks": {
      post: {
        parameters: [{ name: "url", in: "query" }],
      },
    },
    "/api/posts": {
      post: {
        parameters: [
          { name: "content", in: "query" },
          { name: "description", in: "query" },
        ],
      },
    },
  },
};

let tmp: string;
let specPath: string;

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "nico-oa-"));
  specPath = join(tmp, "openapi.json");
  await writeFile(specPath, JSON.stringify(SPEC), "utf-8");
});

afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe("ingestOpenAPI — vector extraction", () => {
  it("extracts sqli vector from query parameter", async () => {
    const vectors = await ingestOpenAPI(specPath, ["sqli"]);
    expect(vectors.some((v) => v.route === "/api/users" && v.inputName === "q" && v.vulnClass === "sqli")).toBe(true);
  });

  it("extracts idor vector from path parameter named id", async () => {
    const vectors = await ingestOpenAPI(specPath, ["idor"]);
    const idor = vectors.filter((v) => v.vulnClass === "idor" && v.route === "/api/users/{id}");
    expect(idor.length).toBeGreaterThan(0);
    expect(idor[0].inputName).toBe("id");
    expect(idor[0].inputType).toBe("path");
  });

  it("extracts ssrf vector from url parameter", async () => {
    const vectors = await ingestOpenAPI(specPath, ["ssrf"]);
    const ssrf = vectors.filter((v) => v.vulnClass === "ssrf");
    expect(ssrf.length).toBeGreaterThan(0);
    expect(ssrf[0].route).toBe("/api/webhooks");
    expect(ssrf[0].inputName).toBe("url");
  });

  it("extracts xss vector from content/description params in POST", async () => {
    const vectors = await ingestOpenAPI(specPath, ["xss"]);
    const xss = vectors.filter((v) => v.vulnClass === "xss");
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some((v) => v.inputName === "content" || v.inputName === "description")).toBe(true);
  });

  it("extracts JSON requestBody schema properties as body inputs", async () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/login": {
          post: {
            requestBody: {
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      email: { type: "string" },
                      password: { type: "string" },
                    },
                  },
                },
              },
            },
          },
        },
      },
    };
    const bodySpecPath = join(tmp, "body.json");
    await writeFile(bodySpecPath, JSON.stringify(spec), "utf-8");
    const vectors = await ingestOpenAPI(bodySpecPath, ["sqli"]);
    expect(vectors.some((v) => v.route === "/login" && v.inputName === "email" && v.inputType === "body")).toBe(true);
    expect(vectors.some((v) => v.route === "/login" && v.inputName === "password" && v.inputType === "body")).toBe(true);
    expect(vectors.some((v) => v.inputName === "body")).toBe(false);
  });

  it("deduplicates path-level params when operation also declares same param", async () => {
    const spec = {
      openapi: "3.0.0",
      paths: {
        "/api/items/{id}": {
          parameters: [{ name: "id", in: "path" }],
          get: {
            parameters: [{ name: "id", in: "path" }],
          },
        },
      },
    };
    const dupPath = join(tmp, "dup.json");
    await writeFile(dupPath, JSON.stringify(spec), "utf-8");
    const vectors = await ingestOpenAPI(dupPath, ["idor"]);
    const idorForRoute = vectors.filter((v) => v.inputName === "id" && v.route === "/api/items/{id}");
    expect(idorForRoute).toHaveLength(1);
  });

  it("sorts by risk score descending", async () => {
    const vectors = await ingestOpenAPI(specPath, ["sqli", "ssrf", "idor", "xss"]);
    for (let i = 1; i < vectors.length; i++) {
      expect(vectors[i].riskScore).toBeLessThanOrEqual(vectors[i - 1].riskScore);
    }
  });

  it("respects scope — only returns vectors for requested classes", async () => {
    const vectors = await ingestOpenAPI(specPath, ["sqli"]);
    expect(vectors.every((v) => v.vulnClass === "sqli")).toBe(true);
  });

  it("assigns correct method from OpenAPI operation key", async () => {
    const vectors = await ingestOpenAPI(specPath, ["idor"]);
    const deletes = vectors.filter((v) => v.method === "DELETE");
    expect(deletes.length).toBeGreaterThan(0);
  });

  it("assigns higher risk to mutating methods", async () => {
    const vectors = await ingestOpenAPI(specPath, ["idor"]);
    const getVec = vectors.find((v) => v.method === "GET" && v.vulnClass === "idor");
    const deleteVec = vectors.find((v) => v.method === "DELETE" && v.vulnClass === "idor");
    if (getVec && deleteVec) {
      expect(deleteVec.riskScore).toBeGreaterThan(getVec.riskScore);
    }
  });
});

describe("ingestOpenAPI — error handling", () => {
  it("throws for .yaml extension", async () => {
    const yamlPath = join(tmp, "spec.yaml");
    await writeFile(yamlPath, "openapi: '3.0.0'", "utf-8");
    await expect(ingestOpenAPI(yamlPath, ["sqli"])).rejects.toThrow("YAML");
  });

  it("throws for .yml extension", async () => {
    const ymlPath = join(tmp, "spec.yml");
    await writeFile(ymlPath, "openapi: '3.0.0'", "utf-8");
    await expect(ingestOpenAPI(ymlPath, ["sqli"])).rejects.toThrow("YAML");
  });

  it("throws for invalid JSON", async () => {
    const badPath = join(tmp, "bad.json");
    await writeFile(badPath, "{ not valid json {{", "utf-8");
    await expect(ingestOpenAPI(badPath, ["sqli"])).rejects.toThrow("Failed to parse");
  });

  it("throws when spec has no paths", async () => {
    const emptyPath = join(tmp, "empty.json");
    await writeFile(emptyPath, JSON.stringify({ openapi: "3.0.0" }), "utf-8");
    await expect(ingestOpenAPI(emptyPath, ["sqli"])).rejects.toThrow("no paths");
  });

  it("returns empty array when scope has no matching vectors", async () => {
    const spec = {
      openapi: "3.0.0",
      paths: { "/health": { get: { parameters: [] } } },
    };
    const noMatchPath = join(tmp, "nomatch.json");
    await writeFile(noMatchPath, JSON.stringify(spec), "utf-8");
    const vectors = await ingestOpenAPI(noMatchPath, ["auth"]);
    expect(vectors).toHaveLength(0);
  });
});
