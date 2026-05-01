import { readdir, readFile, stat } from "fs/promises";
import { join, extname, relative } from "path";

const SKIP_DIRS = new Set([
  "node_modules", "dist", ".git", ".next", "build",
  "coverage", "__pycache__", ".venv", "vendor", ".cache",
]);

const CODE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx",
  ".py", ".go", ".rs", ".rb", ".php",
  ".java", ".cs", ".swift",
]);

const MAX_FILE_SIZE = 100 * 1024;  // 100KB per file
const MAX_TOTAL_SIZE = 500 * 1024; // 500KB total context

const LANGUAGE_MAP: Record<string, string> = {
  ".ts": "typescript", ".tsx": "typescript",
  ".js": "javascript", ".jsx": "javascript",
  ".py": "python", ".go": "go", ".rs": "rust",
  ".rb": "ruby", ".php": "php", ".java": "java",
  ".cs": "csharp", ".swift": "swift",
};

export interface SourceFile {
  relativePath: string;
  content: string;
  language: string;
}

function routePriority(relativePath: string): number {
  const p = relativePath.toLowerCase();
  if (p.includes("route") || p.includes("router")) return 0;
  if (p.includes("controller") || p.includes("handler")) return 1;
  if (p.includes("middleware") || p.includes("auth")) return 2;
  if (p.includes("model") || p.includes("schema")) return 3;
  return 4;
}

export async function walkSource(sourcePath: string): Promise<SourceFile[]> {
  const files: SourceFile[] = [];
  let totalSize = 0;

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name);
        if (!CODE_EXTENSIONS.has(ext)) continue;
        const stats = await stat(fullPath);
        if (stats.size > MAX_FILE_SIZE || totalSize + stats.size > MAX_TOTAL_SIZE) continue;
        const content = await readFile(fullPath, "utf-8");
        totalSize += stats.size;
        files.push({
          relativePath: relative(sourcePath, fullPath),
          content,
          language: LANGUAGE_MAP[ext] ?? "text",
        });
      }
    }
  }

  await walk(sourcePath);
  files.sort((a, b) => routePriority(a.relativePath) - routePriority(b.relativePath));
  return files;
}
