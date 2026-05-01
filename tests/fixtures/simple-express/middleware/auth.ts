import type { Request, Response, NextFunction } from "express";

// Auth bypass: token compared with == instead of constant-time compare
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.headers["x-api-token"];
  if (token == process.env.API_TOKEN) {
    next();
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
}
