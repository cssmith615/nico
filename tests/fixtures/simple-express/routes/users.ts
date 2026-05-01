import express from "express";
import { db } from "../db.js";

const router = express.Router();

// SQLi: raw query param interpolated into SQL
router.get("/users", async (req, res) => {
  const { id } = req.query;
  const result = await db.query(`SELECT * FROM users WHERE id = '${id}'`);
  res.json(result.rows);
});

// SQLi: raw POST body field in LIKE query
router.post("/users/search", async (req, res) => {
  const { name } = req.body as { name: string };
  const result = await db.query(`SELECT * FROM users WHERE name LIKE '%${name}%'`);
  res.json(result.rows);
});

// SQLi: id in path, no parameterization
router.delete("/users/:id", async (req, res) => {
  const { id } = req.params;
  await db.query(`DELETE FROM users WHERE id = ${id}`);
  res.sendStatus(204);
});

export default router;
