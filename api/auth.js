
import mysql from "mysql2/promise";
import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  createHash
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

const hashToken = token =>
  createHash("sha256").update(token).digest("hex");

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = await scrypt(password, salt, 64);
  return `${salt}:${hash.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const [salt, hex] = String(stored || "").split(":");
  if (!salt || !/^[0-9a-f]{128}$/.test(hex)) return false;

  const actual = Buffer.from(hex, "hex");
  const computed = await scrypt(password, salt, 64);
  return timingSafeEqual(actual, computed);
}

function getToken(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.split(";").map(x => x.trim())
    .find(x => x.startsWith("galaxy_session="));

  return match ? match.slice("galaxy_session=".length) : null;
}

function setSessionCookie(res, token, age) {
  res.setHeader(
    "Set-Cookie",
    `galaxy_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`
  );
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  const action = req.query.action;

  if (!["GET", "POST"].includes(req.method)) {
    return res.status(405).json({ error: "Method not allowed" });
  }

  let db;

  try {
    db = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      port: 4000,
      database: "test",
      ssl: { minVersion: "TLSv1.2" }
    });

    if (action === "register" && req.method === "POST") {
      const body = req.body || {};
      const username = String(body.username || "").trim().toLowerCase();
      const displayName = String(body.display_name || "").trim();
      const password = body.password;

      if (!/^[a-z0-9_]{3,30}$/.test(username) ||
          !displayName || displayName.length > 100 ||
          typeof password !== "string" ||
          password.length < 12 ||
          Buffer.byteLength(password, "utf8") > 128) {
        return res.status(400).json({
          error: "Ma'lumotlarni tekshiring"
        });
      }

      const passwordHash = await hashPassword(password);

      try {
        await db.execute(
          `INSERT INTO users
           (username, display_name, password_hash, role)
           VALUES (?, ?, ?, 'user')`,
          [username, displayName, passwordHash]
        );
      } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
          return res.status(409).json({
            error: "Bu login band"
          });
        }
        throw error;
      }

      return res.status(201).json({ success: true });
    }

    if (action === "login" && req.method === "POST") {
      const body = req.body || {};
      const username = String(body.username || "").trim().toLowerCase();
      const password = body.password;

      if (!/^[a-z0-9_]{3,30}$/.test(username) ||
          typeof password !== "string" ||
          Buffer.byteLength(password, "utf8") > 128) {
        return res.status(401).json({
          error: "Login yoki parol noto'g'ri"
        });
      }

      const [rows] = await db.execute(
        `SELECT id, username, display_name,
                password_hash, role, is_blocked
         FROM users WHERE username = ? LIMIT 1`,
        [username]
      );

      const user = rows[0];

      if (!user || user.is_blocked ||
          !(await verifyPassword(password, user.password_hash))) {
        return res.status(401).json({
          error: "Login yoki parol noto'g'ri"
        });
      }

      const token = randomBytes(32).toString("hex");

      await db.execute(
        `INSERT INTO sessions
         (user_id, token_hash, expires_at)
         VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 7 DAY))`,
        [user.id, hashToken(token)]
      );

      setSessionCookie(res, token, 604800);

      return res.status(200).json({
        success: true,
        user: {
          username: user.username,
          display_name: user.display_name,
          role: user.role
        }
      });
    }

    if (action === "me" && req.method === "GET") {
      const token = getToken(req);

      if (!token || !/^[0-9a-f]{64}$/.test(token)) {
        return res.status(401).json({
          authenticated: false
        });
      }

      const [rows] = await db.execute(
        `SELECT u.username, u.display_name,
                u.role, u.is_blocked
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?
           AND s.expires_at > UTC_TIMESTAMP()
         LIMIT 1`,
        [hashToken(token)]
      );

      const user = rows[0];

      if (!user || user.is_blocked) {
        return res.status(401).json({
          authenticated: false
        });
      }

      return res.status(200).json({
        authenticated: true,
        user: {
          username: user.username,
          display_name: user.display_name,
          role: user.role
        }
      });
    }

    if (action === "logout" && req.method === "POST") {
      const token = getToken(req);

      if (token && /^[0-9a-f]{64}$/.test(token)) {
        await db.execute(
          "DELETE FROM sessions WHERE token_hash = ?",
          [hashToken(token)]
        );
      }

      setSessionCookie(res, "", 0);

      return res.status(200).json({ success: true });
    }

    return res.status(404).json({ error: "Not found" });

  } catch (error) {
    console.error("Auth API error:", error);
    return res.status(500).json({
      error: "Server xatosi"
    });
  } finally {
    if (db) await db.end();
  }
}
