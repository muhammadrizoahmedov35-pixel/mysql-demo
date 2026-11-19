
import mysql from "mysql2/promise";
import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  createHash
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

const headers = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, ...extra }
  });

const hashToken = token =>
  createHash("sha256").update(token).digest("hex");

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = await scrypt(password, salt, 64);
  return `${salt}:${hash.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const [salt, hex] = (stored || "").split(":");
  if (!salt || !hex || !/^[0-9a-f]{128}$/.test(hex)) {
    return false;
  }

  const actual = Buffer.from(hex, "hex");
  const computed = await scrypt(password, salt, 64);
  return timingSafeEqual(actual, computed);
}

function getCookie(request, key) {
  const cookies = request.headers.get("cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith(key + "="));
  return item ? item.slice(key.length + 1) : null;
}

function sessionCookie(token, maxAge) {
  return `galaxy_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function getCurrentUser(db, request) {
  const token = getCookie(request, "galaxy_session");
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;

  const [rows] = await db.execute(
    `SELECT u.id, u.username, u.display_name,
            u.role, u.is_blocked
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?
       AND s.expires_at > UTC_TIMESTAMP()
     LIMIT 1`,
    [hashToken(token)]
  );

  return rows[0] || null;
}

export default async (request) => {
  if (request.method !== "POST" && request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405);
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

    const url = new URL(request.url);
    const action = url.searchParams.get("action");

    if (action === "register" && request.method === "POST") {
      const body = await request.json();
      const username = String(body.username || "").trim().toLowerCase();
      const displayName = String(body.display_name || "").trim();
      const password = body.password;

      if (!/^[a-z0-9_]{3,30}$/.test(username) ||
          displayName.length < 1 ||
          displayName.length > 100 ||
          typeof password !== "string" ||
          password.length < 12 ||
          Buffer.byteLength(password, "utf8") > 128) {
        return json({ error: "Ma'lumotlar noto'g'ri" }, 400);
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
          return json({ error: "Bu login band" }, 409);
        }
        throw error;
      }

      return json({ success: true }, 201);
    }

    if (action === "login" && request.method === "POST") {
      const body = await request.json();
      const username = String(body.username || "").trim().toLowerCase();
      const password = body.password;

      if (!/^[a-z0-9_]{3,30}$/.test(username) ||
          typeof password !== "string" ||
          Buffer.byteLength(password, "utf8") > 128) {
        return json({ error: "Login yoki parol noto'g'ri" }, 401);
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
        return json({ error: "Login yoki parol noto'g'ri" }, 401);
      }

      const token = randomBytes(32).toString("hex");
      const tokenHash = hashToken(token);

      await db.execute(
        `INSERT INTO sessions (user_id, token_hash, expires_at)
         VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 7 DAY))`,
        [user.id, tokenHash]
      );

      return json(
        {
          success: true,
          user: {
            username: user.username,
            display_name: user.display_name,
            role: user.role
          }
        },
        200,
        { "Set-Cookie": sessionCookie(token, 604800) }
      );
    }

    if (action === "me" && request.method === "GET") {
      const user = await getCurrentUser(db, request);

      if (!user || user.is_blocked) {
        return json({ authenticated: false }, 401);
      }

      return json({
        authenticated: true,
        user: {
          username: user.username,
          display_name: user.display_name,
          role: user.role
        }
      });
    }

    if (action === "logout" && request.method === "POST") {
      const token = getCookie(request, "galaxy_session");

      if (token && /^[0-9a-f]{64}$/.test(token)) {
        await db.execute(
          "DELETE FROM sessions WHERE token_hash = ?",
          [hashToken(token)]
        );
      }

      return json(
        { success: true },
        200,
        { "Set-Cookie": sessionCookie("", 0) }
      );
    }

    return json({ error: "Not found" }, 404);

  } catch (error) {
    console.error("Auth error:", error);
    return json({ error: "Server xatosi" }, 500);
  } finally {
    if (db) await db.end();
  }
};

export const config = {
  path: "/auth"
};
