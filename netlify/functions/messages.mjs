
import mysql from "mysql2/promise";
import { createHash } from "node:crypto";

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

function getSessionToken(request) {
  const cookies = request.headers.get("cookie") || "";
  const item = cookies
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("galaxy_session="));

  return item ? item.slice("galaxy_session=".length) : null;
}

async function getCurrentUser(db, request) {
  const token = getSessionToken(request);

  if (!token || !/^[0-9a-f]{64}$/.test(token)) {
    return null;
  }

  const tokenHash = createHash("sha256")
    .update(token)
    .digest("hex");

  const [rows] = await db.execute(
    `SELECT u.id, u.username, u.display_name,
            u.role, u.is_blocked
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?
       AND s.expires_at > UTC_TIMESTAMP()
     LIMIT 1`,
    [tokenHash]
  );

  return rows[0] || null;
}

export default async (request) => {
  if (!["GET", "POST"].includes(request.method)) {
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

    if (request.method === "GET") {
      const [rows] = await db.execute(
        `SELECT m.id, m.message, m.created_at,
                u.display_name, u.username
         FROM messages m
         JOIN users u ON u.id = m.user_id
         ORDER BY m.id DESC
         LIMIT 100`
      );

      return json(rows);
    }

    // POST: faqat login qilganlar
    const user = await getCurrentUser(db, request);

    if (!user) {
      return json({ error: "Avval login qiling" }, 401);
    }

    if (user.is_blocked) {
      return json({ error: "Akkauntingiz bloklangan" }, 403);
    }

    // Xabar faqat shu saytning o'zidan yuborilsin
    const origin = request.headers.get("origin");
    const expectedOrigin = new URL(request.url).origin;

    if (origin !== expectedOrigin) {
      return json({ error: "Ruxsat berilmagan so'rov" }, 403);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({ error: "JSON noto'g'ri" }, 400);
    }

    const message =
      typeof body.message === "string"
        ? body.message.trim()
        : "";

    if (
      message.length < 1 ||
      message.length > 1000
    ) {
      return json({
        error: "Xabar 1–1000 belgi bo'lishi kerak"
      }, 400);
    }

    await db.execute(
      `INSERT INTO messages (user_id, message)
       VALUES (?, ?)`,
      [user.id, message]
    );

    return json({ success: true }, 201);

  } catch (error) {
    console.error("Messages API error:", error);
    return json({ error: "Server xatosi" }, 500);
  } finally {
    if (db) await db.end();
  }
};

export const config = {
  path: "/messages"
};
