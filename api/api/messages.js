
import mysql from "mysql2/promise";
import { createHash } from "node:crypto";

function getToken(req) {
  const cookie = req.headers.cookie || "";
  const item = cookie.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("galaxy_session="));

  return item
    ? item.slice("galaxy_session=".length)
    : null;
}

async function currentUser(db, req) {
  const token = getToken(req);

  if (!token || !/^[0-9a-f]{64}$/.test(token)) {
    return null;
  }

  const hash = createHash("sha256")
    .update(token)
    .digest("hex");

  const [rows] = await db.execute(
    `SELECT u.id, u.display_name,
            u.role, u.is_blocked
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?
       AND s.expires_at > UTC_TIMESTAMP()
     LIMIT 1`,
    [hash]
  );

  return rows[0] || null;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (!["GET", "POST"].includes(req.method)) {
    return res.status(405).json({
      error: "Method not allowed"
    });
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

    if (req.method === "GET") {
      const [rows] = await db.execute(
        `SELECT m.id, m.message, m.created_at,
                u.display_name, u.username
         FROM messages m
         JOIN users u ON u.id = m.user_id
         ORDER BY m.id DESC
         LIMIT 100`
      );

      return res.status(200).json(rows);
    }

    // POST: faqat login qilgan foydalanuvchilar
    const user = await currentUser(db, req);

    if (!user) {
      return res.status(401).json({
        error: "Avval login qiling"
      });
    }

    if (user.is_blocked) {
      return res.status(403).json({
        error: "Akkauntingiz bloklangan"
      });
    }

    // Boshqa saytlardan yuborilgan so'rovlarni rad etish
    const origin = req.headers.origin;
    const expectedOrigin = `https://${req.headers.host}`;

    if (origin !== expectedOrigin) {
      return res.status(403).json({
        error: "Ruxsat berilmagan so'rov"
      });
    }

    const message =
      typeof req.body?.message === "string"
        ? req.body.message.trim()
        : "";

    if (!message || message.length > 1000) {
      return res.status(400).json({
        error: "Xabar 1–1000 belgi bo'lishi kerak"
      });
    }

    await db.execute(
      `INSERT INTO messages (user_id, message)
       VALUES (?, ?)`,
      [user.id, message]
    );

    return res.status(201).json({
      success: true
    });

  } catch (error) {
    console.error("Messages API error:", error);

    return res.status(500).json({
      error: "Server xatosi"
    });
  } finally {
    if (db) await db.end();
  }
}
