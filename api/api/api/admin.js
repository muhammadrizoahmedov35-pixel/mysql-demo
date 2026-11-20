
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
    `SELECT u.id, u.username, u.role, u.is_blocked
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

    const user = await currentUser(db, req);

    if (!user || user.is_blocked ||
        !["admin", "superadmin"].includes(user.role)) {
      return res.status(403).json({
        error: "Admin ruxsati kerak"
      });
    }

    const action = req.query.action;

    if (req.method === "GET") {
      if (action === "users") {
        const [rows] = await db.execute(
          `SELECT id, username, display_name,
                  role, is_blocked, created_at
           FROM users
           ORDER BY id DESC LIMIT 200`
        );
        return res.status(200).json(rows);
      }

      if (action === "messages") {
        const [rows] = await db.execute(
          `SELECT m.id, m.message, m.created_at,
                  u.username, u.display_name
           FROM messages m
           JOIN users u ON u.id = m.user_id
           ORDER BY m.id DESC LIMIT 200`
        );
        return res.status(200).json(rows);
      }

      return res.status(404).json({
        error: "Not found"
      });
    }

    // POST: boshqa saytlardan so'rovlarni rad etish
    const origin = req.headers.origin;
    const expectedOrigin = `https://${req.headers.host}`;

    if (origin !== expectedOrigin) {
      return res.status(403).json({
        error: "Ruxsat berilmagan so'rov"
      });
    }

    const body = req.body || {};

    if (action === "delete-message") {
      const id = Number(body.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "ID noto'g'ri"
        });
      }

      await db.execute(
        "DELETE FROM messages WHERE id = ?",
        [id]
      );

      return res.status(200).json({
        success: true
      });
    }

    if (action === "block-user") {
      const id = Number(body.id);
      const blocked = body.blocked;

      if (!Number.isSafeInteger(id) || id <= 0 ||
          typeof blocked !== "boolean") {
        return res.status(400).json({
          error: "Ma'lumot noto'g'ri"
        });
      }

      if (id === Number(user.id)) {
        return res.status(403).json({
          error: "O'zingizni bloklay olmaysiz"
        });
      }

      const [targets] = await db.execute(
        "SELECT role FROM users WHERE id = ?",
        [id]
      );

      if (!targets.length) {
        return res.status(404).json({
          error: "Foydalanuvchi topilmadi"
        });
      }

      if (targets[0].role === "superadmin" ||
          (user.role !== "superadmin" &&
           targets[0].role !== "user")) {
        return res.status(403).json({
          error: "Ruxsat yo'q"
        });
      }

      await db.execute(
        "UPDATE users SET is_blocked = ? WHERE id = ?",
        [blocked, id]
      );

      if (blocked) {
        await db.execute(
          "DELETE FROM sessions WHERE user_id = ?",
          [id]
        );
      }

      return res.status(200).json({
        success: true
      });
    }

    if (action === "set-role") {
      if (user.role !== "superadmin") {
        return res.status(403).json({
          error: "Faqat superadmin"
        });
      }

      const id = Number(body.id);
      const role = body.role;

      if (!Number.isSafeInteger(id) || id <= 0 ||
          !["user", "admin"].includes(role)) {
        return res.status(400).json({
          error: "Ma'lumot noto'g'ri"
        });
      }

      if (id === Number(user.id)) {
        return res.status(403).json({
          error: "O'z rolingizni o'zgartira olmaysiz"
        });
      }

      const [result] = await db.execute(
        `UPDATE users SET role = ?
         WHERE id = ? AND role <> 'superadmin'`,
        [role, id]
      );

      if (!result.affectedRows) {
        return res.status(404).json({
          error: "Foydalanuvchi topilmadi yoki himoyalangan"
        });
      }

      await db.execute(
        "DELETE FROM sessions WHERE user_id = ?",
        [id]
      );

      return res.status(200).json({
        success: true
      });
    }

    return res.status(404).json({
      error: "Not found"
    });

  } catch (error) {
    console.error("Admin API error:", error);

    return res.status(500).json({
      error: "Server xatosi"
    });
  } finally {
    if (db) await db.end();
  }
}
