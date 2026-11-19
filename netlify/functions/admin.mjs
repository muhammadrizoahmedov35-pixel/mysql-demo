
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

function getToken(request) {
  const cookies = request.headers.get("cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith("galaxy_session="));

  return item ? item.slice("galaxy_session=".length) : null;
}

async function currentUser(db, request) {
  const token = getToken(request);
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;

  const hash = createHash("sha256")
    .update(token).digest("hex");

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

    const user = await currentUser(db, request);

    if (!user || user.is_blocked ||
        !["admin", "superadmin"].includes(user.role)) {
      return json({ error: "Admin ruxsati kerak" }, 403);
    }

    const url = new URL(request.url);
    const action = url.searchParams.get("action");

    if (request.method === "GET") {
      if (action === "users") {
        const [rows] = await db.execute(
          `SELECT id, username, display_name,
                  role, is_blocked, created_at
           FROM users ORDER BY id DESC LIMIT 200`
        );
        return json(rows);
      }

      if (action === "messages") {
        const [rows] = await db.execute(
          `SELECT m.id, m.message, m.created_at,
                  u.username, u.display_name
           FROM messages m
           JOIN users u ON u.id = m.user_id
           ORDER BY m.id DESC LIMIT 200`
        );
        return json(rows);
      }

      return json({ error: "Not found" }, 404);
    }

    // POST so'rovlari uchun origin tekshiruvi
    const origin = request.headers.get("origin");
    if (origin !== new URL(request.url).origin) {
      return json({ error: "Ruxsat berilmagan so'rov" }, 403);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "JSON noto'g'ri" }, 400);
    }

    if (action === "delete-message") {
      const id = Number(body.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return json({ error: "ID noto'g'ri" }, 400);
      }

      await db.execute(
        "DELETE FROM messages WHERE id = ?",
        [id]
      );

      return json({ success: true });
    }

    if (action === "block-user") {
      const id = Number(body.id);
      const blocked = body.blocked;

      if (!Number.isSafeInteger(id) || id <= 0 ||
          typeof blocked !== "boolean") {
        return json({ error: "Ma'lumot noto'g'ri" }, 400);
      }

      if (id === Number(user.id)) {
        return json({ error: "O'zingizni bloklay olmaysiz" }, 403);
      }

      // Oddiy admin boshqa adminlarni boshqara olmaydi
      const [targets] = await db.execute(
        "SELECT role FROM users WHERE id = ?",
        [id]
      );

      if (!targets.length) {
        return json({ error: "Foydalanuvchi topilmadi" }, 404);
      }

      if (targets[0].role === "superadmin" ||
          (user.role !== "superadmin" &&
           targets[0].role !== "user")) {
        return json({ error: "Ruxsat yo'q" }, 403);
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

      return json({ success: true });
    }

    if (action === "set-role") {
      if (user.role !== "superadmin") {
        return json({ error: "Faqat superadmin" }, 403);
      }

      const id = Number(body.id);
      const role = body.role;

      if (!Number.isSafeInteger(id) || id <= 0 ||
          !["user", "admin"].includes(role)) {
        return json({ error: "Ma'lumot noto'g'ri" }, 400);
      }

      if (id === Number(user.id)) {
        return json({ error: "O'z rolingizni o'zgartira olmaysiz" }, 403);
      }

      const [result] = await db.execute(
        `UPDATE users SET role = ?
         WHERE id = ? AND role <> 'superadmin'`,
        [role, id]
      );

      if (!result.affectedRows) {
        return json({ error: "Foydalanuvchi topilmadi yoki himoyalangan" }, 404);
      }

      // Rol o'zgarganda eski sessiyalarni bekor qilish
      await db.execute(
        "DELETE FROM sessions WHERE user_id = ?",
        [id]
      );

      return json({ success: true });
    }

    return json({ error: "Not found" }, 404);

  } catch (error) {
    console.error("Admin API error:", error);
    return json({ error: "Server xatosi" }, 500);
  } finally {
    if (db) await db.end();
  }
};

export const config = {
  path: "/admin-api"
};
