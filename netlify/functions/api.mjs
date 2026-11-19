
import mysql from "mysql2/promise";

export default async (request) => {
  const headers = {
    "Content-Type": "application/json"
  };

if (request.method !== "GET" && request.method !== "POST") {
  return new Response(
    JSON.stringify({ error: "Method not allowed" }),
    { status: 405, headers }
  );
}

  let db;

  try {
    db = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: 4000,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: "test",
      ssl: { minVersion: "TLSv1.2" }
    });

if (request.method === "POST") {
  const body = await request.json();
  const name = body.name?.trim();

  if (!name || name.length > 100) {
    return new Response(
      JSON.stringify({ error: "Ism noto'g'ri" }),
      { status: 400, headers }
    );
  }

  await db.execute(
    "INSERT INTO notes (name) VALUES (?)",
    [name]
  );

  return new Response(
    JSON.stringify({ success: true }),
    { status: 201, headers }
  );
}

    const [rows] = await db.execute(
      "SELECT id, name, created_at FROM notes ORDER BY id DESC LIMIT 100"
    );

    return new Response(
      JSON.stringify(rows),
      { status: 200, headers }
    );
  } catch (error) {
    console.error("Database error:", error.message);

    return new Response(
      JSON.stringify({ error: "Database error" }),
      { status: 500, headers }
    );
  } finally {
    if (db) await db.end();
  }
};

export const config = {
  path: "/api"
};
