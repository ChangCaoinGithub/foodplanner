const SESSION_COOKIE = "kitchen_session";
const SESSION_SECONDS = 60 * 60 * 24 * 180;
const LOGIN_WINDOW_SECONDS = 15 * 60;
const LOGIN_MAX_ATTEMPTS = 12;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function parseCookies(request) {
  const raw = request.headers.get("Cookie") || "";
  const out = {};
  raw.split(";").forEach(part => {
    const i = part.indexOf("=");
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function requireSession(context) {
  const token = parseCookies(context.request)[SESSION_COOKIE];
  if (!token) return null;
  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);
  const row = await context.env.DB
    .prepare("SELECT id FROM sessions WHERE token_hash = ? AND expires_at > ? LIMIT 1")
    .bind(tokenHash, now)
    .first();
  return row ? { tokenHash } : null;
}

function cookieHeader(token) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookieHeader() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

async function bodyJson(request) {
  try { return await request.json(); } catch { return {}; }
}

function validUnit(v) { return ["kg","ml","portion","pieces"].includes(v); }
function validStorage(v) { return ["Fridge","Freezer","Outside"].includes(v); }
function validMealType(v) { return ["Lunch","Dinner"].includes(v); }

async function handleLogin(context) {
  if (context.request.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const body = await bodyJson(context.request);
  const email = String(body.email || "").trim().toLowerCase();
  if (!email || email.length > 254) return json({ allowed: false }, 403);

  const ip = context.request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await sha256(ip);
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - LOGIN_WINDOW_SECONDS;

  await context.env.DB.prepare("DELETE FROM login_attempts WHERE window_start < ?").bind(windowStart).run();
  const attempt = await context.env.DB.prepare("SELECT count, window_start FROM login_attempts WHERE ip_hash = ? LIMIT 1").bind(ipHash).first();

  if (attempt && attempt.window_start >= windowStart && attempt.count >= LOGIN_MAX_ATTEMPTS) {
    return json({ error: "Too many attempts" }, 429);
  }
  if (attempt && attempt.window_start >= windowStart) {
    await context.env.DB.prepare("UPDATE login_attempts SET count = count + 1 WHERE ip_hash = ?").bind(ipHash).run();
  } else {
    await context.env.DB.prepare("INSERT OR REPLACE INTO login_attempts (ip_hash, count, window_start) VALUES (?, 1, ?)").bind(ipHash, now).run();
  }

  const allowed = await context.env.DB.prepare("SELECT 1 AS ok FROM allowed_users WHERE email = ? LIMIT 1").bind(email).first();
  if (!allowed) return json({ allowed: false }, 403);

  await context.env.DB.prepare("DELETE FROM login_attempts WHERE ip_hash = ?").bind(ipHash).run();

  const token = crypto.randomUUID() + crypto.randomUUID();
  const tokenHash = await sha256(token);
  const expiresAt = now + SESSION_SECONDS;
  await context.env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now).run();
  await context.env.DB.prepare("INSERT INTO sessions (id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)").bind(crypto.randomUUID(), tokenHash, expiresAt, now).run();

  return json({ allowed: true }, 200, { "Set-Cookie": cookieHeader(token), "Cache-Control": "no-store" });
}

async function handleSession(context) {
  if (context.request.method !== "GET") return json({ error: "Method not allowed" }, 405);
  const session = await requireSession(context);
  return session ? json({ authenticated: true }, 200, { "Cache-Control": "no-store" })
                 : json({ authenticated: false }, 401, { "Cache-Control": "no-store" });
}

async function handleLogout(context) {
  if (context.request.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const token = parseCookies(context.request)[SESSION_COOKIE];
  if (token) {
    const tokenHash = await sha256(token);
    await context.env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
  return json({ ok: true }, 200, { "Set-Cookie": clearCookieHeader(), "Cache-Control": "no-store" });
}

async function handleIngredients(context) {
  const session = await requireSession(context);
  if (!session) return json({ error: "Unauthorized" }, 401);
  const url = new URL(context.request.url);

  if (context.request.method === "GET") {
    const { results } = await context.env.DB.prepare("SELECT id, name, quantity, unit, storage, created_at FROM ingredients ORDER BY created_at ASC").all();
    return json({ ingredients: results || [] });
  }

  if (context.request.method === "POST") {
    const b = await bodyJson(context.request);
    const name = String(b.name || "").trim();
    const quantity = Number(b.quantity);
    if (!name || name.length > 120 || !(quantity > 0) || !validUnit(b.unit) || !validStorage(b.storage)) return json({ error: "Invalid ingredient" }, 400);
    const id = crypto.randomUUID(), now = Date.now();
    await context.env.DB.prepare("INSERT INTO ingredients (id,name,quantity,unit,storage,created_at) VALUES (?,?,?,?,?,?)").bind(id,name,quantity,b.unit,b.storage,now).run();
    return json({ ok: true, id }, 201);
  }

  const id = url.searchParams.get("id");
  if (!id) return json({ error: "Missing id" }, 400);

  if (context.request.method === "DELETE") {
    await context.env.DB.prepare("DELETE FROM ingredients WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  if (context.request.method === "PATCH") {
    const b = await bodyJson(context.request);
    const sets=[], vals=[];
    if ("quantity" in b) {
      const q=Number(b.quantity); if (!(q > 0)) return json({ error: "Invalid quantity" }, 400);
      sets.push("quantity = ?"); vals.push(q);
    }
    if ("unit" in b) { if(!validUnit(b.unit)) return json({ error:"Invalid unit" },400); sets.push("unit = ?"); vals.push(b.unit); }
    if ("storage" in b) { if(!validStorage(b.storage)) return json({ error:"Invalid storage" },400); sets.push("storage = ?"); vals.push(b.storage); }
    if (!sets.length) return json({ error:"Nothing to update" },400);
    vals.push(id);
    await context.env.DB.prepare(`UPDATE ingredients SET ${sets.join(", ")} WHERE id = ?`).bind(...vals).run();
    return json({ ok: true });
  }

  return json({ error: "Method not allowed" }, 405);
}

async function handleMeals(context) {
  const session = await requireSession(context);
  if (!session) return json({ error: "Unauthorized" }, 401);
  const url = new URL(context.request.url);

  if (context.request.method === "GET") {
    const { results } = await context.env.DB.prepare("SELECT id,name,meal_type,meal_date,notes,items,status,created_at FROM meals ORDER BY meal_date ASC, created_at ASC").all();
    const meals = (results || []).map(m => ({ ...m, items: (()=>{try{return JSON.parse(m.items||"[]")}catch{return []}})() }));
    return json({ meals });
  }

  if (context.request.method === "POST") {
    const b=await bodyJson(context.request);
    const name=String(b.name||"").trim(), date=String(b.meal_date||"");
    if(!name||name.length>160||!validMealType(b.meal_type)||!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({error:"Invalid meal"},400);
    const id=crypto.randomUUID(), now=Date.now(), notes=String(b.notes||"").slice(0,2000);
    const items=Array.isArray(b.items)?b.items.slice(0,100):[];
    await context.env.DB.prepare("INSERT INTO meals (id,name,meal_type,meal_date,notes,items,status,created_at) VALUES (?,?,?,?,?,?,?,?)")
      .bind(id,name,b.meal_type,date,notes,JSON.stringify(items),"planned",now).run();
    return json({ok:true,id},201);
  }

  const id=url.searchParams.get("id");
  if(!id)return json({error:"Missing id"},400);

  if(context.request.method==="DELETE"){
    await context.env.DB.prepare("DELETE FROM meals WHERE id = ?").bind(id).run();
    return json({ok:true});
  }

  if(context.request.method==="PATCH" && url.searchParams.get("action")==="cook"){
    const meal=await context.env.DB.prepare("SELECT items FROM meals WHERE id = ? LIMIT 1").bind(id).first();
    if(!meal)return json({error:"Meal not found"},404);
    let items=[];try{items=JSON.parse(meal.items||"[]")}catch{}
    for(const item of items){
      if(!item?.ingredientId)continue;
      const ing=await context.env.DB.prepare("SELECT quantity FROM ingredients WHERE id = ? LIMIT 1").bind(item.ingredientId).first();
      if(!ing)continue;
      const next=Math.max(0,Number(ing.quantity)-Number(item.qty||0));
      if(next<=0)await context.env.DB.prepare("DELETE FROM ingredients WHERE id = ?").bind(item.ingredientId).run();
      else await context.env.DB.prepare("UPDATE ingredients SET quantity = ? WHERE id = ?").bind(next,item.ingredientId).run();
    }
    await context.env.DB.prepare("UPDATE meals SET status = 'eaten' WHERE id = ?").bind(id).run();
    return json({ok:true});
  }

  return json({error:"Method not allowed"},405);
}


async function routeRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, "");
  const context = { request, env, ctx };

  if (url.pathname.startsWith("/api/")) {
    if (path === "login") return handleLogin(context);
    if (path === "session") return handleSession(context);
    if (path === "logout") return handleLogout(context);
    if (path === "ingredients") return handleIngredients(context);
    if (path === "meals") return handleMeals(context);
    return json({ error: "Not found" }, 404);
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await routeRequest(request, env, ctx);
    } catch (error) {
      console.error(error);
      return json({ error: "Server error" }, 500);
    }
  }
};
