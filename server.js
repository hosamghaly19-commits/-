const express = require("express"), crypto = require("crypto"), path = require("path");
const UNITS = "القيراطية,كفر حجازي,رعاية ثان,السجاعية,شبراملكان,سندسيس,الهياتم,بلقينا,اللابشيط,كفر فيالة,صفط,المعتمدية,شويقي سعد,شبرابابل,دنوشر,م.صحة ثان,م.صحة ثالث,م.صحة سادس,الدواخلية,العامرية,عياش,راغب عطية,كفر دمتنو,نمرة البصل,كفر قريطنة".split(",");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) { console.error("ADMIN_PASSWORD is required"); process.exit(1); }
let Pool;
if (process.env.PGMEM) Pool = require("pg-mem").newDb().adapters.createPg().Pool;
else Pool = require("pg").Pool;
const url = process.env.DATABASE_URL || "";
const pool = new Pool(process.env.PGMEM ? {} : { connectionString: url, max: 3, ssl: /localhost|127\.0\.0\.1/.test(url) ? false : { rejectUnauthorized: false } });
const q = (s, p) => pool.query(s, p);
const sha = s => crypto.createHash("sha256").update(String(s)).digest("hex");
const eq = (a, b) => { a = Buffer.from(a); b = Buffer.from(b); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const norm = p => { p = String(p || "").replace(/\D/g, ""); if (p.startsWith("00")) p = p.slice(2); if (p.startsWith("0")) p = "20" + p.slice(1); return p; };
const h = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: "خطأ في السيرفر" }); });
const bad = (res, msg, c = 400) => res.status(c).json({ error: msg });

async function init() {
  await q("create table if not exists users(phone text primary key, name text, role text, units text, salt text, code_hash text, fails int default 0, locked_until bigint default 0)");
  await q("create table if not exists sessions(token text primary key, kind text, phone text, created bigint)");
  await q("create table if not exists reports(date text, unit text, role text, count int, reason text, note text, by_name text, phone text, at bigint, primary key(date,unit,role))");
}
let ready;
const ensure = () => ready || (ready = init().catch(e => { ready = null; throw e; }));
async function newCode(u) {
  const code = String(crypto.randomInt(100000, 1000000)), salt = crypto.randomBytes(8).toString("hex");
  await q(`insert into users(phone,name,role,units,salt,code_hash,fails,locked_until) values($1,$2,$3,$4,$5,$6,0,0)
   on conflict (phone) do update set name=$2,role=$3,units=$4,salt=$5,code_hash=$6,fails=0,locked_until=0`,
    [u.phone, u.name, u.role, JSON.stringify(u.units), salt, sha(salt + u.phone + code)]);
  await q("delete from sessions where phone=$1", [u.phone]);
  return code;
}
async function session(kind, phone) {
  const t = crypto.randomBytes(32).toString("hex");
  await q("insert into sessions values($1,$2,$3,$4)", [sha(t), kind, phone, Date.now()]);
  return t;
}
const auth = kind => async (req, res, next) => {
  try {
    const t = (req.headers.authorization || "").replace("Bearer ", "");
    const s = t && (await q("select * from sessions where token=$1", [sha(t)])).rows[0];
    if (!s || s.kind !== kind || Date.now() - Number(s.created) > 30 * 864e5) return bad(res, "سجّل الدخول من جديد", 401);
    req.s = s; next();
  } catch (e) { bad(res, "خطأ", 500); }
};

const app = express();
app.use(express.json());
app.use("/api", (req, res, next) => ensure().then(() => next(), e => { console.error(e); bad(res, "تعذر الاتصال بقاعدة البيانات", 500); }));
app.use(express.static(path.join(__dirname, "public")));
app.get("/api/meta", (req, res) => res.json({ units: UNITS }));

app.post("/api/login", h(async (req, res) => {
  const phone = norm(req.body.phone), code = String(req.body.code || "").trim();
  const u = (await q("select * from users where phone=$1", [phone])).rows[0];
  const msg = "الرقم أو الكود غير صحيح، أو الحساب مقفول مؤقتًا";
  if (!u || Number(u.locked_until) > Date.now()) return bad(res, msg, 401);
  if (!eq(u.code_hash, sha(u.salt + phone + code))) {
    const f = u.fails + 1;
    await q("update users set fails=$2, locked_until=$3 where phone=$1", [phone, f >= 5 ? 0 : f, f >= 5 ? Date.now() + 15 * 60000 : 0]);
    return bad(res, msg, 401);
  }
  await q("update users set fails=0 where phone=$1", [phone]);
  res.json({ token: await session("user", phone), user: { name: u.name, phone, role: u.role, units: JSON.parse(u.units) } });
}));

let af = 0, alock = 0;
app.post("/api/admin/login", h(async (req, res) => {
  if (Date.now() < alock) return bad(res, "محاولات كثيرة، حاول بعد 15 دقيقة", 429);
  if (!eq(sha(req.body.password || ""), sha(ADMIN_PASSWORD))) { if (++af >= 8) { af = 0; alock = Date.now() + 15 * 60000; } return bad(res, "كلمة السر غير صحيحة", 401); }
  af = 0; res.json({ token: await session("admin", "admin") });
}));

app.post("/api/report", auth("user"), h(async (req, res) => {
  const u = (await q("select * from users where phone=$1", [req.s.phone])).rows[0];
  if (!u) return bad(res, "المستخدم غير موجود", 401);
  const { date, unit, count, reason, note } = req.body, n = Number(count);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date || "") || !Number.isInteger(n) || n < 0 || n > 100000) return bad(res, "بيانات غير صحيحة");
  if (!JSON.parse(u.units).includes(unit)) return bad(res, "هذه الوحدة غير مسموحة لك", 403);
  await q(`insert into reports values($1,$2,$3,$4,$5,$6,$7,$8,$9)
   on conflict (date,unit,role) do update set count=$4,reason=$5,note=$6,by_name=$7,phone=$8,at=$9`,
    [date, unit, u.role, n, n === 0 ? String(reason || "").slice(0, 100) : "", n === 0 ? String(note || "").slice(0, 300) : "", u.name, u.phone, Date.now()]);
  res.json({ ok: true });
}));

const A = auth("admin");
app.get("/api/admin/reports", A, h(async (req, res) => {
  res.json((await q("select date,unit,role,count,reason,note,by_name from reports where date>=$1 and date<=$2", [String(req.query.from), String(req.query.to)])).rows);
}));
app.get("/api/admin/users", A, h(async (req, res) => {
  res.json((await q("select phone,name,role,units from users order by name")).rows.map(r => ({ ...r, units: JSON.parse(r.units) })));
}));
app.post("/api/admin/users", A, h(async (req, res) => {
  const u = { name: String(req.body.name || "").trim(), phone: norm(req.body.phone), role: req.body.role === "m" ? "m" : "o", units: (req.body.units || []).filter(x => UNITS.includes(x)) };
  if (!u.name || u.phone.length < 11 || !u.units.length) return bad(res, "اكتب الاسم والتليفون واختر وحدة");
  res.json({ code: await newCode(u), phone: u.phone, name: u.name });
}));
app.post("/api/admin/users/:phone/code", A, h(async (req, res) => {
  const r = (await q("select * from users where phone=$1", [req.params.phone])).rows[0];
  if (!r) return bad(res, "غير موجود", 404);
  res.json({ code: await newCode({ ...r, units: JSON.parse(r.units) }), phone: r.phone, name: r.name });
}));
app.delete("/api/admin/users/:phone", A, h(async (req, res) => {
  await q("delete from users where phone=$1", [req.params.phone]); await q("delete from sessions where phone=$1", [req.params.phone]); res.json({ ok: true });
}));

if (require.main === module) ensure().then(() => app.listen(process.env.PORT || 3000, () => console.log("running"))).catch(e => { console.error(e); process.exit(1); });
module.exports = app;
