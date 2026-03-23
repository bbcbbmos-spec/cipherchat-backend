import os, sqlite3, secrets, asyncio, random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from werkzeug.security import generate_password_hash, check_password_hash
from jose import jwt, JWTError
from pydantic import BaseModel
import socketio, uvicorn

# ── Конфиг ───────────────────────────────────────────────────
SECRET  = os.environ.get("JWT_SECRET", secrets.token_hex(32))
ALGO    = "HS256"
DB_PATH = "/tmp/cipherchat.db"
PORT    = int(os.environ.get("PORT", 8000))

bearer = HTTPBearer(auto_error=False)

# ── БД ───────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

with db() as d:
    d.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL, nickname TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, public_key TEXT,
        signing_public_key TEXT, is_bot INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS chats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL, name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS chat_participants(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        encrypted_key TEXT DEFAULT '', iv TEXT DEFAULT '',
        is_favorite INTEGER DEFAULT 0, UNIQUE(chat_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL, sender_id INTEGER NOT NULL,
        encrypted_text TEXT DEFAULT '', ciphertext TEXT DEFAULT '',
        iv TEXT DEFAULT '', ratchet_key TEXT, signature TEXT,
        counter INTEGER DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS saved_messages(
        user_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
        PRIMARY KEY(user_id, message_id)
    );
    INSERT OR IGNORE INTO users(email,nickname,password_hash,is_bot)
        VALUES('q@bot.local','q','x',1),('w@bot.local','w','x',1);
    """)

# ── JWT ──────────────────────────────────────────────────────
def tok(data):
    return jwt.encode(
        {**data, "exp": datetime.utcnow() + timedelta(days=7)},
        SECRET, ALGO)

def me(c: HTTPAuthorizationCredentials = Depends(bearer)):
    if not c: raise HTTPException(401)
    try: return jwt.decode(c.credentials, SECRET, algorithms=[ALGO])
    except JWTError: raise HTTPException(403)

# ── Pydantic ─────────────────────────────────────────────────
class Reg(BaseModel):
    email: str; nickname: str; password: str
class Log(BaseModel):
    email: str; password: str
class Chat(BaseModel):
    type: str; name: Optional[str] = None
    participantIds: list[int]; encryptedKeys: Optional[dict] = None
class PubKey(BaseModel):
    publicKey: str; signingPublicKey: Optional[str] = None

# ── Helper ───────────────────────────────────────────────────
def get_chat_with_recipient(d, chat_id: int, user_id: int):
    return d.execute("""
        SELECT c.id, c.type, c.name, c.created_at,
               cp.encrypted_key, cp.iv, cp.is_favorite,
               (SELECT u2.nickname FROM chat_participants cp2
                JOIN users u2 ON cp2.user_id=u2.id
                WHERE cp2.chat_id=c.id AND cp2.user_id!=? LIMIT 1) as recipient_username,
               (SELECT u2.id FROM chat_participants cp2
                JOIN users u2 ON cp2.user_id=u2.id
                WHERE cp2.chat_id=c.id AND cp2.user_id!=? LIMIT 1) as recipient_id
        FROM chats c JOIN chat_participants cp ON c.id=cp.chat_id
        WHERE c.id=? AND cp.user_id=?
    """, (user_id, user_id, chat_id, user_id)).fetchone()

# ── FastAPI ───────────────────────────────────────────────────
app = FastAPI(docs_url="/docs")

@app.middleware("http")
async def cors(req: Request, nxt):
    if req.method == "OPTIONS":
        return Response(status_code=200, headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
        })
    r = await nxt(req)
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return r

@app.get("/health")
def health(): return {"ok": True}

@app.get("/")
def root(): return {"status": "ok"}

@app.post("/api/auth/register")
def register(b: Reg):
    if len(b.password) < 6: raise HTTPException(400, "Password too short")
    d = db()
    try:
        cur = d.execute(
            "INSERT INTO users(email,nickname,password_hash) VALUES(?,?,?)",
            (b.email.lower().strip(), b.nickname.strip(), generate_password_hash(b.password)))
        d.commit(); uid = cur.lastrowid
        return {"token": tok({"id":uid,"email":b.email,"nickname":b.nickname}),
                "user":  {"id":uid,"email":b.email,"nickname":b.nickname}}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Email or nickname already exists")
    finally: d.close()

@app.post("/api/auth/login")
def login(b: Log):
    d = db()
    try:
        u = d.execute("SELECT * FROM users WHERE email=?", (b.email.lower().strip(),)).fetchone()
        if not u or u["is_bot"] or not check_password_hash(u["password_hash"], b.password):
            raise HTTPException(401, "Invalid credentials")
        return {"token": tok({"id":u["id"],"email":u["email"],"nickname":u["nickname"]}),
                "user":  {"id":u["id"],"email":u["email"],"nickname":u["nickname"]}}
    finally: d.close()

@app.get("/api/users/search")
def search(query: str, u=Depends(me)):
    d = db()
    try:
        q = f"%{query}%"
        rows = d.execute(
            "SELECT id,email,nickname,is_bot,public_key,signing_public_key FROM users "
            "WHERE (email LIKE ? OR nickname LIKE ?) AND id!=? LIMIT 10",
            (q,q,u["id"])).fetchall()
        return [dict(r) for r in rows]
    finally: d.close()

@app.post("/api/users/public-key")
def upd_key(b: PubKey, u=Depends(me)):
    d = db()
    try:
        d.execute("UPDATE users SET public_key=?,signing_public_key=? WHERE id=?",
                  (b.publicKey,b.signingPublicKey,u["id"]))
        d.commit(); return {"success": True}
    finally: d.close()

@app.get("/api/users/{uid}/public-key")
def get_key(uid: int, u=Depends(me)):
    d = db()
    try:
        r = d.execute("SELECT public_key,signing_public_key FROM users WHERE id=?",(uid,)).fetchone()
        if not r: raise HTTPException(404)
        return {"publicKey":r["public_key"],"signingPublicKey":r["signing_public_key"]}
    finally: d.close()

@app.get("/api/chats")
def list_chats(u=Depends(me)):
    d = db()
    try:
        rows = d.execute("""
            SELECT c.id,c.type,c.name,c.created_at,cp.encrypted_key,cp.iv,cp.is_favorite,
                   (SELECT u2.nickname FROM chat_participants cp2 JOIN users u2 ON cp2.user_id=u2.id
                    WHERE cp2.chat_id=c.id AND cp2.user_id!=? LIMIT 1) as recipient_username,
                   (SELECT u2.id FROM chat_participants cp2 JOIN users u2 ON cp2.user_id=u2.id
                    WHERE cp2.chat_id=c.id AND cp2.user_id!=? LIMIT 1) as recipient_id
            FROM chats c JOIN chat_participants cp ON c.id=cp.chat_id
            WHERE cp.user_id=? ORDER BY c.created_at DESC
        """, (u["id"],u["id"],u["id"])).fetchall()
        return [dict(r) for r in rows]
    finally: d.close()

@app.post("/api/chats")
def create_chat(b: Chat, u=Depends(me)):
    d = db()
    try:
        ids = list(set(b.participantIds+[u["id"]]))
        ex = d.execute(f"SELECT id FROM users WHERE id IN ({','.join('?'*len(ids))})",ids).fetchall()
        if len(ex)!=len(ids): raise HTTPException(400,"User not found")
        if b.type=='private' and len(ids)==2:
            other_id=[i for i in ids if i!=u["id"]][0]
            existing=d.execute("""
                SELECT c.id FROM chats c
                JOIN chat_participants cp1 ON cp1.chat_id=c.id AND cp1.user_id=?
                JOIN chat_participants cp2 ON cp2.chat_id=c.id AND cp2.user_id=?
                WHERE c.type='private' LIMIT 1
            """,(u["id"],other_id)).fetchone()
            if existing:
                return dict(get_chat_with_recipient(d,existing["id"],u["id"]))
        cur=d.execute("INSERT INTO chats(type,name) VALUES(?,?)",(b.type,b.name))
        cid=cur.lastrowid
        for pid in ids:
            kd=(b.encryptedKeys or {}).get(str(pid),{})
            d.execute("INSERT OR IGNORE INTO chat_participants(chat_id,user_id,encrypted_key,iv) VALUES(?,?,?,?)",
                      (cid,pid,kd.get("wrappedKey",""),kd.get("iv","")))
        d.commit()
        return dict(get_chat_with_recipient(d,cid,u["id"]))
    finally: d.close()

@app.delete("/api/chats/{cid}")
def delete_chat(cid: int, u=Depends(me)):
    d = db()
    try:
        if not d.execute("SELECT 1 FROM chat_participants WHERE chat_id=? AND user_id=?",
                         (cid,u["id"])).fetchone():
            raise HTTPException(403)
        d.execute("DELETE FROM saved_messages WHERE message_id IN (SELECT id FROM messages WHERE chat_id=?)",(cid,))
        d.execute("DELETE FROM messages WHERE chat_id=?",(cid,))
        d.execute("DELETE FROM chat_participants WHERE chat_id=?",(cid,))
        d.execute("DELETE FROM chats WHERE id=?",(cid,))
        d.commit()
        return {"success":True,"deleted_chat_id":cid}
    finally: d.close()

@app.get("/api/chats/saved-messages")
def saved_msgs(u=Depends(me)):
    d = db()
    try:
        rows=d.execute("""
            SELECT m.*,u.nickname as sender_nickname,u.is_bot as sender_is_bot
            FROM saved_messages sm JOIN messages m ON sm.message_id=m.id
            JOIN users u ON m.sender_id=u.id WHERE sm.user_id=? ORDER BY m.timestamp DESC
        """,(u["id"],)).fetchall()
        return [dict(r) for r in rows]
    finally: d.close()

@app.get("/api/chats/{cid}/messages")
def get_msgs(cid: int, u=Depends(me)):
    d = db()
    try:
        if not d.execute("SELECT 1 FROM chat_participants WHERE chat_id=? AND user_id=?",
                         (cid,u["id"])).fetchone(): raise HTTPException(403)
        rows=d.execute("""
            SELECT m.*,u.nickname as sender_nickname,u.is_bot as sender_is_bot,
                   CASE WHEN sm.message_id IS NOT NULL THEN 1 ELSE 0 END as is_saved
            FROM messages m JOIN users u ON m.sender_id=u.id
            LEFT JOIN saved_messages sm ON sm.message_id=m.id AND sm.user_id=?
            WHERE m.chat_id=? ORDER BY m.timestamp ASC LIMIT 200
        """,(u["id"],cid)).fetchall()
        return [dict(r) for r in rows]
    finally: d.close()

@app.get("/api/chats/{cid}/participants")
def get_parts(cid: int, u=Depends(me)):
    d = db()
    try:
        rows=d.execute("""
            SELECT u.id,u.email,u.nickname,u.is_bot,u.public_key,u.signing_public_key
            FROM chat_participants cp JOIN users u ON cp.user_id=u.id WHERE cp.chat_id=?
        """,(cid,)).fetchall()
        return [dict(r) for r in rows]
    finally: d.close()

@app.post("/api/chats/{cid}/favorite")
def fav(cid: int, u=Depends(me)):
    d = db()
    try:
        r=d.execute("SELECT is_favorite FROM chat_participants WHERE chat_id=? AND user_id=?",
                    (cid,u["id"])).fetchone()
        if not r: raise HTTPException(403)
        new=0 if r["is_favorite"] else 1
        d.execute("UPDATE chat_participants SET is_favorite=? WHERE chat_id=? AND user_id=?",
                  (new,cid,u["id"]))
        d.commit(); return {"is_favorite":bool(new)}
    finally: d.close()

@app.post("/api/chats/messages/{mid}/save")
def save_msg(mid: int, u=Depends(me)):
    d = db()
    try:
        ex=d.execute("SELECT 1 FROM saved_messages WHERE user_id=? AND message_id=?",
                     (u["id"],mid)).fetchone()
        if ex:
            d.execute("DELETE FROM saved_messages WHERE user_id=? AND message_id=?",(u["id"],mid))
            saved=False
        else:
            d.execute("INSERT OR IGNORE INTO saved_messages VALUES(?,?)",(u["id"],mid))
            saved=True
        d.commit(); return {"is_saved":saved}
    finally: d.close()

# ── Socket.IO ─────────────────────────────────────────────────
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*",
                            logger=False, engineio_logger=False)
us, su = {}, {}
BOTS = {"q":["Hello! 👋","Tell me more!","Looks good 🚀"],
        "w":["Bot W here.","Beep boop...","Works! ✅"]}

@sio.event
async def connect(sid, environ, auth):
    t=(auth or {}).get("token")
    if not t: raise socketio.exceptions.ConnectionRefusedError("no token")
    try:
        p=jwt.decode(t,SECRET,algorithms=[ALGO])
        uid=p["id"]; us[uid]=sid; su[sid]=uid
        d=db()
        for c in d.execute("SELECT chat_id FROM chat_participants WHERE user_id=?",(uid,)).fetchall():
            await sio.enter_room(sid,f"chat_{c['chat_id']}")
        d.close()
    except JWTError:
        raise socketio.exceptions.ConnectionRefusedError("bad token")

@sio.event
async def disconnect(sid):
    uid=su.pop(sid,None)
    if uid: us.pop(uid,None)

@sio.event
async def join_chat(sid, chat_id):
    uid=su.get(sid)
    if not uid: return
    d=db()
    if d.execute("SELECT 1 FROM chat_participants WHERE chat_id=? AND user_id=?",
                 (chat_id,uid)).fetchone():
        await sio.enter_room(sid,f"chat_{chat_id}")
    d.close()

@sio.event
async def send_message(sid, data, callback=None):
    uid=su.get(sid)
    if not uid: return
    cid=data.get("chatId"); ct=data.get("ciphertext") or data.get("encryptedText","")
    iv=data.get("iv","PLAIN"); sig=data.get("signature")
    rat=data.get("ratchetKey"); ctr=data.get("counter",0)
    d=db()
    if not d.execute("SELECT 1 FROM chat_participants WHERE chat_id=? AND user_id=?",
                     (cid,uid)).fetchone():
        d.close()
        if callback: callback({"status":"error"}); return
    cur=d.execute(
        "INSERT INTO messages(chat_id,sender_id,encrypted_text,ciphertext,iv,ratchet_key,signature,counter)"
        " VALUES(?,?,?,?,?,?,?,?)",(cid,uid,ct,ct,iv,rat,sig,ctr))
    d.commit(); mid=cur.lastrowid
    nick=d.execute("SELECT nickname FROM users WHERE id=?",(uid,)).fetchone()["nickname"]
    msg={"id":mid,"chat_id":cid,"sender_id":uid,"sender_nickname":nick,"sender_is_bot":0,
         "encrypted_text":ct,"ciphertext":ct,"iv":iv,"signature":sig,"ratchet_key":rat,
         "counter":ctr,"timestamp":datetime.utcnow().isoformat(),"attachments":[]}
    await sio.emit("new_message",msg,room=f"chat_{cid}")
    if callback: callback({"status":"ok","id":mid})
    bots=d.execute("""SELECT u.id,u.nickname FROM chat_participants cp
        JOIN users u ON cp.user_id=u.id WHERE cp.chat_id=? AND u.is_bot=1""",(cid,)).fetchall()
    d.close()
    for bot in bots:
        await asyncio.sleep(random.uniform(1,2.5))
        text=random.choice(BOTS.get(bot["nickname"],["I'm a bot!"]))
        d2=db()
        bc=d2.execute("INSERT INTO messages(chat_id,sender_id,encrypted_text,ciphertext,iv) VALUES(?,?,?,?,?)",
                      (cid,bot["id"],text,text,"BOT"))
        d2.commit(); bid=bc.lastrowid; d2.close()
        await sio.emit("new_message",{"id":bid,"chat_id":cid,"sender_id":bot["id"],
            "sender_nickname":bot["nickname"],"sender_is_bot":1,
            "encrypted_text":text,"ciphertext":text,"iv":"BOT",
            "timestamp":datetime.utcnow().isoformat(),"attachments":[]},room=f"chat_{cid}")

# ── Сборка и запуск ───────────────────────────────────────────
from socketio import ASGIApp
combined = ASGIApp(sio, other_asgi_app=app, socketio_path="socket.io")

if __name__ == "__main__":
    uvicorn.run(combined, host="0.0.0.0", port=PORT, log_level="info")
