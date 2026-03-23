import os, secrets, asyncio, random
from datetime import datetime, timedelta
from typing import Optional
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor
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
PORT    = int(os.environ.get("PORT", 8000))
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres.vgtvhythxizlxyktjamd:kh-eR3a3xfUV3YM@aws-1-eu-west-1.pooler.supabase.com:5432/postgres"
)

bearer = HTTPBearer(auto_error=False)

# ── БД ───────────────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor,
                            connect_timeout=10)

@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ── Инициализация таблиц ──────────────────────────────────────
def init_db():
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            nickname TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            signing_public_key TEXT,
            is_bot INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS chats(
            id SERIAL PRIMARY KEY,
            type TEXT NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS chat_participants(
            id SERIAL PRIMARY KEY,
            chat_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            encrypted_key TEXT DEFAULT '',
            iv TEXT DEFAULT '',
            is_favorite INTEGER DEFAULT 0,
            UNIQUE(chat_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages(
            id SERIAL PRIMARY KEY,
            chat_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            encrypted_text TEXT DEFAULT '',
            ciphertext TEXT DEFAULT '',
            iv TEXT DEFAULT '',
            ratchet_key TEXT,
            signature TEXT,
            counter INTEGER DEFAULT 0,
            is_read BOOLEAN DEFAULT FALSE,
            timestamp TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS saved_messages(
            user_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            PRIMARY KEY(user_id, message_id)
        );
        INSERT INTO users(email,nickname,password_hash,is_bot)
            VALUES('q@bot.local','q','x',1) ON CONFLICT DO NOTHING;
        INSERT INTO users(email,nickname,password_hash,is_bot)
            VALUES('w@bot.local','w','x',1) ON CONFLICT DO NOTHING;

        -- Добавляем is_read если таблица уже существовала без него
        ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT FALSE;
        """)

init_db()
print("✅ БД готова")

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
def get_chat_with_recipient(cur, chat_id: int, user_id: int):
    cur.execute("""
        SELECT c.id,c.type,c.name,c.created_at,
               cp.encrypted_key,cp.iv,cp.is_favorite,
               (SELECT u2.nickname FROM chat_participants cp2
                JOIN users u2 ON cp2.user_id=u2.id
                WHERE cp2.chat_id=c.id AND cp2.user_id!=%s LIMIT 1) as recipient_username,
               (SELECT u2.id FROM chat_participants cp2
                JOIN users u2 ON cp2.user_id=u2.id
                WHERE cp2.chat_id=c.id AND cp2.user_id!=%s LIMIT 1) as recipient_id
        FROM chats c JOIN chat_participants cp ON c.id=cp.chat_id
        WHERE c.id=%s AND cp.user_id=%s
    """, (user_id, user_id, chat_id, user_id))
    row = cur.fetchone()
    return dict(row) if row else {}

# ── FastAPI ───────────────────────────────────────────────────
app = FastAPI(docs_url="/docs")

@app.middleware("http")
async def cors(req: Request, nxt):
    if req.method == "OPTIONS":
        return Response(status_code=200, headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization,ngrok-skip-browser-warning",
        })
    r = await nxt(req)
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,ngrok-skip-browser-warning"
    return r

@app.get("/health")
def health(): return {"ok": True}

@app.get("/")
def root(): return {"status": "ok"}

# ── AUTH ──────────────────────────────────────────────────────
@app.post("/api/auth/register")
def register(b: Reg):
    if len(b.password) < 6: raise HTTPException(400, "Password too short")
    with db() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users(email,nickname,password_hash) VALUES(%s,%s,%s) RETURNING id",
                (b.email.lower().strip(), b.nickname.strip(), generate_password_hash(b.password)))
            uid = cur.fetchone()["id"]
            return {"token": tok({"id":uid,"email":b.email,"nickname":b.nickname}),
                    "user":  {"id":uid,"email":b.email,"nickname":b.nickname}}
        except psycopg2.errors.UniqueViolation:
            raise HTTPException(400, "Email or nickname already exists")

@app.post("/api/auth/login")
def login(b: Log):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (b.email.lower().strip(),))
        u = cur.fetchone()
        if not u or u["is_bot"] or not check_password_hash(u["password_hash"], b.password):
            raise HTTPException(401, "Invalid credentials")
        return {"token": tok({"id":u["id"],"email":u["email"],"nickname":u["nickname"]}),
                "user":  {"id":u["id"],"email":u["email"],"nickname":u["nickname"]}}

# ── USERS ─────────────────────────────────────────────────────
@app.get("/api/users/search")
def search(query: str, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        q = f"%{query}%"
        cur.execute(
            "SELECT id,email,nickname,is_bot,public_key,signing_public_key FROM users "
            "WHERE (email LIKE %s OR nickname LIKE %s) AND id!=%s LIMIT 10",
            (q,q,u["id"]))
        return [dict(r) for r in cur.fetchall()]

@app.post("/api/users/public-key")
def upd_key(b: PubKey, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET public_key=%s,signing_public_key=%s WHERE id=%s",
                    (b.publicKey,b.signingPublicKey,u["id"]))
        return {"success": True}

@app.get("/api/users/{uid}/public-key")
def get_key(uid: int, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT public_key,signing_public_key FROM users WHERE id=%s",(uid,))
        r = cur.fetchone()
        if not r: raise HTTPException(404)
        return {"publicKey":r["public_key"],"signingPublicKey":r["signing_public_key"]}

# ── CHATS ─────────────────────────────────────────────────────
@app.get("/api/chats")
def list_chats(u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT c.id,c.type,c.name,c.created_at,cp.encrypted_key,cp.iv,cp.is_favorite,
                   (SELECT u2.nickname FROM chat_participants cp2
                    JOIN users u2 ON cp2.user_id=u2.id
                    WHERE cp2.chat_id=c.id AND cp2.user_id!=%s LIMIT 1) as recipient_username,
                   (SELECT u2.id FROM chat_participants cp2
                    JOIN users u2 ON cp2.user_id=u2.id
                    WHERE cp2.chat_id=c.id AND cp2.user_id!=%s LIMIT 1) as recipient_id
            FROM chats c JOIN chat_participants cp ON c.id=cp.chat_id
            WHERE cp.user_id=%s ORDER BY c.created_at DESC
        """, (u["id"],u["id"],u["id"]))
        return [dict(r) for r in cur.fetchall()]

@app.post("/api/chats")
def create_chat(b: Chat, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        ids = list(set(b.participantIds+[u["id"]]))
        cur.execute(f"SELECT id FROM users WHERE id IN ({','.join(['%s']*len(ids))})", ids)
        if len(cur.fetchall()) != len(ids): raise HTTPException(400,"User not found")

        if b.type=='private' and len(ids)==2:
            other_id=[i for i in ids if i!=u["id"]][0]
            cur.execute("""
                SELECT c.id FROM chats c
                JOIN chat_participants cp1 ON cp1.chat_id=c.id AND cp1.user_id=%s
                JOIN chat_participants cp2 ON cp2.chat_id=c.id AND cp2.user_id=%s
                WHERE c.type='private' LIMIT 1
            """, (u["id"],other_id))
            existing = cur.fetchone()
            if existing:
                return get_chat_with_recipient(cur, existing["id"], u["id"])

        cur.execute("INSERT INTO chats(type,name) VALUES(%s,%s) RETURNING id",(b.type,b.name))
        cid = cur.fetchone()["id"]
        for pid in ids:
            kd=(b.encryptedKeys or {}).get(str(pid),{})
            cur.execute(
                "INSERT INTO chat_participants(chat_id,user_id,encrypted_key,iv) "
                "VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (cid,pid,kd.get("wrappedKey",""),kd.get("iv","")))
        return get_chat_with_recipient(cur, cid, u["id"])

@app.delete("/api/chats/{cid}")
def delete_chat(cid: int, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM chat_participants WHERE chat_id=%s AND user_id=%s",(cid,u["id"]))
        if not cur.fetchone(): raise HTTPException(403)
        cur.execute("DELETE FROM saved_messages WHERE message_id IN "
                    "(SELECT id FROM messages WHERE chat_id=%s)",(cid,))
        cur.execute("DELETE FROM messages WHERE chat_id=%s",(cid,))
        cur.execute("DELETE FROM chat_participants WHERE chat_id=%s",(cid,))
        cur.execute("DELETE FROM chats WHERE id=%s",(cid,))
        return {"success":True,"deleted_chat_id":cid}

@app.get("/api/chats/saved-messages")
def saved_msgs(u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT m.*,u.nickname as sender_nickname,u.is_bot as sender_is_bot
            FROM saved_messages sm JOIN messages m ON sm.message_id=m.id
            JOIN users u ON m.sender_id=u.id
            WHERE sm.user_id=%s ORDER BY m.timestamp DESC
        """,(u["id"],))
        return [dict(r) for r in cur.fetchall()]

@app.get("/api/chats/{cid}/messages")
def get_msgs(cid: int, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM chat_participants WHERE chat_id=%s AND user_id=%s",(cid,u["id"]))
        if not cur.fetchone(): raise HTTPException(403)
        cur.execute("""
            SELECT m.*,u.nickname as sender_nickname,u.is_bot as sender_is_bot,
                   CASE WHEN sm.message_id IS NOT NULL THEN 1 ELSE 0 END as is_saved
            FROM messages m JOIN users u ON m.sender_id=u.id
            LEFT JOIN saved_messages sm ON sm.message_id=m.id AND sm.user_id=%s
            WHERE m.chat_id=%s ORDER BY m.timestamp ASC LIMIT 200
        """,(u["id"],cid))
        return [dict(r) for r in cur.fetchall()]

# ── ПРОЧИТАНО — отмечаем все сообщения чата как прочитанные ──
@app.post("/api/chats/{cid}/read")
def mark_read(cid: int, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM chat_participants WHERE chat_id=%s AND user_id=%s",(cid,u["id"]))
        if not cur.fetchone(): raise HTTPException(403)
        # Отмечаем как прочитанные все сообщения НЕ от текущего пользователя
        cur.execute("""
            UPDATE messages SET is_read=TRUE
            WHERE chat_id=%s AND sender_id!=%s AND is_read=FALSE
            RETURNING id
        """, (cid, u["id"]))
        read_ids = [r["id"] for r in cur.fetchall()]
        return {"read_message_ids": read_ids}

@app.get("/api/chats/{cid}/participants")
def get_parts(cid: int, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT u.id,u.email,u.nickname,u.is_bot,u.public_key,u.signing_public_key
            FROM chat_participants cp JOIN users u ON cp.user_id=u.id WHERE cp.chat_id=%s
        """,(cid,))
        return [dict(r) for r in cur.fetchall()]

@app.post("/api/chats/{cid}/favorite")
def fav(cid: int, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT is_favorite FROM chat_participants WHERE chat_id=%s AND user_id=%s",
                    (cid,u["id"]))
        r = cur.fetchone()
        if not r: raise HTTPException(403)
        new = 0 if r["is_favorite"] else 1
        cur.execute("UPDATE chat_participants SET is_favorite=%s WHERE chat_id=%s AND user_id=%s",
                    (new,cid,u["id"]))
        return {"is_favorite":bool(new)}

@app.post("/api/chats/messages/{mid}/save")
def save_msg(mid: int, u=Depends(me)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM saved_messages WHERE user_id=%s AND message_id=%s",
                    (u["id"],mid))
        if cur.fetchone():
            cur.execute("DELETE FROM saved_messages WHERE user_id=%s AND message_id=%s",
                        (u["id"],mid))
            return {"is_saved":False}
        else:
            cur.execute("INSERT INTO saved_messages VALUES(%s,%s) ON CONFLICT DO NOTHING",
                        (u["id"],mid))
            return {"is_saved":True}

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
        with db() as conn:
            cur=conn.cursor()
            cur.execute("SELECT chat_id FROM chat_participants WHERE user_id=%s",(uid,))
            for c in cur.fetchall():
                await sio.enter_room(sid,f"chat_{c['chat_id']}")
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
    with db() as conn:
        cur=conn.cursor()
        cur.execute("SELECT 1 FROM chat_participants WHERE chat_id=%s AND user_id=%s",(chat_id,uid))
        if cur.fetchone():
            await sio.enter_room(sid,f"chat_{chat_id}")
            # Отмечаем сообщения как прочитанные при входе в чат
            cur.execute("""
                UPDATE messages SET is_read=TRUE
                WHERE chat_id=%s AND sender_id!=%s AND is_read=FALSE
                RETURNING id, sender_id
            """, (chat_id, uid))
            read_rows = cur.fetchall()
            # Уведомляем отправителей что их сообщения прочитаны
            for row in read_rows:
                sender_sid = us.get(row["sender_id"])
                if sender_sid:
                    await sio.emit("messages_read", {
                        "chat_id": chat_id,
                        "message_id": row["id"],
                        "read_by": uid
                    }, to=sender_sid)

@sio.event
async def send_message(sid, data, callback=None):
    uid=su.get(sid)
    if not uid: return
    cid=data.get("chatId"); ct=data.get("ciphertext") or data.get("encryptedText","")
    iv=data.get("iv","PLAIN"); sig=data.get("signature")
    rat=data.get("ratchetKey"); ctr=data.get("counter",0)

    with db() as conn:
        cur=conn.cursor()
        cur.execute("SELECT 1 FROM chat_participants WHERE chat_id=%s AND user_id=%s",(cid,uid))
        if not cur.fetchone():
            if callback: callback({"status":"error"}); return

        cur.execute(
            "INSERT INTO messages(chat_id,sender_id,encrypted_text,ciphertext,iv,"
            "ratchet_key,signature,counter,is_read) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,FALSE) RETURNING id",
            (cid,uid,ct,ct,iv,rat,sig,ctr))
        mid=cur.fetchone()["id"]
        cur.execute("SELECT nickname FROM users WHERE id=%s",(uid,))
        nick=cur.fetchone()["nickname"]
        cur.execute("SELECT u.id,u.nickname FROM chat_participants cp "
                    "JOIN users u ON cp.user_id=u.id "
                    "WHERE cp.chat_id=%s AND u.is_bot=1",(cid,))
        bots=cur.fetchall()

        # Проверяем есть ли собеседник онлайн в этом чате
        cur.execute("SELECT user_id FROM chat_participants WHERE chat_id=%s AND user_id!=%s",
                    (cid, uid))
        other_users = cur.fetchall()

    # Проверяем онлайн ли собеседник
    is_read = False
    for other in other_users:
        if other["user_id"] in us:
            is_read = True
            # Отмечаем как прочитанное сразу
            with db() as conn:
                cur = conn.cursor()
                cur.execute("UPDATE messages SET is_read=TRUE WHERE id=%s", (mid,))
            break

    msg={"id":mid,"chat_id":cid,"sender_id":uid,"sender_nickname":nick,"sender_is_bot":0,
         "encrypted_text":ct,"ciphertext":ct,"iv":iv,"signature":sig,"ratchet_key":rat,
         "counter":ctr,"is_read":is_read,
         "timestamp":datetime.utcnow().isoformat(),"attachments":[]}
    await sio.emit("new_message",msg,room=f"chat_{cid}")
    if callback: callback({"status":"ok","id":mid})

    for bot in bots:
        await asyncio.sleep(random.uniform(1,2.5))
        text=random.choice(BOTS.get(bot["nickname"],["I'm a bot!"]))
        with db() as conn:
            cur=conn.cursor()
            cur.execute(
                "INSERT INTO messages(chat_id,sender_id,encrypted_text,ciphertext,iv)"
                " VALUES(%s,%s,%s,%s,%s) RETURNING id",
                (cid,bot["id"],text,text,"BOT"))
            bid=cur.fetchone()["id"]
        await sio.emit("new_message",{
            "id":bid,"chat_id":cid,"sender_id":bot["id"],
            "sender_nickname":bot["nickname"],"sender_is_bot":1,
            "encrypted_text":text,"ciphertext":text,"iv":"BOT","is_read":False,
            "timestamp":datetime.utcnow().isoformat(),"attachments":[]},
            room=f"chat_{cid}")

# ── Сборка и запуск ───────────────────────────────────────────
from socketio import ASGIApp
combined = ASGIApp(sio, other_asgi_app=app, socketio_path="socket.io")

if __name__ == "__main__":
    uvicorn.run(combined, host="0.0.0.0", port=PORT, log_level="info")
