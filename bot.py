# language: Python 3.11+, file: bot.py, target: Telegram Bot API
# OSINT-бот: пароль-гейт FREE/PAID, поиск по номеру/@ник/email/ФИО,
# гео (EXIF/IP/домен), поиск родителей, история.
# зависимости: aiogram aiohttp aiosqlite phonenumbers pillow

import asyncio
import aiosqlite
import aiohttp
import hashlib
import hmac
import io
import os
import re
import time
import phonenumbers
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command
from aiogram.types import Message
from aiogram.client.default import DefaultBotProperties

# ============================================================
# КОНФИГ
# ============================================================
BOT_TOKEN = os.getenv("BOT_TOKEN", "YOUR_TOKEN_HERE")
ACCESS_PASSWORD_HASH = os.getenv(
    "ACCESS_PASSWORD_HASH",
    hashlib.sha256(b"changeme").hexdigest(),
)
DB_PATH = os.getenv("DB_PATH", "osint.db")

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_attempts: dict[int, list[float]] = {}
_unlocked: dict[int, float] = {}

router = Router()

# ============================================================
# БАЗА
# ============================================================
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL,
                source TEXT NOT NULL,
                data TEXT NOT NULL,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_query ON results(query)")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                unlocked INTEGER DEFAULT 0,
                unlock_ts REAL DEFAULT 0
            )
        """)
        await db.commit()

async def save_result(query: str, source: str, data: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO results (query, source, data) VALUES (?, ?, ?)",
            (query, source, data),
        )
        await db.commit()

async def fetch_results(query: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT source, data, ts FROM results WHERE query = ? ORDER BY ts DESC LIMIT 50",
            (query,),
        )
        return await cur.fetchall()

# ============================================================
# ДОСТУП
# ============================================================
async def is_unlocked(user_id: int) -> bool:
    if user_id in _unlocked:
        return _unlocked[user_id] == 0 or time.time() < _unlocked[user_id]
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT unlocked, unlock_ts FROM users WHERE user_id = ?", (user_id,)
        )
        row = await cur.fetchone()
        if not row or not row[0]:
            return False
        ts = row[1]
        if ts == 0 or time.time() < ts:
            _unlocked[user_id] = ts
            return True
    return False

async def set_unlocked(user_id: int, duration: float = 0):
    unlock_ts = 0 if duration == 0 else time.time() + duration
    _unlocked[user_id] = unlock_ts
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO users (user_id, unlocked, unlock_ts) VALUES (?, 1, ?)",
            (user_id, unlock_ts),
        )
        await db.commit()

def check_password(raw: str) -> bool:
    h = hashlib.sha256(raw.encode()).hexdigest()
    return hmac.compare_digest(h, ACCESS_PASSWORD_HASH)

def rate_limited(user_id: int) -> bool:
    now = time.time()
    hist = _attempts.setdefault(user_id, [])
    hist[:] = [t for t in hist if now - t < LOCKOUT_SECONDS]
    if len(hist) >= MAX_ATTEMPTS:
        return True
    hist.append(now)
    return False

# ============================================================
# ВАЛИДАЦИЯ
# ============================================================
def parse_phone(raw: str):
    try:
        p = phonenumbers.parse(raw, None)
        if phonenumbers.is_valid_number(p):
            return phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        pass
    return None

def classify(query: str) -> str:
    q = query.strip()
    if q.startswith("@"):
        return "username"
    if "@" in q and "." in q:
        return "email"
    if q.startswith("+") or q.replace(" ", "").replace("-", "").isdigit():
        return "phone"
    if re.match(r"^[А-ЯЁа-яё][а-яё]+\s+[А-ЯЁа-яё]+\s+[А-ЯЁа-яё]+", q):
        return "fullname"
    return "unknown"

# ============================================================
# ГЕО — EXIF
# ============================================================
def _gps_to_decimal(gps: dict):
    def _to_deg(v, ref):
        d, m, s = v
        deg = float(d) + float(m) / 60 + float(s) / 3600
        return -deg if ref in ("S", "W") else deg
    try:
        return _to_deg(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef")), \
               _to_deg(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
    except Exception:
        return None

def extract_exif_geo(image_bytes: bytes):
    out = {"gps": None, "datetime": None, "camera": None}
    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif = img.getexif()
        if not exif:
            return out
        for tag_id, value in exif.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "DateTimeOriginal":
                out["datetime"] = str(value)
            elif tag == "Model":
                out["camera"] = str(value)
        gps_ifd = exif.get_ifd(0x8825)
        if gps_ifd:
            gps = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            out["gps"] = _gps_to_decimal(gps)
    except Exception:
        pass
    return out

def geo_links(lat: float, lon: float):
    return [
        ("yandex_maps", f"https://yandex.ru/maps/?pt={lon},{lat}&z=17"),
        ("google_maps", f"https://maps.google.com/?q={lat},{lon}"),
        ("osm", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"),
    ]

# ============================================================
# ГЕО — IP / домен
# ============================================================
async def ip_geo(session: aiohttp.ClientSession, ip: str):
    try:
        async with session.get(f"http://ip-api.com/json/{ip}", timeout=10) as r:
            if r.status == 200:
                d = await r.json()
                if d.get("status") == "success":
                    return [("ip_geo",
                             f"IP {ip}: {d.get('country')}, {d.get('regionName')}, "
                             f"{d.get('city')}, {d.get('zip')}, ISP: {d.get('isp')}, "
                             f"координаты: {d.get('lat')},{d.get('lon')}")]
    except Exception:
        pass
    return []

async def domain_geo(session: aiohttp.ClientSession, domain: str):
    try:
        async with session.get(f"https://rdap.org/domain/{domain}", timeout=15) as r:
            if r.status == 200:
                d = await r.json()
                events = d.get("events", [])
                reg = next((e.get("eventDate") for e in events
                            if e.get("eventAction") == "registration"), "?")
                return [("domain", f"{domain}: регистрация {reg}")]
    except Exception:
        pass
    return []

# ============================================================
# ПОИСК — БАЗОВЫЕ
# ============================================================
async def check_phone_operator(phone: str):
    try:
        p = phonenumbers.parse(phone, None)
        carrier = phonenumbers.carrier.name_for_number(p, "ru")
        region = phonenumbers.geocoder.description_for_number(p, "ru")
        return [("phone_info", f"оператор: {carrier or '?'}, регион: {region or '?'}")]
    except Exception:
        return []

async def check_telegram_username(session: aiohttp.ClientSession, username: str):
    url = f"https://t.me/{username.lstrip('@')}"
    try:
        async with session.get(url, timeout=10) as r:
            if r.status == 200 and "tgme_page_title" in await r.text():
                return [("telegram", f"@{username.lstrip('@')} существует")]
    except Exception:
        pass
    return []

async def check_gravatar(session: aiohttp.ClientSession, email: str):
    h = hashlib.md5(email.lower().strip().encode()).hexdigest()
    try:
        async with session.get(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=10) as r:
            if r.status == 200:
                return [("gravatar", f"профиль: https://gravatar.com/{h}")]
    except Exception:
        pass
    return []

async def check_github_email(session: aiohttp.ClientSession, email: str):
    url = f"https://api.github.com/search/commits?q=author-email:{email}"
    headers = {"Accept": "application/vnd.github.cloak-preview+json"}
    try:
        async with session.get(url, headers=headers, timeout=15) as r:
            if r.status == 200:
                d = await r.json()
                if d.get("total_count", 0) > 0:
                    return [("github", f"найдено {d['total_count']} коммитов")]
    except Exception:
        pass
    return []

# ============================================================
# ПОИСК — РОДИТЕЛИ
# ============================================================
async def search_sudact(session: aiohttp.ClientSession, full_name: str):
    url = f"https://sudact.ru/regular/doc/?regular-txt={full_name}"
    try:
        async with session.get(url, timeout=15,
                               headers={"User-Agent": "Mozilla/5.0"}) as r:
            if r.status == 200:
                text = await r.text()
                m = re.search(r"Найдено[^\d]*(\d+)", text)
                count = m.group(1) if m else "0"
                return [("sudact", f"суд. дела по '{full_name}': {count} ({url})")]
    except Exception:
        pass
    return []

async def search_fssp(session: aiohttp.ClientSession, full_name: str):
    parts = full_name.strip().split()
    if len(parts) < 2:
        return []
    return [("fssp", f"долги: https://fssp.gov.ru/iss/ip (ФИО: {full_name})")]

async def search_vk_relatives(session: aiohttp.ClientSession, full_name: str):
    return [("vk", f"поиск VK: https://vk.com/search?c[q]={full_name}&c[section]=people")]

async def search_social_by_surname(session: aiohttp.ClientSession, full_name: str):
    parts = full_name.strip().split()
    if not parts:
        return []
    s = parts[0]
    return [
        ("ok", f"Одноклассники: https://ok.ru/search?st.query={s}"),
        ("vk_people", f"VK люди: https://vk.com/search?c[q]={s}&c[section]=people"),
    ]

async def search_fns_egrul(session: aiohttp.ClientSession, full_name: str):
    return [("fns", f"ЕГРЮЛ: https://egrul.nalog.ru/search?query={full_name}")]

async def find_parents(full_name: str, city: str | None = None):
    results = []
    async with aiohttp.ClientSession() as session:
        tasks = [
            search_sudact(session, full_name),
            search_fssp(session, full_name),
            search_vk_relatives(session, full_name),
            search_social_by_surname(session, full_name),
            search_fns_egrul(session, full_name),
        ]
        for g in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(g, list):
                results.extend(g)
    return results

# ============================================================
# АГРЕГАТОР
# ============================================================
async def run_osint(query: str, paid: bool):
    kind = classify(query)
    results = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        if kind == "phone":
            phone = parse_phone(query) or query
            query = phone
            results.extend(await check_phone_operator(phone))
        elif paid and kind == "username":
            tasks.append(check_telegram_username(session, query))
        elif paid and kind == "email":
            tasks.append(check_gravatar(session, query))
            tasks.append(check_github_email(session, query))
        elif paid and kind == "fullname":
            results.extend(await find_parents(query))
        if tasks:
            for g in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(g, list):
                    results.extend(g)
    if paid:
        for source, data in results:
            await save_result(query, source, data)
    return results

# ============================================================
# ХЕНДЛЕРЫ
# ============================================================
@router.message(Command("start"))
async def cmd_start(msg: Message):
    paid = await is_unlocked(msg.from_user.id)
    mode = "PAID (полный)" if paid else "FREE (базовый)"
    await msg.answer(
        f"OSINT-бот. Режим: {mode}\n"
        "Запросы: номер (+7...), @username, email, ФИО.\n"
        "/geo <IP|домен> — гео\n"
        "Фото с подписью /geo — EXIF GPS\n"
        "/parents ФИО — поиск родителей\n"
        "/history <запрос> — история (PAID)\n"
        "/unlock <пароль> — полный доступ"
    )

@router.message(Command("unlock"))
async def cmd_unlock(msg: Message):
    uid = msg.from_user.id
    if await is_unlocked(uid):
        await msg.answer("Уже разблокировано.")
        return
    parts = msg.text.split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("Использование: /unlock <пароль>")
        return
    if rate_limited(uid):
        await msg.answer(f"Слишком много попыток. Жди {LOCKOUT_SECONDS // 60} мин.")
        return
    if check_password(parts[1].strip()):
        await set_unlocked(uid, duration=0)
        _attempts.pop(uid, None)
        await msg.answer("Доступ открыт. Полный режим активен.")
    else:
        remaining = MAX_ATTEMPTS - len(_attempts.get(uid, []))
        await msg.answer(f"Неверный пароль. Осталось попыток: {remaining}")

@router.message(Command("history"))
async def cmd_history(msg: Message):
    if not await is_unlocked(msg.from_user.id):
        await msg.answer("Только для PAID. /unlock <пароль>")
        return
    parts = msg.text.split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("Использование: /history <запрос>")
        return
    rows = await fetch_results(parts[1].strip())
    if not rows:
        await msg.answer("Пусто.")
        return
    out = "\n".join(f"[{s}] {d} ({ts})" for s, d, ts in rows)
    await msg.answer(f"<pre>{out}</pre>")

@router.message(Command("geo"))
async def cmd_geo(msg: Message):
    parts = msg.text.split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("Использование: /geo <IP|домен>  или  фото с подписью /geo")
        return
    target = parts[1].strip()
    async with aiohttp.ClientSession() as session:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            res = await ip_geo(session, target)
        else:
            res = await domain_geo(session, target)
    if not res:
        await msg.answer("Не найдено.")
        return
    out = "\n".join(f"[{s}] {d}" for s, d in res)
    await msg.answer(f"<pre>{out}</pre>")

@router.message(F.photo, F.caption == "/geo")
async def handle_geo_photo(msg: Message):
    photo = msg.photo[-1]
    file = await msg.bot.get_file(photo.file_id)
    buf = io.BytesIO()
    await msg.bot.download_file(file.file_path, buf)
    exif = extract_exif_geo(buf.getvalue())
    if not exif["gps"]:
        await msg.answer("EXIF GPS не найден.")
        return
    lat, lon = exif["gps"]
    out = f"Координаты: {lat}, {lon}\n"
    if exif["datetime"]:
        out += f"Время: {exif['datetime']}\n"
    if exif["camera"]:
        out += f"Камера: {exif['camera']}\n"
    out += "\n".join(f"[{s}] {u}" for s, u in geo_links(lat, lon))
    await msg.answer(f"<pre>{out}</pre>")

@router.message(Command("parents"))
async def cmd_parents(msg: Message):
    if not await is_unlocked(msg.from_user.id):
        await msg.answer("Только для PAID. /unlock <пароль>")
        return
    parts = msg.text.split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("Использование: /parents Фамилия Имя Отчество [город]")
        return
    args = parts[1].strip().split()
    full_name = " ".join(args[:3])
    city = args[3] if len(args) > 3 else None
    await msg.answer(f"Ищу родителей по: {full_name}...")
    results = await find_parents(full_name, city)
    if not results:
        await msg.answer("Ничего не найдено.")
        return
    out = "\n".join(f"[{s}] {d}" for s, d in results)
    await msg.answer(f"<pre>{out}</pre>")

@router.message(F.text)
async def handle_query(msg: Message):
    q = msg.text.strip()
    if q.startswith("/"):
        return
    kind = classify(q)
    if kind == "unknown":
        await msg.answer("Номер, @username, email или ФИО.")
        return
    paid = await is_unlocked(msg.from_user.id)
    results = await run_osint(q, paid=paid)
    if not results:
        tail = "" if paid else "\nДля полного поиска: /unlock <пароль>"
        await msg.answer(f"Ничего не найдено.{tail}")
        return
    out = "\n".join(f"[{s}] {d}" for s, d in results)
    tail = "" if paid else "\n(FREE — часть источников скрыта)"
    await msg.answer(f"<pre>{out}</pre>{tail}")

# ============================================================
# ЗАПУСК
# ============================================================
async def main():
    await init_db()
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher()
    dp.include_router(router)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
