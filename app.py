BOT_NAME = 'raazdaar_bot'
TOKEN = '8532570108:AAFK4Rfzx0KLYIX75v3I_k-nRZThc1qPs9g'  # From BotFather
import json
import logging
import os
import base64
import asyncio  # Added for async bridging
from flask import Flask, request  # Added for webhook
from telegram import Update  # Already there, but ensures de_json works
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler
from telegram.constants import ChatAction, ChatType
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import random
import nest_asyncio
nest_asyncio.apply()  # Patches asyncio for webhook loops

# Enable logging to see bot activity/errors (helps debugging)
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

DUMMY_TEXTS = [
    "Hey yoooo! 😊",
    "What's up? brooo 👋",
    "How's it going???? 🌟",
    "Quick hellooooo! ☕",
    "Chillin' here! 🛋️",
    "Just dropped a meme 😂",
    "Pizza cravings hit hard 🍕",
    "Weekend vibes? 🏖️",
    "This weather tho... 🌤️",
    "Bored—anyone alive? 😴"
]

# JSON FILE STORE DATA ----------------- (UPDATED: per-user passes/auth, dummies per-chat with sender_id)
DATA_FILE = 'bot_data.json' # Renamed for clarity
# Load data from JSON (creates empty dict if file doesn't exist)
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {'user_passwords': {}, 'dummies': {}, 'active_msgs': {}} # UPDATED: No global pass/owner; users gone (auth via pass presence)

# Save data to JSON
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Load data at startup
data = load_data()

# UPDATED: Fixed storage key for encrypting user passes (generate your own: os.urandom(32))
STORAGE_KEY = bytes.fromhex('7d46a385a8841119e030235a32ed570516247e209d8e9ece13a3e0a660be867c')  # 32 bytes, secure random example

# UPDATED: Per-user plain cache (dict for multiple users)
user_plain_cache = {}  # {user_id: plain_pass}

# Crypto helpers -----------------------
def derive_key(password: str):
    salt = b'saltysalt123' # Fixed for demo; randomize in prod
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_message(real_msg: str, password: str):
    key = derive_key(password)
    aesgcm = AESGCM(key)
    nonce = b'nonce12345678' # Fixed demo; random in prod
    ciphertext = aesgcm.encrypt(nonce, real_msg.encode(), None)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_message(encrypted: str, password: str):
    try:
        key = derive_key(password)
        aesgcm = AESGCM(key)
        nonce = b'nonce12345678'
        ciphertext = base64.b64decode(encrypted)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
        return plaintext
    except:
        return None # Wrong pass/key

# UPDATED: Encrypt/decrypt user_pass for secure storage (uses fixed STORAGE_KEY)
def encrypt_storage_pass(plain: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Random nonce for security
    ct = aesgcm.encrypt(nonce, plain.encode(), None)
    return base64.b64encode(nonce + ct).decode('utf-8')

def decrypt_storage_pass(enc: str, key: bytes) -> str:
    try:
        data = base64.b64decode(enc)
        nonce = data[:12]
        ct = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None).decode('utf-8')
    except:
        return None  # Fail silently (wrong key/enc)

def get_user_plain(user_id: int) -> str | None:
    """Get plain pass for a user_id (cached for runtime)."""
    if user_id not in user_plain_cache:
        enc_pass = data.get('user_passwords', {}).get(str(user_id))
        if enc_pass:
            plain = decrypt_storage_pass(enc_pass, STORAGE_KEY)
            if plain:
                user_plain_cache[user_id] = plain
            else:
                logger.error(f"Failed to decrypt pass for user {user_id} - check STORAGE_KEY?")
    return user_plain_cache.get(user_id)

def is_user_authenticated(user_id: int) -> bool:
    """Check if user has a stored pass (implies auth'd for sending)."""
    return str(user_id) in data.get('user_passwords', {})

# START COMMAND ------------------------ (UPDATED: Only in private DMs; sets per-user pass)
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles /start: Sets up per-user pass if needed (private DM only), then auth flow.
    """
    chat = update.effective_chat
    user_id = update.effective_user.id  # UPDATED: Use user_id, not chat_id
    if chat.type != ChatType.PRIVATE:
        await update.message.reply_text("❌ /start only works in your private DM with me. Start a 1:1 chat first!")
        return

    # await context.bot.send_chat_action(chat_id=chat.id, action=ChatAction.TYPING)
    # logger.info(f"Sent TYPING for /start from user {user_id} in private DM")

    # UPDATED: Per-user setup check (no global first-time)
    user_passwords = data.get('user_passwords', {})
    if str(user_id) not in user_passwords:
        # First-time for this user: Flag setup
        context.user_data['awaiting_set_pass'] = True
        await update.message.reply_text("🚀 First setup! Enter your master passphrase (keep it secret—share only with trusted contacts):")
        return

    # User has pass: Confirm auth (prompt for it? Nah—presence = auth'd for sending. For reveal, pass is needed anyway.)
    await update.message.reply_text("✅ You're all set! Your passphrase is active. Use /changepass to update it.\n\nTip: Add me to a private group with a friend, send messages—they'll encrypt with your pass. Share your pass privately for them to reveal.")

# MESSAGE HANDLER ---------------------- (UPDATED: Per-user auth for sending; per-sender pass for reveal)
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles text: Reveal attempts (via reply to dummy, checks sender's pass), sets user pass (if first-time), or encrypts (if sender auth'd).
    """
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id  # UPDATED: Key for auth
    text = update.message.text.strip()
    # await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
    # logger.info(f"Received text: '{text}' from user {user_id} in chat {chat_id}")

    dummies = data.get('dummies', {})

    # UPDATED: First, check for reveal attempt (reply to a dummy message)
    if update.message.reply_to_message and update.message.reply_to_message.from_user.id == context.bot.id:
        replied_msg = update.message.reply_to_message
        replied_msg_id = replied_msg.message_id
        chat_dummies = dummies.get(str(chat_id), {})
        if replied_msg_id in chat_dummies:
            dummy_data = chat_dummies[replied_msg_id]  # UPDATED: Now {'enc': str, 'sender_id': int}
            sender_id = dummy_data['sender_id']
            encrypted = dummy_data['enc']
            sender_plain = get_user_plain(sender_id)  # Get sender's pass
            if text == sender_plain:
                # Correct passphrase: Decrypt, edit dummy to real, delete the passphrase reply (stealth)
                real_msg = decrypt_message(encrypted, text)
                if real_msg:
                    await context.bot.edit_message_text(
                        chat_id=chat_id,
                        message_id=replied_msg_id,
                        text=f"{real_msg} ✨"
                    )
                    # Remove from storage
                    del chat_dummies[replied_msg_id]
                    if not chat_dummies:
                        del dummies[str(chat_id)]
                    save_data(data)
                    # Delete the passphrase reply to hide it
                    await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
                    logger.info(f"User {user_id} revealed msg {replied_msg_id} from sender {sender_id} in chat {chat_id}")
                    return
                else:
                    await update.message.reply_text("❌ Decrypt failed. Contact the sender.")
                    return
            else:
                # Wrong passphrase: Do nothing (leave reply intact), continue to process as normal message
                logger.info(f"Wrong passphrase attempt for reveal by {user_id} on {sender_id}'s msg in {chat_id}")
                # Fall through to normal handling below

    # UPDATED: Check for first-time setup (private DM only, before other logic)
    if context.user_data.get('awaiting_set_pass') and update.effective_chat.type == ChatType.PRIVATE:
        # Set per-user pass
        data.setdefault('user_passwords', {})[str(user_id)] = encrypt_storage_pass(text, STORAGE_KEY)
        user_plain_cache[user_id] = text  # Cache the plain for runtime use
        save_data(data)
        del context.user_data['awaiting_set_pass']
        await update.message.reply_text("✅ Your passphrase is set! You're authenticated for sending encrypted messages.\n\nTip: Add me to a private group with a friend to start.")
        logger.info(f"Set pass for user {user_id}")
        return

    # UPDATED: Sending check (auth per sender user_id, anywhere bot is added)
    if is_user_authenticated(user_id):
        # Sender is auth'd: Silently delete the real sent message (hides "outgoing")
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
            logger.info(f"Deleted sent msg {update.message.message_id} from {user_id} in {chat_id}")
        except Exception as e:
            logger.warning(f"Failed to delete sent msg in {chat_id}: {e}")  # Fallback: msg stays, but rare

        sender_plain = get_user_plain(user_id)
        if not sender_plain:
            await context.bot.send_message(chat_id=chat_id, text="❌ Your passphrase unavailable - restart /start in private DM.")
            return
        encrypted = encrypt_message(text, sender_plain)
        dummy_text = random.choice(DUMMY_TEXTS)
        msg = await context.bot.send_message(chat_id=chat_id, text=dummy_text)  # No reply_to needed
        # UPDATED: Store for reveal via reply (with sender_id)
        chat_dummies = data.setdefault('dummies', {}).setdefault(str(chat_id), {})
        chat_dummies[msg.message_id] = {'enc': encrypted, 'sender_id': user_id}
        # NEW: Track active bot msgs for auto-trim (ordered list) (DELETE OLD MESSAGES)
        chat_active = data.setdefault('active_msgs', {}).setdefault(str(chat_id), [])
        chat_active.append(msg.message_id)
        # NEW: Trim to last 2: Delete oldest if >2
        if len(chat_active) > 2:
            oldest_id = chat_active.pop(0)
            try:
                await context.bot.delete_message(chat_id=chat_id, message_id=oldest_id)
                # Clean from dummies if still there (e.g., unrevealed)
                if oldest_id in chat_dummies:
                    del chat_dummies[oldest_id]
                logger.info(f"Trimmed old msg {oldest_id} in {chat_id} to keep last 2")
            except Exception as e:
                logger.warning(f"Failed to trim old msg {oldest_id} in {chat_id}: {e}")
                # Still pop from list to avoid stale tracking (END OF DELETE OLD)
        save_data(data)
        logger.info(f"Sent dummy for msg from {user_id} in {chat_id}")
        return

    # UPDATED: Fallback: If not auth'd sender and not reveal/setup, ignore (normal Telegram message stays)

# CHANGE PASSWORD -------------------- (UPDATED: Per-user, private DM only)
# Conversation handler for /changepass
OLD_PASS, NEW_PASS = range(2) # States for conversation: 0=old pass prompt, 1=new pass prompt

async def changepass_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    user_id = update.effective_user.id
    if chat.type != ChatType.PRIVATE:
        await update.message.reply_text("❌ /changepass only works in your private DM with me.")
        return ConversationHandler.END
    if not is_user_authenticated(user_id):
        await update.message.reply_text("❌ Set your passphrase first with /start.")
        return ConversationHandler.END
    await update.message.reply_text("🔐 Enter your current (old) passphrase to confirm:")
    return OLD_PASS # Go to OLD_PASS state

async def get_old_pass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()
    old_plain = get_user_plain(user_id)
    if text == old_plain:
        # Store old_pass in user_data for re-encryption later
        context.user_data['old_pass'] = text
        await update.message.reply_text("✅ Old pass correct. Now enter the new passphrase:")
        return NEW_PASS # Go to NEW_PASS state
    else:
        await update.message.reply_text("❌ Wrong old passphrase. /changepass to try again.")
        return ConversationHandler.END # Fail, end flow

async def get_new_pass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    new_pass = update.message.text.strip()
    if not new_pass:
        await update.message.reply_text("❌ Pass can't be empty. /changepass to retry.")
        return ConversationHandler.END
    # Re-encrypt *this user's* dummies with new pass
    old_pass = context.user_data.pop('old_pass', None)
    if old_pass:
        dummies = data.get('dummies', {})
        for ch_str, ch_dummies in list(dummies.items()):
            for m_id, dummy_data in list(ch_dummies.items()):
                if dummy_data['sender_id'] == user_id:  # Only this user's dummies
                    try:
                        plain = decrypt_message(dummy_data['enc'], old_pass)
                        if plain:
                            new_enc = encrypt_message(plain, new_pass)
                            dummy_data['enc'] = new_enc
                        else:
                            del ch_dummies[m_id]  # Couldn't decrypt old
                    except Exception as e:
                        logger.warning(f"Failed re-encrypt dummy {ch_str}:{m_id} for {user_id}: {e}")
                        del ch_dummies[m_id]
            if not ch_dummies:
                del dummies[ch_str]
        save_data(data)  # Save re-encrypted dummies first
        # Encrypt new pass for storage
        data.setdefault('user_passwords', {})[str(user_id)] = encrypt_storage_pass(new_pass, STORAGE_KEY)
        # Update cache with new plain
        user_plain_cache[user_id] = new_pass
    save_data(data)
    logger.info(f"Pass changed by user {user_id}")
    await update.message.reply_text("✅ Passphrase updated! Your dummies are re-encrypted. Share the new one with contacts if needed.")
    return ConversationHandler.END # End flow

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Change cancelled.")
    return ConversationHandler.END

# Build and add the handler
conv_handler = ConversationHandler(
    entry_points=[CommandHandler('changepass', changepass_start)],
    states={
        OLD_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_old_pass)],
        NEW_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_new_pass)],
    },
    fallbacks=[CommandHandler('cancel', cancel)],
)

# Flask App & Webhook Setup (adapted from your old script - no functional changes)
app = Flask(__name__)  # Flask instance
application = Application.builder().token(TOKEN).build()  # PTB instance

# Add handlers to PTB (same as before)
application.add_handler(CommandHandler("start", start))
application.add_handler(conv_handler)
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

# Global flag to ensure init once (like old script)
_initialized = False

def initialize_application():
    global _initialized
    if not _initialized:
        try:
            asyncio.run(application.initialize())
            asyncio.run(application.start())
            _initialized = True
            logger.info("PTB Application initialized and started!")  # Debug log
        except Exception as e:
            logger.exception("Failed to initialize PTB: %s", e)

# Initialize on load
initialize_application()

@app.route('/webhook', methods=['POST'])
def webhook():
    """Safe webhook wrapper: logs full exceptions so we can see why Telegram gets 500."""
    update_json = request.get_json(silent=True)
    logger.debug("Webhook received raw update: %s", update_json)
    try:
        update = Update.de_json(update_json, application.bot)
        # Run async processing in a new event loop (sync WSGI fix)
        asyncio.run(application.process_update(update))
        return 'OK', 200
    except Exception as e:
        logger.exception("Unhandled exception while handling /webhook: %s", e)
        return 'Internal Server Error', 500

@app.route('/')
def index():
    return f"{BOT_NAME} alive! Webhook ready."

# Run Flask (replaces polling - listens on PORT like old script)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)