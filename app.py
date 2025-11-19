import logging
import os
from flask import Flask, request
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Bot
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import json  # For simple storage

app = Flask(__name__)
TOKEN = '8532570108:AAFK4Rfzx0KLYIX75v3I_k-nRZThc1qPs9g'  # From BotFather
bot = Bot(TOKEN)
application = Application.builder().token(TOKEN).bot(bot).build()

# Simple storage (file-based, encrypted later if needed)
STORAGE_FILE = 'bot_data.json'
def load_data():
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, 'r') as f:
            return json.load(f)
    return {'active_pass': None, 'owner_id': None}

def save_data(data):
    with open(STORAGE_FILE, 'w') as f:
        json.dump(data, f)

data = load_data()

# Crypto helpers
def derive_key(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_message(message: str, password: str):
    key, salt = derive_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    combined = base64.b64encode(salt + nonce + ciphertext).decode('utf-8')
    return combined, salt  # Return salt for potential storage

def decrypt_message(encrypted: str, password: str):
    try:
        combined = base64.b64decode(encrypted)
        salt = combined[:16]
        nonce = combined[16:28]
        ciphertext = combined[28:]
        key, _ = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
        return plaintext
    except:
        return None

# Admin check
async def is_owner(user_id):
    if data['owner_id'] is None:
        data['owner_id'] = user_id
        save_data(data)
        return True
    return user_id == data['owner_id']

# Start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if await is_owner(user_id):
        keyboard = [[InlineKeyboardButton("🔐 Set Master Pass", callback_data="set_pass")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("🔒 Admin Panel: You're the owner. Set your first pass!", reply_markup=reply_markup)
    else:
        await update.message.reply_text("🔒 Welcome! Type messages and tap 🔒 to encrypt. Unlock with shared pass.")

# Button callbacks
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data_ = query.data

    if data_ == "set_pass":
        if not await is_owner(user_id):
            await query.edit_message_text("❌ Owner only.")
            return
        await query.message.reply_text("Enter new master pass:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel")]]))
        context.user_data['waiting_for'] = 'set_pass'
        return

    elif data_ == "encrypt_this":
        # Assume this is triggered after message - store msg_id in context or pass via data
        # For simplicity, we'll use force reply in message handler
        await query.edit_message_text("🔒 Confirm pass to lock:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel")]]))
        context.user_data['waiting_for'] = 'confirm_encrypt'
        return

    elif data_ == "unlock_packet":
        await query.message.reply_text("Enter unlock pass:")
        context.user_data['waiting_for'] = 'unlock_pass'
        return

    # Add more as needed

# Message handler for plaintext (auto-button) and force replies
async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    msg_text = update.message.text
    if context.user_data.get('waiting_for') == 'set_pass':
        new_pass = msg_text
        if new_pass:
            data['active_pass'] = new_pass  # In real, hash it
            save_data(data)
            await update.message.reply_text("✅ Pass set! Share OOB.")
        context.user_data['waiting_for'] = None
        return

    if context.user_data.get('waiting_for') == 'confirm_encrypt':
        pass_confirm = msg_text
        if data['active_pass'] and pass_confirm == data['active_pass']:
            # Get the original message - for demo, assume last msg or pass msg_id
            # Simplified: Encrypt a placeholder
            encrypted, _ = encrypt_message("Demo secret", data['active_pass'])
            packet_text = f"🔒 Secure Packet [ID:{secrets.randbits(16)}]"
            await update.message.reply_text(packet_text)
            await update.message.reply_text("✅ Locked!", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔓 Unlock", callback_data="unlock_packet")]]))
        else:
            await update.message.reply_text("❌ Pass mismatch.")
        context.user_data['waiting_for'] = None
        return

    # Auto-button for plaintext
    if msg_text and not msg_text.startswith('🔒'):  # Not a packet
        keyboard = [[InlineKeyboardButton("🔒 Encrypt This", callback_data="encrypt_this"), InlineKeyboardButton("Skip", callback_data="skip")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Want to lock this?", reply_markup=reply_markup)

# For packets - detect in message handler if starts with 🔒
    if msg_text and msg_text.startswith('🔒'):
        keyboard = [[InlineKeyboardButton("🔓 Unlock Packet", callback_data="unlock_packet")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Incoming secure—unlock?", reply_markup=reply_markup)

# Add handlers
application.add_handler(CommandHandler("start", start))
application.add_handler(CallbackQueryHandler(button_handler))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

# Webhook
@app.route('/webhook', methods=['POST'])
def webhook():
    update = Update.de_json(request.get_json(), bot)
    application.process_update(update)
    return 'OK'

@app.route('/')
def index():
    return "razdar alive! Set webhook to /webhook."

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)