BOT_NAME = 'test_raz_bot'
TOKEN = '8563748679:AAEPn_PS9UeMMp4IdKpCRXo-7ItPek4j_mM' # test key
import json
import logging
import os
import base64
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler, ConversationHandler
from telegram.constants import ChatAction
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import asyncio  # For safe async delete if needed (but sync works fine)
# Enable logging to see bot activity/errors (helps debugging)
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)
# JSON FILE STORE DATA ----------------- (now includes master_pass, owner_id, users, and dummies)
DATA_FILE = 'bot_data.json' # Renamed for clarity
# Load data from JSON (creates empty dict if file doesn't exist)
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {'master_pass': None, 'owner_id': None, 'users': {}, 'dummies': {}} # Default structure with dummies
# Save data to JSON
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)
# Load data at startup
data = load_data()
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
# START COMMAND ------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles /start: Sets up master pass if needed, then auth flow.
    """
    chat_id = update.effective_chat.id
    await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
    logger.info(f"Sent TYPING for /start from chat {chat_id}")
   
    # First-time setup check
    if data['master_pass'] is None:
        if data['owner_id'] is None: # Truly fresh: This user becomes owner
            data['owner_id'] = chat_id # This user is owner
            data.setdefault('users', {})[chat_id] = {'tries': 0}
            save_data(data)
            logger.info(f"First-time setup: Owner set to {chat_id}")
            # NEW: Flag setup state in user_data
            context.user_data['awaiting_set_pass'] = True
            await update.message.reply_text("🚀 First setup! Enter your master passphrase (keep it secret):")
            return # Next message will be treated as set_pass in handle_message
        else:
            await update.message.reply_text("❌ No master passphrase set. Contact the owner to initialize.")
            return
   
    # Master pass exists: Check auth
    users = data.get('users', {})
    data['users'] = users # Ensure it's saved back if new
    save_data(data)
   
    if chat_id in users and users[chat_id].get('authenticated', False):
        is_owner = chat_id == data['owner_id']
        msg = "Welcome back, Admin!" if not is_owner else "Welcome back, Owner Admin! (Future: Change pass here.)"
        await update.message.reply_text(msg)
        return
   
    # Unauthenticated: Reset tries, prompt for pass
    users.setdefault(chat_id, {'tries': 0})
    users[chat_id]['tries'] = 0 # Always reset on /start
    save_data(data)
    logger.info(f"Reset tries to 0 for chat {chat_id} on /start")
    await update.message.reply_text("🔐 Enter the master passphrase to authenticate as Admin:")
# MESSAGE HANDLER ----------------------
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles text: Reveal attempts (via reply to dummy), sets master pass (if first-time), auth attempts, or echoes (post-auth).
    """
    chat_id = update.effective_chat.id
    text = update.message.text.strip()
    await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
    logger.info(f"Received text: '{text}' from chat {chat_id}")
   
    users = data.get('users', {})
   
    # NEW: First, check for reveal attempt (reply to a dummy message)
    if update.message.reply_to_message and update.message.reply_to_message.from_user.id == context.bot.id:
        replied_msg = update.message.reply_to_message
        replied_msg_id = replied_msg.message_id
        chat_dummies = data.get('dummies', {}).get(str(chat_id), {})
        if replied_msg_id in chat_dummies:
            encrypted = chat_dummies[replied_msg_id]
            if text == data['master_pass']:
                # Correct passphrase: Decrypt, edit dummy to real, delete the passphrase reply (stealth)
                real_msg = decrypt_message(encrypted, text)
                if real_msg:
                    await context.bot.edit_message_text(
                        chat_id=chat_id,
                        message_id=replied_msg_id,
                        text=f"{real_msg} ✨ Revealed!"
                    )
                    # Remove from storage
                    del chat_dummies[replied_msg_id]
                    if not chat_dummies:
                        del data['dummies'][str(chat_id)]
                    save_data(data)
                    # Delete the passphrase reply to hide it
                    await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
                    logger.info(f"Revealed msg {replied_msg_id} in chat {chat_id}")
                    return
                else:
                    await update.message.reply_text("❌ Decrypt failed. Contact owner.")
                    return
            else:
                # Wrong passphrase: Do nothing (leave reply intact), continue to process as normal message
                logger.info(f"Wrong passphrase attempt for reveal in {chat_id}")
                # Fall through to normal handling below
    
    # NEW: Check for first-time setup (before auth logic)
    if context.user_data.get('awaiting_set_pass'):
        data['master_pass'] = text
        users.setdefault(chat_id, {'tries': 0})
        users[chat_id]['authenticated'] = True  # Owner is auto-auth'd
        save_data(data)
        del context.user_data['awaiting_set_pass']
        is_owner = chat_id == data['owner_id']
        msg = "✅ Master passphrase set! You are now authenticated as Owner Admin!" 
        logger.info(f"Set master pass for owner {chat_id}")
        await update.message.reply_text(msg + " (Future: Show menu here.)")
        return
   
    # Auth check (after setup)
    # if chat_id in users and users[chat_id].get('authenticated', False):
    #     # Post-auth: Encrypt & send plain dummy (no button!)
    #     encrypted = encrypt_message(text, data['master_pass'])
    #     dummy_text = "Hey there! 😊" # Plain text, looks innocent
    #     msg = await update.message.reply_text(dummy_text)  # No reply_markup
    #     # Store for reveal via reply
    #     chat_dummies = data.setdefault('dummies', {}).setdefault(str(chat_id), {})
    #     chat_dummies[msg.message_id] = encrypted
    #     save_data(data)
    #     logger.info(f"Sent dummy for msg in {chat_id}")
    #     return
   

    # Auth check (after setup)
    if chat_id in users and users[chat_id].get('authenticated', False):
        # NEW: Silently delete the user's real sent message (hides "outgoing")
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
            logger.info(f"Deleted sent msg {update.message.message_id} in {chat_id}")
        except Exception as e:
            logger.warning(f"Failed to delete sent msg in {chat_id}: {e}")  # Fallback: msg stays, but rare
        
        # Post-auth: Encrypt & send plain dummy (no button!) as "sent" placeholder
        encrypted = encrypt_message(text, data['master_pass'])
        dummy_text = "Hey there! 😊" # Plain text, looks innocent
        msg = await update.message.reply_text(dummy_text)  # Reply to deleted? Nah—reply_text without reply_to is fine, threads to chat
        # Store for reveal via reply
        chat_dummies = data.setdefault('dummies', {}).setdefault(str(chat_id), {})
        chat_dummies[msg.message_id] = encrypted
        save_data(data)
        logger.info(f"Sent dummy for msg in {chat_id}")
        return




    # Ensure user entry
    users.setdefault(chat_id, {'tries': 0})
   
    # Auth attempt: Compare to saved master_pass
    if text == data['master_pass']:
        users[chat_id]['authenticated'] = True
        users[chat_id]['tries'] = 0
        save_data(data)
        is_owner = chat_id == data['owner_id']
        msg = "✅ Authenticated as Admin!" if not is_owner else "✅ Authenticated as Owner Admin!"
        logger.info(f"Authenticated {chat_id} ({'Owner' if is_owner else 'User'})")
        await update.message.reply_text(msg + " (Future: Show menu here.)")
    else:
        users[chat_id]['tries'] += 1
        tries = users[chat_id]['tries']
        save_data(data)
        logger.info(f"Failed attempt {tries} for {chat_id}")
       
        if tries >= 3:
            await update.message.reply_text("❌ Too many failed attempts. Contact the owner to resolve.")
        else:
            await update.message.reply_text(f"❌ Wrong passphrase. {3 - tries} tries left.")
# CHANGE PASSWORD --------------------
# Conversation handler for /changepass
OLD_PASS, NEW_PASS = range(2) # States for conversation: 0=old pass prompt, 1=new pass prompt
async def changepass_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if chat_id != data['owner_id']:
        await update.message.reply_text("❌ Only the owner can change the master passphrase.")
        return ConversationHandler.END
    await update.message.reply_text("🔐 Enter your current (old) master passphrase to confirm:")
    return OLD_PASS # Go to OLD_PASS state
async def get_old_pass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if text == data['master_pass']:
        # NEW: Store old_pass in user_data for re-encryption later
        context.user_data['old_pass'] = text
        await update.message.reply_text("✅ Old pass correct. Now enter the new master passphrase:")
        return NEW_PASS # Go to NEW_PASS state
    else:
        await update.message.reply_text("❌ Wrong old passphrase. /changepass to try again.")
        return ConversationHandler.END # Fail, end flow
async def get_new_pass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    new_pass = update.message.text.strip()
    if not new_pass:
        await update.message.reply_text("❌ Pass can't be empty. /changepass to retry.")
        return ConversationHandler.END
    # NEW: Re-encrypt all dummies with new pass before updating
    old_pass = context.user_data.pop('old_pass', None)
    if old_pass:
        dummies = data.get('dummies', {})
        for ch_str, ch_dummies in list(dummies.items()):
            for m_id, enc in list(ch_dummies.items()):
                try:
                    plain = decrypt_message(enc, old_pass)
                    if plain:
                        new_enc = encrypt_message(plain, new_pass)
                        ch_dummies[m_id] = new_enc
                    else:
                        del ch_dummies[m_id]  # Couldn't decrypt old
                except Exception as e:
                    logger.warning(f"Failed re-encrypt dummy {ch_str}:{m_id}: {e}")
                    del ch_dummies[m_id]
            if not ch_dummies:
                del dummies[ch_str]
        save_data(data)  # Save re-encrypted dummies first
    # Update pass and invalidate auth
    data['master_pass'] = new_pass
    for user in data.get('users', {}).values():
        user['authenticated'] = False # Force re-auth for everyone
    save_data(data)
    logger.info(f"Pass changed by owner {update.effective_chat.id}")
    await update.message.reply_text("✅ Master passphrase updated! All users must re-authenticate.")
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
def main():
    """Main: Sets up and runs bot."""
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(conv_handler)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    # REMOVED: No more reveal_callback since no buttons
    logger.info("Bot starting... Delete bot_data.json for fresh setup!")
    app.run_polling(drop_pending_updates=True, timeout=10, poll_interval=0.5, allowed_updates=Update.ALL_TYPES)
if __name__ == '__main__':
    main()