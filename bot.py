import os
import logging
import socket
import requests
import whois
import asyncio
import ipaddress
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from flask import Flask

# إعداد تطبيق Flask للصحة فقط (للتشغيل على Railway/Heroku)
app = Flask(__name__)

@app.route('/')
def home():
    return "🤖 البوت يعمل بشكل صحيح", 200

@app.route('/health')
def health():
    return "✅ OK", 200

def run_flask():
    """تشغيل Flask في الخلفية"""
    import threading
    thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False))
    thread.daemon = True
    thread.start()

# باقي الكود كما هو...
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    raise ValueError("❌ لم يتم تعيين TELEGRAM_BOT_TOKEN")

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# CDN ranges (نفس الكود السابق)
CDN_RANGES = {
    'Cloudflare': ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22'],
    'CloudFront (AWS)': ['13.32.0.0/15', '13.35.0.0/16', '18.64.0.0/14', '52.46.0.0/18'],
    'Akamai': ['23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14', '104.64.0.0/10'],
    'Fastly': ['23.235.32.0/20', '151.101.0.0/16', '199.27.72.0/21', '199.232.0.0/16'],
    'Google Cloud': ['8.34.0.0/19', '34.0.0.0/15', '35.184.0.0/13', '104.154.0.0/15'],
    'Microsoft Azure': ['13.64.0.0/11', '20.0.0.0/10', '40.64.0.0/10', '52.96.0.0/12'],
    'OVH': ['5.135.0.0/16', '37.59.0.0/16', '91.121.0.0/16', '188.165.0.0/16']
}

def identify_cdn(ip_range):
    try:
        ip_net = ipaddress.ip_network(ip_range, strict=False)
        for cdn_name, ranges in CDN_RANGES.items():
            for cdn_range in ranges:
                cdn_net = ipaddress.ip_network(cdn_range, strict=False)
                if ip_net.subnet_of(cdn_net):
                    return cdn_name
        return 'غير معروف'
    except:
        return 'غير معروف'

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = """
🌐 **بوت نطاقات IP مع CDN**

أرسل لي أي نطاق وسأعطيك نطاقات IP مع معلومات CDN

⚡ **مثال:** `google.com`
    """
    await update.message.reply_text(welcome_text)

def get_asn_from_ip(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            org = data.get('org', '')
            if org and 'AS' in org:
                asn_part = org.split(' ')[0]
                asn_number = asn_part.replace('AS', '')
                if asn_number.isdigit():
                    return [{
                        'asn': asn_number,
                        'name': ' '.join(org.split(' ')[1:]) if len(org.split(' ')) > 1 else 'غير معروف',
                        'country_code': data.get('country', 'غير معروف')
                    }]
    except:
        pass
    return None

def get_prefixes_for_asn(asn_number):
    try:
        url = f"https://api.bgpview.io/asn/{asn_number}/prefixes"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                ipv4_prefixes = data.get('data', {}).get('ipv4_prefixes', [])
                return [prefix['prefix'] for prefix in ipv4_prefixes]
        return []
    except Exception as e:
        logger.error(f"Error getting prefixes for ASN {asn_number}: {e}")
        return []

def get_ip_info(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return {'ip': ip_address, 'error': None}
    except Exception as e:
        return {'error': f"خطأ في الحصول على IP: {str(e)}"}

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_message = update.message.text.strip()
    
    if user_message.startswith('/'):
        return
    
    await update.message.reply_chat_action(action="typing")
    
    try:
        hostname = user_message.lower()
        if '://' in hostname:
            hostname = hostname.split('://')[1]
        if '/' in hostname:
            hostname = hostname.split('/')[0]
        
        ip_info = get_ip_info(hostname)
        if ip_info['error']:
            await update.message.reply_text(f"❌ {ip_info['error']}")
            return
        
        main_ip = ip_info['ip']
        
        message = f"🔍 **تحليل:** `{hostname}`\n📍 **IP:** `{main_ip}`\n\n"
        await update.message.reply_text(message)
        
        asns = get_asn_from_ip(main_ip)
        
        if not asns:
            await update.message.reply_text("❌ لم أتمكن من تحديد ASN")
            return
        
        for asn in asns:
            asn_number = asn['asn']
            asn_name = asn['name']
            
            message = f"🏢 **AS{asn_number}**: {asn_name}\n"
            message += "🔄 **جاري جلب النطاقات...**"
            await update.message.reply_text(message)
            
            prefixes = get_prefixes_for_asn(asn_number)
            
            if prefixes:
                info_message = f"📊 **تم العثور على {len(prefixes)} نطاق:**\n\n"
                await update.message.reply_text(info_message)
                
                cdn_groups = {}
                for prefix in prefixes:
                    cdn = identify_cdn(prefix)
                    if cdn not in cdn_groups:
                        cdn_groups[cdn] = []
                    cdn_groups[cdn].append(prefix)
                
                for cdn_name, cdn_prefixes in cdn_groups.items():
                    cdn_message = f"🛡️ **{cdn_name}** ({len(cdn_prefixes)} نطاق):\n\n"
                    
                    for ip_range in cdn_prefixes[:8]:
                        cdn_message += f"`{ip_range}`\n"
                    
                    if len(cdn_prefixes) > 8:
                        cdn_message += f"📈 ... و {len(cdn_prefixes) - 8} أكثر\n"
                    
                    await update.message.reply_text(cdn_message)
                    await asyncio.sleep(0.3)
            else:
                await update.message.reply_text(f"❌ لا توجد نطاقات مسجلة")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await update.message.reply_text(f"❌ حدث خطأ: {str(e)}")

async def asn_search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ يرجى كتابة رقم ASN\nمثال: `/asn 15169`")
        return
    
    asn_number = context.args[0]
    await update.message.reply_chat_action(action="typing")
    
    try:
        prefixes = get_prefixes_for_asn(asn_number)
        
        if prefixes:
            message = f"📊 **نطاقات AS{asn_number}:** {len(prefixes)} نطاق\n\n"
            
            cdn_groups = {}
            for prefix in prefixes:
                cdn = identify_cdn(prefix)
                if cdn not in cdn_groups:
                    cdn_groups[cdn] = []
                cdn_groups[cdn].append(prefix)
            
            for cdn_name, cdn_prefixes in cdn_groups.items():
                message += f"🛡️ **{cdn_name}:**\n"
                for ip_range in cdn_prefixes[:5]:
                    message += f"`{ip_range}`\n"
                message += "\n"
            
            await update.message.reply_text(message)
        else:
            await update.message.reply_text("❌ لا توجد نطاقات")
            
    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ: {str(e)}")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"حدث خطأ: {context.error}")

def main():
    # تشغيل Flask للصحة (للتشغيل على السحابة)
    run_flask()
    
    try:
        application = Application.builder().token(TOKEN).build()
        
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("asn", asn_search))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        application.add_error_handler(error_handler)
        
        print("🤖 البوت يعمل بشكل مستمر...")
        application.run_polling()
        
    except Exception as e:
        print(f"❌ فشل تشغيل البوت: {e}")

if __name__ == '__main__':
    main()
