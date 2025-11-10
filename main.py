import logging
import socket
import requests
import whois
import asyncio
import ipaddress
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# إعداد التوكن
TOKEN = "8509325639:AAFe85hfq7kAtIwfyLLFJMMhr_gnzGRbx3E"

# إعداد التسجيل
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# قاعدة بيانات CDN المعروفة
CDN_RANGES = {
    'Cloudflare': [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
    ],
    'CloudFront (AWS)': [
        '13.32.0.0/15', '13.35.0.0/16', '13.248.118.0/24', '18.64.0.0/14',
        '18.68.0.0/16', '18.160.0.0/15', '52.46.0.0/18', '52.84.0.0/15',
        '52.124.128.0/17', '52.212.248.0/26', '52.222.128.0/17', '54.182.0.0/16',
        '54.192.0.0/16', '54.230.0.0/16', '54.239.128.0/18', '54.239.192.0/19',
        '70.132.0.0/18', '71.152.0.0/17', '99.84.0.0/16', '99.86.0.0/16',
        '120.52.22.96/27', '120.253.240.192/26', '130.176.0.0/17', '143.204.0.0/16',
        '144.220.0.0/16', '180.163.57.0/25', '204.246.164.0/22', '204.246.168.0/22',
        '204.246.174.0/23', '204.246.176.0/20', '205.251.200.0/21', '205.251.249.0/24',
        '216.137.32.0/19'
    ],
    'Akamai': [
        '23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14', '23.72.0.0/13',
        '23.192.0.0/11', '72.246.0.0/15', '88.221.0.0/16', '96.6.0.0/15',
        '104.64.0.0/10', '173.222.0.0/15', '184.24.0.0/13', '184.50.0.0/15',
        '184.84.0.0/14', '2.16.0.0/13', '95.100.0.0/15'
    ],
    'Fastly': [
        '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '108.162.192.0/18',
        '118.214.0.0/16', '151.101.0.0/16', '157.52.0.0/16', '172.111.0.0/16',
        '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16'
    ],
    'Google Cloud': [
        '8.34.0.0/19', '8.35.0.0/19', '23.236.48.0/20', '23.251.128.0/19',
        '34.0.0.0/15', '34.2.0.0/16', '34.16.0.0/12', '34.32.0.0/11',
        '34.64.0.0/10', '34.128.0.0/10', '35.184.0.0/13', '35.192.0.0/14',
        '35.196.0.0/15', '35.198.0.0/16', '35.199.0.0/17', '35.199.128.0/18',
        '35.200.0.0/13', '35.208.0.0/12', '35.224.0.0/12', '104.154.0.0/15',
        '104.196.0.0/14', '107.167.160.0/19', '107.178.192.0/18', '108.59.80.0/20',
        '130.211.0.0/16', '146.148.0.0/17', '162.216.148.0/22', '162.222.176.0/21',
        '172.110.32.0/21', '172.217.0.0/16', '172.253.0.0/16', '173.255.112.0/20',
        '192.158.28.0/22', '199.192.112.0/22', '199.223.232.0/21', '208.65.152.0/22',
        '208.68.36.0/22', '208.81.188.0/22', '209.85.128.0/17', '216.58.0.0/16',
        '216.239.32.0/19'
    ],
    'Microsoft Azure': [
        '13.64.0.0/11', '13.96.0.0/13', '13.104.0.0/14', '20.0.0.0/10',
        '20.32.0.0/12', '20.48.0.0/13', '20.56.0.0/14', '20.60.0.0/16',
        '20.150.0.0/15', '40.64.0.0/10', '52.96.0.0/12', '65.52.0.0/14',
        '94.245.64.0/18', '104.40.0.0/13', '104.146.0.0/16', '104.208.0.0/13',
        '137.116.0.0/15', '137.135.0.0/16', '138.91.0.0/16', '151.206.0.0/16',
        '157.55.0.0/16', '168.61.0.0/16', '168.62.0.0/15', '191.232.0.0/13',
        '193.149.64.0/19', '199.30.16.0/20', '207.46.0.0/16'
    ],
    'OVH': [
        '5.135.0.0/16', '5.196.0.0/16', '8.33.137.0/24', '37.59.0.0/16',
        '46.105.0.0/16', '51.254.0.0/16', '51.255.0.0/16', '54.36.0.0/16',
        '87.98.128.0/17', '91.121.0.0/16', '92.222.0.0/16', '93.118.0.0/16',
        '137.74.0.0/16', '145.239.0.0/16', '147.135.0.0/16', '164.132.0.0/16',
        '167.114.0.0/16', '176.31.0.0/16', '178.32.0.0/15', '185.15.0.0/16',
        '188.165.0.0/16', '192.95.0.0/16', '193.70.0.0/16', '194.177.0.0/16',
        '195.154.0.0/16', '198.27.0.0/16', '198.50.0.0/16', '198.100.0.0/16'
    ]
}

# دالة للتعرف على CDN من نطاق IP
def identify_cdn(ip_range):
    try:
        ip_net = ipaddress.ip_network(ip_range, strict=False)
        
        for cdn_name, ranges in CDN_RANGES.items():
            for cdn_range in ranges:
                cdn_net = ipaddress.ip_network(cdn_range, strict=False)
                if ip_net.subnet_of(cdn_net) or cdn_net.subnet_of(ip_net) or ip_net.overlaps(cdn_net):
                    return cdn_name
        
        # إذا لم نجد تطابق كامل، نتحقق من التطابق الجزئي
        ip_parts = str(ip_net.network_address).split('.')
        if len(ip_parts) >= 2:
            ip_base = f"{ip_parts[0]}.{ip_parts[1]}"
            
            # تحقق من نطاقات AWS
            if ip_base in ['13.32', '13.35', '18.64', '52.46', '52.84', '54.182', '54.192']:
                return 'CloudFront (AWS)'
            elif ip_base in ['8.34', '8.35', '23.236', '34.0', '35.184', '104.154']:
                return 'Google Cloud'
            elif ip_base in ['13.64', '20.0', '40.64', '52.96', '104.40']:
                return 'Microsoft Azure'
            elif ip_base in ['23.0', '23.32', '23.64', '104.64']:
                return 'Akamai'
            elif ip_base in ['173.245', '103.21', '141.101', '108.162']:
                return 'Cloudflare'
        
        return 'غير معروف'
    except:
        return 'غير معروف'

# دالة البدء
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = """
🌐 **بوت نطاقات IP مع تحديد CDN**

أرسل لي أي نطاق وسأعطيك:
• نطاقات IP الخاصة به
• معلومات CDN لكل نطاق
• معلومات ASN

مثال:
`three.co.uk`
`google.com`
`microsoft.com`
    """
    await update.message.reply_text(welcome_text)

# الحصول على ASN من IP مباشرة
def get_asn_from_ip(ip):
    try:
        # استخدام ipinfo.io
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
                        'description': org,
                        'country_code': data.get('country', 'غير معروف')
                    }]
    except:
        pass
    
    try:
        # استخدام ipapi.co كبديل
        url = f"http://ipapi.co/{ip}/json/"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            asn = data.get('asn')
            if asn:
                asn_number = asn.replace('AS', '')
                if asn_number.isdigit():
                    return [{
                        'asn': asn_number,
                        'name': data.get('org', 'غير معروف'),
                        'description': data.get('org', ''),
                        'country_code': data.get('country', 'غير معروف')
                    }]
    except:
        pass
    
    return None

# الحصول على نطاقات ASN من BGPView
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

# الحصول على معلومات IP الأساسية
def get_ip_info(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return {
            'ip': ip_address,
            'error': None
        }
    except Exception as e:
        return {'error': f"خطأ في الحصول على IP: {str(e)}"}

# المعالجة الرئيسية للمرسائل
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_message = update.message.text.strip()
    
    if user_message.startswith('/'):
        return
    
    await update.message.reply_chat_action(action="typing")
    
    try:
        # تنظيف المدخلات
        hostname = user_message.lower()
        if '://' in hostname:
            hostname = hostname.split('://')[1]
        if '/' in hostname:
            hostname = hostname.split('/')[0]
        
        # الحصول على معلومات IP الأساسية
        ip_info = get_ip_info(hostname)
        if ip_info['error']:
            await update.message.reply_text(f"❌ {ip_info['error']}")
            return
        
        main_ip = ip_info['ip']
        
        message = f"🔍 **تحليل الشبكة ل:** `{hostname}`\n"
        message += f"📍 **IP الأساسي:** `{main_ip}`\n\n"
        
        await update.message.reply_text(message)
        
        # الحصول على ASN من IP المحدد
        asns = get_asn_from_ip(main_ip)
        
        if not asns:
            await update.message.reply_text("❌ لم أتمكن من تحديد ASN لهذا النطاق")
            return
        
        # معالجة كل ASN وجلب نطاقاته
        for asn in asns:
            asn_number = asn['asn']
            asn_name = asn['name']
            
            message = f"🏢 **AS{asn_number}**: {asn_name}\n"
            message += f"🌍 **البلد:** {asn.get('country_code', 'غير معروف')}\n\n"
            message += "🔄 **جاري جلب النطاقات وتحديد CDN...**"
            
            await update.message.reply_text(message)
            
            # الحصول على نطاقات هذا ASN المحدد
            prefixes = get_prefixes_for_asn(asn_number)
            
            if prefixes:
                # عرض معلومات النطاقات
                info_message = f"📊 **تم العثور على {len(prefixes)} نطاق لـ AS{asn_number}:**\n\n"
                await update.message.reply_text(info_message)
                
                # تجميع النطالات حسب CDN
                cdn_groups = {}
                for prefix in prefixes:
                    cdn = identify_cdn(prefix)
                    if cdn not in cdn_groups:
                        cdn_groups[cdn] = []
                    cdn_groups[cdn].append(prefix)
                
                # عرض النطاقات مجمعة حسب CDN
                for cdn_name, cdn_prefixes in cdn_groups.items():
                    if cdn_name == 'غير معروف':
                        continue
                    
                    cdn_message = f"🛡️ **{cdn_name}** ({len(cdn_prefixes)} نطاق):\n\n"
                    
                    chunk_size = 15
                    for i in range(0, len(cdn_prefixes), chunk_size):
                        chunk = cdn_prefixes[i:i + chunk_size]
                        
                        for ip_range in chunk:
                            cdn_message += f"`{ip_range}`\n"
                        
                        if len(cdn_prefixes) > chunk_size and i + chunk_size < len(cdn_prefixes):
                            cdn_message += f"📈 ... والمزيد\n"
                            break
                    
                    await update.message.reply_text(cdn_message)
                    await asyncio.sleep(0.3)
                
                # عرض النطاقات غير المعروفة
                if 'غير معروف' in cdn_groups and cdn_groups['غير معروف']:
                    unknown_message = f"❓ **نطاقات غير معروفة** ({len(cdn_groups['غير معروف'])} نطاق):\n\n"
                    
                    chunk_size = 20
                    for i in range(0, len(cdn_groups['غير معروف']), chunk_size):
                        chunk = cdn_groups['غير معروف'][i:i + chunk_size]
                        
                        for ip_range in chunk:
                            unknown_message += f"`{ip_range}`\n"
                        
                        await update.message.reply_text(unknown_message)
                        
                        if i + chunk_size < len(cdn_groups['غير معروف']):
                            unknown_message = f"❓ **استكمال النطاقات غير المعروفة:**\n\n"
                            await asyncio.sleep(0.3)
            else:
                await update.message.reply_text(f"❌ لا توجد نطاقات مسجلة لـ AS{asn_number}")
        
    except Exception as e:
        logger.error(f"Error in handle_message: {e}")
        error_message = f"❌ حدث خطأ أثناء المعالجة: {str(e)}"
        await update.message.reply_text(error_message)

# أمر للبحث المباشر عن ASN
async def asn_search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ يرجى كتابة رقم ASN\nمثال: `/asn 15169` لجوجل")
        return
    
    asn_number = context.args[0]
    if not asn_number.isdigit():
        await update.message.reply_text("❌ يرجى إدخال رقم ASN صحيح")
        return
    
    await update.message.reply_chat_action(action="typing")
    
    try:
        message = f"🔍 **جاري البحث عن AS{asn_number}...**"
        await update.message.reply_text(message)
        
        # الحصول على معلومات ASN
        url = f"https://api.bgpview.io/asn/{asn_number}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                asn_data = data['data']
                
                info_message = f"🏢 **AS{asn_number}**: {asn_data.get('name', 'غير معروف')}\n"
                info_message += f"📝 **الوصف:** {asn_data.get('description', '')}\n"
                info_message += f"🌍 **البلد:** {asn_data.get('country_code', 'غير معروف')}\n"
                
                await update.message.reply_text(info_message)
                
                # الحصول على النطاقات
                prefixes = get_prefixes_for_asn(asn_number)
                
                if prefixes:
                    total_message = f"📊 **تم العثور على {len(prefixes)} نطاق:**\n\n"
                    await update.message.reply_text(total_message)
                    
                    # تجميع حسب CDN وعرضها
                    cdn_groups = {}
                    for prefix in prefixes:
                        cdn = identify_cdn(prefix)
                        if cdn not in cdn_groups:
                            cdn_groups[cdn] = []
                        cdn_groups[cdn].append(prefix)
                    
                    # عرض النطاقات مع CDN
                    for cdn_name, cdn_prefixes in cdn_groups.items():
                        cdn_msg = f"🛡️ **{cdn_name}** - {len(cdn_prefixes)} نطاق:\n\n"
                        
                        for ip_range in cdn_prefixes[:10]:  # عرض أول 10 نطاقات لكل CDN
                            cdn_msg += f"`{ip_range}`\n"
                        
                        if len(cdn_prefixes) > 10:
                            cdn_msg += f"📈 ... و {len(cdn_prefixes) - 10} أكثر\n"
                        
                        await update.message.reply_text(cdn_msg)
                        await asyncio.sleep(0.3)
                else:
                    await update.message.reply_text("❌ لا توجد نطاقات مسجلة لهذا ASN")
            else:
                await update.message.reply_text("❌ ASN غير موجود")
        else:
            await update.message.reply_text("❌ خطأ في الاتصال بالخادم")
            
    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ: {str(e)}")

# أمر لفحص CDN لنطاق معين
async def cdn_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ يرجى كتابة نطاق IP\nمثال: `/cdn 8.8.8.8` أو `/cdn 192.168.1.0/24`")
        return
    
    ip_range = context.args[0]
    
    await update.message.reply_chat_action(action="typing")
    
    try:
        cdn = identify_cdn(ip_range)
        
        message = f"🔍 **فحص CDN للنطاق:** `{ip_range}`\n\n"
        message += f"🛡️ **مزود CDN:** {cdn}\n\n"
        
        if cdn != 'غير معروف':
            message += "✅ هذا النطاق يستخدم خدمة CDN معروفة\n"
        else:
            message += "❓ لم يتم التعرف على مزود CDN لهذا النطاق\n"
            message += "💡 قد يكون النطاق مملوكاً للشركة مباشرة\n"
        
        await update.message.reply_text(message)
        
    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ: {str(e)}")

# أمر لعرض جميع مزودي CDN المعروفين
async def cdns_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = "🛡️ **مزودو CDN المعروفون في النظام:**\n\n"
    
    for cdn_name in CDN_RANGES.keys():
        message += f"• {cdn_name}\n"
    
    message += f"\n📊 **إجمالي:** {len(CDN_RANGES)} مزود CDN\n"
    message += "💡 استخدم `/cdncheck` للتحقق من نطاق معين"
    
    await update.message.reply_text(message)

# دالة للتعامل مع الأخطاء
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"حدث خطأ: {context.error}")
    try:
        await update.message.reply_text("❌ حدث خطأ غير متوقع. يرجى المحاولة مرة أخرى.")
    except:
        pass

# الدالة الرئيسية
def main():
    try:
        application = Application.builder().token(TOKEN).build()
        
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("asn", asn_search))
        application.add_handler(CommandHandler("cdn", cdn_check))
        application.add_handler(CommandHandler("cdns", cdns_list))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        application.add_error_handler(error_handler)
        
        print("🤖 البوت مع CDN يعمل الآن...")
        application.run_polling()
        
    except Exception as e:
        print(f"❌ فشل تشغيل البوت: {e}")

if __name__ == '__main__':
    main()
