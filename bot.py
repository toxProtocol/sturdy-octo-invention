import os
from importlib import import_module

import requests
import re
import ipaddress
import time
import logging
import telethon
import urllib3
import moudle(" ")
import bot("dotenv").load_dotenv(
    dotenv_path='.env'
)
from tele import TeleBot
import telebot.types

# Loading sensitive credentials securely from environment variables
API_TOKEN = os.getenv('7676557478:AAFs1ieOa2FkbWplKeDIggQR95x-0n6MQzE')
NEWS_API_KEY = os.getenv('b9ce2579-e386-4ead-a2ce-7aa4c3f93e30')
HIBP_API_KEY = os.getenv('f8e395da146640af9b039ae37fcd2095')
WHOIS_API_KEY = os.getenv('5543|SFuO7bfti3eAxWxybFnDDdKn47D8K2kuiyQZvkWC')
IPINFO_API_KEY = os.getenv('30c0ce81a3')
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?resultsPerPage=20&startIndex=0'
CTFTIME_API_URL = 'https://ctftime.org/api/v1/events/'

bot = TeleBot(API_TOKEN)

# Initialize logging for error tracking
logging.basicConfig(level=logging.INFO)

class RateLimiter:
    """Rate limiter to control API request flow."""
    def __init__(self, rate):
        self.rate = rate
        self.last_call = time.time()

    def wait(self):
        elapsed = time.time() - self.last_call
        if elapsed < self.rate:
            time.sleep(self.rate - elapsed)
        self.last_call = time.time()

limiter = RateLimiter(1)  # 1 request per second

# Helper function to make API requests securely and handle errors
def api_request(url, headers=None):
    try:
        limiter.wait()
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.Timeout:
        return {"error": "Request timed out."}
    except requests.HTTPError as http_err:
        return {"error": f"HTTP error: {http_err}"}
    except requests.RequestException as req_err:
        return {"error": f"Request error: {req_err}"}

# Command: /start - Welcome message
@bot.message_handler(commands=['start'])
def send_welcome(message):
    welcome_message = (
        "👋 Welcome to **Sentinel Ops - Defence**!\n"
        "Your advanced cybersecurity assistant for real-time threat intelligence, vulnerability tracking, "
        "and OSINT tools.\n\n"
        "Type /help to see all available commands."
    )
    bot.reply_to(message, welcome_message)

# Command: /help - Display commands with inline buttons
@bot.message_handler(commands=['help'])
def send_help(message):
    markup = telebot.types.InlineKeyboardMarkup()
    markup.add(telebot.types.InlineKeyboardButton("🔐 Latest News", callback_data="news"))
    markup.add(telebot.types.InlineKeyboardButton("📂 View Vulnerabilities", callback_data="vulns"))
    markup.add(telebot.types.InlineKeyboardButton("💾 View Data Breaches", callback_data="breaches"))
    markup.add(telebot.types.InlineKeyboardButton("🌐 Perform WHOIS Lookup", callback_data="whois"))
    markup.add(telebot.types.InlineKeyboardButton("📍 Geolocate IP", callback_data="ip"))
    markup.add(telebot.types.InlineKeyboardButton("🏆 View CTF Competitions", callback_data="ctf"))
    
    help_text = """
**Available Commands:**
- /start - Introduction message
- /help - Display this command menu
- /breaches - View recent data breaches
- /news - Get the latest cybersecurity news
- /vulns - View recent vulnerabilities (CVEs)
- /whois [domain] - Perform WHOIS lookup for a domain
- /ip [address] - Geolocate an IP address
- /status - Get device/network information
- /feedback - Provide feedback to developers
- /ctf - List ongoing CTF competitions
- /about - Information about Sentinel Ops - Defence
"""
    bot.reply_to(message, help_text, reply_markup=markup)

# Command: /news - Fetch latest cybersecurity news
@bot.message_handler(commands=['news'])
def get_news(message):
    url = f'https://newsapi.org/v2/everything?q=cybersecurity&apiKey={NEWS_API_KEY}'
    news_data = api_request(url)
    if "error" in news_data:
        bot.reply_to(message, news_data['error'])
        return
    
    news_message = "📰 **Latest Cybersecurity News:**\n\n"
    for article in news_data.get('articles', [])[:5]:
        news_message += f"🔸 {article['title']}\n🔗 {article['url']}\n\n"
    bot.reply_to(message, news_message)

# Command: /vulns - View recent vulnerabilities (CVEs) from NVD API
@bot.message_handler(commands=['vulns'])
def get_vulns(message):
    vuln_data = api_request(NVD_API_URL)
    if "error" in vuln_data:
        bot.reply_to(message, vuln_data['error'])
        return
    
    vuln_message = "🛡 **Latest Vulnerabilities (CVEs):**\n\n"
    for item in vuln_data['result']['CVE_Items'][:5]:
        cve_id = item['cve']['CVE_data_meta']['ID']
        description = item['cve']['description']['description_data'][0]['value']
        vuln_message += f"🔸 {cve_id}: {description}\n\n"
    bot.reply_to(message, vuln_message)

# Command: /breaches - Fetch data breach info from Have I Been Pwned API
@bot.message_handler(commands=['breaches'])
def get_breaches(message):
    url = 'https://haveibeenpwned.com/api/v3/breaches'
    headers = {'hibp-api-key': HIBP_API_KEY}
    breach_data = api_request(url, headers)
    if "error" in breach_data:
        bot.reply_to(message, breach_data['error'])
        return
    
    breach_message = "🔓 **Recent Data Breaches:**\n\n"
    for breach in breach_data[:5]:
        breach_message += f"🔸 {breach['Title']}: {breach['Description']}\n\n"
    bot.reply_to(message, breach_message)

# Command: /whois - Perform a WHOIS lookup for a domain
@bot.message_handler(commands=['whois'])
def whois_lookup(message):
    bot.reply_to(message, "Please provide a domain (e.g., /whois example.com).")

@bot.message_handler(func=lambda message: message.text.startswith('/whois '))
def perform_whois(message):
    domain = message.text.split()[1]
    
    # Domain name validation
    if not re.match(r'^(?:[a-zA-Z0-9-]+\.)+[A-Z]{2,}$', domain, re.IGNORECASE):
        bot.reply_to(message, "Invalid domain name format. Please try again.")
        return
    
    url = f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON'
    whois_data = api_request(url)
    
    if "error" in whois_data:
        bot.reply_to(message, whois_data['error'])
        return
    
    domain_name = whois_data['WhoisRecord']['domainName']
    created_date = whois_data['WhoisRecord'].get('createdDate', 'N/A')
    expiry_date = whois_data['WhoisRecord'].get('expiresDate', 'N/A')
    registrar = whois_data['WhoisRecord'].get('registrarName', 'N/A')
    
    whois_message = f"🌐 **Domain**: {domain_name}\n📅 **Created**: {created_date}\n📅 **Expires**: {expiry_date}\n🏢 **Registrar**: {registrar}"
    bot.reply_to(message, whois_message)

# Command: /ip - Geolocate an IP address
@bot.message_handler(commands=['ip'])
def ip_lookup(message):
    bot.reply_to(message, "Please provide an IP address (e.g., /ip 8.8.8.8).")

@bot.message_handler(func=lambda message: message.text.startswith('/ip '))
def perform_ip_lookup(message):
    ip = message.text.split()[1]
    
    # IP address validation
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        bot.reply_to(message, "Invalid IP address format. Please try again.")
        return
    
    url = f'https://ipinfo.io/{ip}?token={IPINFO_API_KEY}'
    ip_data = api_request(url)
    
    if "error" in ip_data:
        bot.reply_to(message, ip_data['error'])
        return
    
    ip_message = f"🌍 **IP**: {ip_data['ip']}\n🇺🇸 **Country**: {ip_data.get('country', 'N/A')}\n🌆 **City**: {ip_data.get('city', 'N/A')}\n🏢 **Org**: {ip_data.get('org', 'N/A')}"
    bot.reply_to(message, ip_message)

# Command: /ctf - List ongoing CTF competitions
@bot.message_handler(commands=['ctf'])
def list_ctf(message):
    url = f'{CTFTIME_API_URL}?limit=5'
    ctf_data = api_request(url)
    
    if "error" in ctf_data:
        bot.reply_to(message, ctf_data['error'])
        return
    
    ctf_message = "🏆 **Ongoing Capture the Flag (CTF) Competitions:**\n\n"
    for event in ctf_data[:5]:
        ctf_message += f"🔸 {event['title']} - {event['url']}\nStarts: {event['start']}\n\n"
    bot.reply_to(message, ctf_message)

# Inline button handling (Callback Queries)
@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.data == "news":
        get_news(call.message)
    elif call.data == "vulns":
        get_vulns(call.message)
    elif call.data == "breaches":
        get_breaches(call.message)
    elif call.data == "whois":
        whois_lookup(call.message)
    elif call.data == "ip":
        ip_lookup(call.message)
    elif call.data == "ctf":
        list_ctf(call.message)

# Keep the bot running
bot.polling()

