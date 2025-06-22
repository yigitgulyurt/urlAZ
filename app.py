from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_mail import Mail, Message
from flask_talisman import Talisman
from flask_caching import Cache
from shortuuid import ShortUUID
import qrcode
import os
import redis
import asyncio
import pdfkit
from urlaz.utils import take_screenshot
from urlaz.security_check import SecurityAnalyzer
from functools import lru_cache
import time
import logging
from markupsafe import Markup
from redis.connection import ConnectionPool
import hashlib

# URL kısaltma fonksiyonu
def shorten_url(url):
    short_uuid = ShortUUID().random(length=6)
    # Kısa URL'yi Redis'e kaydet
    redis_client.set(f'short_url:{short_uuid}', url)
    redis_client.expire(f'short_url:{short_uuid}', 60 * 60 * 24 * 30)  # 30 gün geçerli
    return short_uuid

# QR kod oluşturma fonksiyonu
def generate_qr_code(url, qrid):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    qrcodes_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'qrcodes')
    os.makedirs(qrcodes_dir, exist_ok=True)
    filename = f"qr_{qrid}.png"
    img.save(os.path.join(qrcodes_dir, filename))
    return filename

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key'

# Logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/urlaz2/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Redis bağlantı havuzu
redis_pool = ConnectionPool(host='localhost', port=6379, db=0, max_connections=10)
redis_client = redis.Redis(connection_pool=redis_pool)

# Flask-Caching yapılandırması
cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# Rate limiting - Redis backend ile
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379/0"
)

# Güvenlik başlıkları
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'img-src': "'self' data:",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    'font-src': "'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com"
})

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/cookies')
def cookies():
    return render_template('cookies.html')

@app.route('/shorten', methods=['POST'])
def shorten():
    try:
        url = request.form['url']
        if not url:
            return jsonify({'error': 'URL gerekli'}), 400

        short_code = shorten_url(url)
        short_url = f"https://urlaz.yigitgulyurt.com/r/{short_code}"
        
        # İşlem logunu kaydet
        logger.info(f"URL kısaltıldı: {url} -> {short_url}")
        
        return render_template('url_result.html', original_url=url, short_url=short_url)
    except Exception as e:
        logger.error(f"URL kısaltma hatası: {str(e)}")
        return render_template('error.html', message='URL kısaltma işlemi başarısız oldu.'), 500

@app.route('/r/<short_code>')
def redirect_to_url(short_code):
    original_url = redis_client.get(f'short_url:{short_code}')
    if original_url:
        return redirect(original_url.decode('utf-8'))
    return render_template('error.html', message='Bu kısa URL geçersiz veya süresi dolmuş.'), 404

@app.route('/qr', methods=['POST'])
def qr_post():
    url = request.form['url']
    qrid = ShortUUID().random(length=6)
    filename = generate_qr_code(url, qrid)
    return redirect(url_for('serve_qr_result', qrid=qrid, url=url))

@app.route('/qr/<qrid>')
def serve_qr_result(qrid):
    url = request.args.get('url', '')
    qr_url = f"/qrcodes/qr_{qrid}.png"
    return render_template('qr_result.html', qr_url=qr_url, url=url, qrid=qrid)

# Login yönetimi
login_manager = LoginManager()
login_manager.init_app(app)

# Mail yapılandırması
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
mail = Mail(app)

class User(UserMixin):
    def __init__(self, id, email=None):
        self.id = id
        self.email = email
    @staticmethod
    def get(user_id):
        user_data = redis_client.hgetall(f'user:{user_id}')
        if user_data:
            email = user_data.get(b'email', b'').decode()
            return User(user_id, email=email)
        return None
    @staticmethod
    def get_by_email(email):
        user_id = redis_client.get(f'user_email:{email}')
        if user_id:
            return User.get(user_id.decode())
        return None
    @staticmethod
    def create(email, password):
        if redis_client.get(f'user_email:{email}'):
            return None  # Already exists
        user_id = str(redis_client.incr('user:id:seq'))
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        redis_client.hmset(f'user:{user_id}', {'email': email, 'password': password_hash})
        redis_client.set(f'user_email:{email}', user_id)
        return User(user_id, email=email)
    def check_password(self, password):
        user_data = redis_client.hgetall(f'user:{self.id}')
        if not user_data:
            return False
        password_hash = user_data.get(b'password', b'').decode()
        return password_hash == hashlib.sha256(password.encode()).hexdigest()

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            return render_template('register.html', error='Şifreler eşleşmiyor')
        if User.get_by_email(email):
            return render_template('register.html', error='Bu e-posta ile kayıtlı bir kullanıcı zaten var')
        user = User.create(email, password)
        if user:
            login_user(user)
            return redirect(url_for('index'))
        return render_template('register.html', error='Kayıt başarısız')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.get_by_email(email)
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error='Geçersiz e-posta veya şifre')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/batch_analyze', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def batch_analyze():
    urls = request.json.get('urls', [])
    results = []
    for url in urls:
        result = get_cached_analysis(url)
        results.append(result)
    return jsonify(results)

@app.route('/generate_pdf/<path:url>')
@login_required
def generate_pdf(url):
    analysis_result = get_cached_analysis(url)
    html = render_template('pdf_report.html',
                          url=url,
                          analysis=analysis_result)
    pdf = pdfkit.from_string(html, False)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={url}.pdf'
    return response

@app.route('/history')
@login_required
def view_history():
    user_history = redis_client.lrange(f'user:{current_user.id}:history', 0, -1)
    analyses = []
    for item in user_history:
        try:
            analysis = json.loads(item)
            analyses.append(analysis)
        except Exception:
            continue
    return render_template('history.html', analyses=analyses)

@app.route('/notify', methods=['POST'])
@login_required
def notify():
    url = request.form.get('url')
    analysis_result = get_cached_analysis(url)
    msg = Message('URL Analiz Sonucu',
                  sender='your-email@gmail.com',
                  recipients=[current_user.email])
    msg.body = f'URL: {url}\nRisk Skoru: {analysis_result["risk_score"]}'
    mail.send(msg)
    return jsonify({'status': 'success'})

security_analyzer = SecurityAnalyzer()

# URL analiz sonuçlarını önbellekle (1 saat)
@lru_cache(maxsize=100)
def get_cached_analysis(url):
    return security_analyzer.analyze_url(url)

@app.route('/qrcodes/<path:filename>')
def serve_qrcodes(filename):
    qrcodes_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'qrcodes')
    return send_from_directory(qrcodes_dir, filename)

@app.route('/', methods=['GET', 'POST'])
def index():
    url = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            return redirect(url_for('security_result', url=url))
    return render_template('index.html', url=url)

@app.route('/security_result')
def security_result():
    url = request.args.get('url')
    if not url:
        return render_template('error.html', message='URL parametresi eksik veya hatalı.'), 400
    analysis_result = get_cached_analysis(url)
    screenshot_path = take_screenshot(url)
    if screenshot_path:
        screenshot_path = screenshot_path.replace('\\', '/')
        if screenshot_path.startswith('/var/www/urlaz2/sessions/'):
            screenshot_path = '/sessions/' + screenshot_path.split('/sessions/', 1)[1]
    qr_url = None
    qrid = None
    # QR kodu varsa, url ile ilişkili qrid bulmaya çalış
    # (isteğe bağlı: burada bir veri tabanı veya cache sorgusu yapılabilir)
    if current_user.is_authenticated:
        save_analysis_to_history(current_user.id, analysis_result)
    return render_template('security_result.html', url=url, analysis=analysis_result, screenshot_path=screenshot_path, qr_url=qr_url, qrid=qrid)

@app.route('/sessions/<path:filename>')
def serve_session_file(filename):
    return send_from_directory(os.path.join(app.root_path, 'sessions'), filename)


@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL gerekli'}), 400
    result = get_cached_analysis(url)
    if current_user.is_authenticated:
        save_analysis_to_history(current_user.id, result)
    return jsonify(result)

@app.route('/qr/<qrid>')
def serve_qr(qrid):
    qrcodes_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'qrcodes')
    filename = f"qr_{qrid}.png"
    return send_from_directory(qrcodes_dir, filename)

application = app

if __name__ == '__main__':
    # Uygulama başlangıç logları
    logger.info("Uygulama başlatılıyor...")
    try:
        redis_client.ping()
        logger.info("Redis bağlantısı başarılı")
    except redis.ConnectionError:
        logger.error("Redis bağlantısı başarısız!")


    app.run(debug=True, host='0.0.0.0', port=6006)


def save_analysis_to_history(user_id, analysis):
    redis_client.lpush(f'user:{user_id}:history', json.dumps(analysis))
    redis_client.ltrim(f'user:{user_id}:history', 0, 49)  # Keep last 50