from flask import Flask, request, current_app, g
import secrets
from flask_babel import Babel
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_migrate import Migrate

db = SQLAlchemy()
socketio = SocketIO()
migrate = Migrate()
babel = Babel()

def get_locale():
    # 1. Check if user has an explicit language preference in session or cookie (future feature)
    # 2. Check Accept-Language header manually to support fuzzy matching (en-US -> en)
    supported_languages = current_app.config['LANGUAGES']
    
    # request.accept_languages is ordered by quality (q)
    for lang in request.accept_languages.values():
        # Clean the language code (just in case)
        lang = lang.replace('_', '-')
        
        # 1. Try exact match
        if lang in supported_languages:
            return lang
            
        # 2. Try language code match (en-US -> en)
        if '-' in lang:
            lang_code = lang.split('-')[0]
            if lang_code in supported_languages:
                return lang_code
    
    # Fallback to default
    return current_app.config['BABEL_DEFAULT_LOCALE']



def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    # ProxyFix for Nginx/Cloudflare real IP
    from werkzeug.middleware.proxy_fix import ProxyFix
    # x_for=2: Cloudflare(1) + Nginx(1) = 2 proxy güvenliği
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1, x_prefix=1)

    # Standart Flask/Werkzeug Loglarını Gerçek IP ile Güncelleme (WSGI Middleware)
    class RealIPMiddleware:
        def __init__(self, app):
            self.app = app
        def __call__(self, environ, start_response):
            # Cloudflare IP'sini environ'a (Flask'ın kalbine) enjekte et
            real_ip = environ.get('HTTP_CF_CONNECTING_IP') or \
                      environ.get('HTTP_X_REAL_IP') or \
                      environ.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
            
            # Eğer bulunan IP 127.0.0.1 ise ve listede başka IP varsa onları dene
            if real_ip == '127.0.0.1' and environ.get('HTTP_X_FORWARDED_FOR'):
                ips = [i.strip() for i in environ.get('HTTP_X_FORWARDED_FOR', '').split(',')]
                for ip in ips:
                    if ip != '127.0.0.1':
                        real_ip = ip
                        break

            if real_ip:
                environ['REMOTE_ADDR'] = real_ip
            return self.app(environ, start_response)

    app.wsgi_app = RealIPMiddleware(app.wsgi_app)

    # --- Werkzeug Terminal Loglarını Yamalama (Monkey-Patch) ---
    # Bu kısım terminaldeki "127.0.0.1 - - [date] GET..." satırlarını düzeltir
    try:
        import werkzeug.serving
        parent_address_string = werkzeug.serving.WSGIRequestHandler.address_string
        
        def patched_address_string(self):
            # Headers içinden gerçek IP'yi ara
            real_ip = self.headers.get('CF-Connecting-IP') or \
                      self.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            return real_ip if real_ip else parent_address_string(self)
            
        werkzeug.serving.WSGIRequestHandler.address_string = patched_address_string
    except (ImportError, AttributeError):
        pass

    # Custom Session Interface (Key Rotation)
    from .session_interface import RotateKeysSessionInterface
    app.session_interface = RotateKeysSessionInterface()

    db.init_app(app)
    migrate.init_app(app, db)
    babel.init_app(app, locale_selector=get_locale)
    socketio.init_app(app)

    # Login Manager Init
    from flask_login import LoginManager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login_page'
    
    from .models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    # Register custom Jinja2 filters
    from .routes import register_filters
    register_filters(app)
    
    @app.before_request
    def set_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def inject_global_data():
        from .security import generate_csrf_token
        return dict(
            get_locale=get_locale, 
            csrf_token=generate_csrf_token(),
            csp_nonce=getattr(g, 'csp_nonce', '')
        )


    # Güvenlik middleware'lerini uygula
    from .middleware import apply_all_middleware
    apply_all_middleware(app, socketio)

    from .routes import auth_bp, main_bp
    from .blueprints.app_api import app_api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(app_api_bp)

    from . import sockets

    return app, socketio
