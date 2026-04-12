from flask import Flask, request, current_app
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
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

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
    
    @app.context_processor
    def inject_global_data():
        from .security import generate_csrf_token
        return dict(get_locale=get_locale, csrf_token=generate_csrf_token())


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
