"""
KeyCord Landing Page Server
Secure Flask server with comprehensive protection against DDoS, rate limiting, and security headers.
"""

import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, send_from_directory, request, abort, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
import re

# Initialize Flask app
app = Flask(__name__, static_folder='.')
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size

# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/landing_page.log', maxBytes=10240000, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('KeyCord Landing Page Server started')

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "30 per hour", "10 per minute"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to all responses"""
    
    # Content Security Policy - prevents XSS attacks
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Force HTTPS (only in production)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions policy
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
    )
    
    # XSS Protection (legacy, but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

# Request validation middleware
@app.before_request
def validate_request():
    """Validate incoming requests for suspicious patterns"""
    
    # Block requests without User-Agent
    user_agent = request.headers.get('User-Agent', '')
    if not user_agent:
        app.logger.warning(f'Request without User-Agent from {get_remote_address()}')
        abort(403)
    
    # Block common bot patterns (optional - uncomment if needed)
    suspicious_patterns = [
        r'nikto', r'sqlmap', r'nmap', r'masscan', r'metasploit',
        r'<script', r'javascript:', r'onerror=', r'onload='
    ]
    
    # Check User-Agent for suspicious patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, user_agent, re.IGNORECASE):
            app.logger.warning(f'Suspicious User-Agent from {get_remote_address()}: {user_agent}')
            abort(403)
    
    # Check for suspicious query parameters
    for key, value in request.args.items():
        for pattern in suspicious_patterns:
            if re.search(pattern, str(value), re.IGNORECASE):
                app.logger.warning(f'Suspicious query parameter from {get_remote_address()}: {key}={value}')
                abort(403)
    
    # Log all requests
    app.logger.info(f'{request.method} {request.path} from {get_remote_address()} - UA: {user_agent[:100]}')

# Rate limit error handler
@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom handler for rate limit exceeded"""
    app.logger.warning(f'Rate limit exceeded for {get_remote_address()}')
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429

# Generic error handler
@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all exceptions"""
    
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return e
    
    # Log the error
    app.logger.error(f'Unhandled exception: {str(e)}', exc_info=True)
    
    # Return generic error
    return jsonify({
        'error': 'Internal server error',
        'message': 'Something went wrong. Please try again later.'
    }), 500

# Routes
@app.route('/')
@limiter.limit("50 per hour")  # More lenient for homepage
def index():
    """Serve the main landing page"""
    try:
        return send_from_directory('.', 'index.html')
    except FileNotFoundError:
        app.logger.error('index.html not found')
        abort(404)

@app.route('/whitepaper.html')
@limiter.limit("20 per hour")  # Whitepaper is less frequently accessed
def whitepaper():
    """Serve the whitepaper page"""
    try:
        return send_from_directory('.', 'whitepaper.html')
    except FileNotFoundError:
        app.logger.error('whitepaper.html not found')
        abort(404)

@app.route('/<path:filename>')
@limiter.limit("100 per hour")
def serve_static(filename):
    """Serve static files (CSS, JS, fonts)"""
    
    # Security: Prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        app.logger.warning(f'Directory traversal attempt from {get_remote_address()}: {filename}')
        abort(403)
    
    # Only allow specific file types
    allowed_extensions = {'.html', '.css', '.js', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp'}
    file_ext = os.path.splitext(filename)[1].lower()
    
    if file_ext not in allowed_extensions:
        app.logger.warning(f'Forbidden file type requested from {get_remote_address()}: {filename}')
        abort(403)
    
    try:
        return send_from_directory('.', filename)
    except FileNotFoundError:
        app.logger.warning(f'File not found: {filename}')
        abort(404)

@app.route('/health')
@limiter.exempt  # Health check should not be rate limited
def health():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

# Custom 404 handler
@app.errorhandler(404)
def not_found(e):
    """Custom 404 page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - Not Found</title>
        <style>
            body {
                background: #050505;
                color: #e0e0e0;
                font-family: 'Courier New', monospace;
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
                text-align: center;
            }
            .error-box {
                border: 2px solid #fff;
                padding: 3rem;
                max-width: 500px;
            }
            h1 { font-size: 3rem; margin: 0; }
            p { font-size: 1.2rem; }
            a { color: #fff; text-decoration: none; border-bottom: 1px solid #fff; }
            a:hover { color: #27c93f; border-color: #27c93f; }
        </style>
    </head>
    <body>
        <div class="error-box">
            <h1>404</h1>
            <p>PAGE_NOT_FOUND</p>
            <p><a href="/">← RETURN_TO_TERMINAL</a></p>
        </div>
    </body>
    </html>
    """, 404

if __name__ == '__main__':
    # Development server - DO NOT USE IN PRODUCTION
    # For production, use: gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
    app.run(
        host='0.0.0.0',
        port=8006,
        debug=os.getenv('FLASK_DEBUG', 'False') == 'True'
    )
