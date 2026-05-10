from app import create_app, db

app, socketio = create_app()

with app.app_context():
    db.create_all()
    # pass

# Ana sayfa rotasını welcome'a yönlendir
@app.route('/')
def index():
    # pyrefly: ignore [missing-import]
    from flask import redirect, url_for
    return redirect(url_for('auth.welcome'))

# Favicon route
@app.route('/favicon.ico')
def favicon():
    # pyrefly: ignore [missing-import]
    from flask import send_from_directory
    return send_from_directory(app.static_folder, 'logo.png')

def start_services():
    import subprocess
    import sys
    import os
    
    services_dir = os.path.join(os.path.dirname(__file__), 'services')
    if not os.path.exists(services_dir):
        return
        
    python_executable = sys.executable
    service_files = [f for f in os.listdir(services_dir) if f.endswith('.py')]
    
    for service in service_files:
        service_path = os.path.join(services_dir, service)
        print(f"[*] Starting service: {service}")
        # Servisleri arka planda bağımsız süreçler olarak başlat
        subprocess.Popen([python_executable, service_path], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)

if __name__ == "__main__":
    import os
    # Servisleri başlat
    start_services()
    
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    socketio.run(app, debug=debug, host='127.0.0.1', port=8005, allow_unsafe_werkzeug=True)
