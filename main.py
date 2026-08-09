import eventlet
eventlet.monkey_patch()

from app import create_app, db
import logging

app, socketio = create_app()

with app.app_context():
    db.create_all()
    from app.schema_guard import ensure_schema
    ensure_schema(db)

# Ana sayfa rotasını welcome'a yönlendir
@app.route('/')
def index():
    from flask import redirect, url_for
    return redirect(url_for('auth.welcome'))

# Favicon route
@app.route('/favicon.ico')
def favicon():
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
        logging.info(f"SERVICE_STARTING service={service}")
        subprocess.Popen([python_executable, service_path],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

if __name__ == "__main__":
    import os
    start_services()

    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    socketio.run(app, debug=debug, host='0.0.0.0', port=8005)
