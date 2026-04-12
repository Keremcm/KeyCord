from app import create_app, db
from app.routes import mail

app, socketio = create_app()
mail.init_app(app)

with app.app_context():
    db.create_all()
    # pass

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

if __name__ == "__main__":
    import os
    socketio.run(app, debug=True, host='0.0.0.0', port=8005)
