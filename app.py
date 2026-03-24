from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from datetime import timedelta
from auth import auth_bp
import os

load_dotenv()

app = Flask(__name__)

# JWT config
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]    # ⬅ this was missing!
app.config["JWT_COOKIE_HTTPONLY"] = True
app.config["JWT_COOKIE_SECURE"] = False           # ⬅ False for localhost (no HTTPS locally)
app.config["JWT_COOKIE_SAMESITE"] = "Lax"         # ⬅ Lax for localhost (Strict blocks localhost)

# CORS config
CORS(app,
  resources={r"/api/*": {
    "origins": "http://localhost:8080",
    "supports_credentials": True,
  }}
)

JWTManager(app)
app.register_blueprint(auth_bp)

if __name__ == "__main__":
  app.run(debug=True)