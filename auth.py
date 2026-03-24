from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from supabase import create_client
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

auth_bp = Blueprint("auth", __name__)
supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))

# 👇 helper function to set cookie — reuse in both login and signup
def set_auth_cookie(response, token):
    response.set_cookie(
        "access_token_cookie",  # ⬅ flask-jwt-extended expects this exact name
        token,
        httponly=True,
        secure=False,           # ⬅ False for localhost
        samesite="Lax"          # ⬅ Lax for localhost
    )
    return response


# ✅ signup route added
@auth_bp.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    name = data.get("name", "")
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # check if user already exists
    existing = supabase.table("users").select("id").eq("email", email).execute()
    if existing.data:
        return jsonify({"error": "Email already registered"}), 409

    # hash password
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), 
        bcrypt.gensalt()
    ).decode("utf-8")

    # insert user into supabase
    result = supabase.table("users").insert({
        "name": name,
        "email": email,
        "password_hash": password_hash
    }).execute()

    user = result.data[0]
    token = create_access_token(identity=user["id"])

    response = make_response(jsonify({
        "user": {"id": user["id"], "email": email, "name": name}
    }), 201)

    return set_auth_cookie(response, token)  # ⬅ reusing helper


@auth_bp.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    result = supabase.table("users").select("*").eq("email", email).execute()
    if not result.data:
        return jsonify({"error": "Invalid email or password"}), 401

    user = result.data[0]

    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"error": "Invalid email or password"}), 401

    token = create_access_token(identity=user["id"])

    response = make_response(jsonify({
        "user": {"id": user["id"], "email": email, "name": user["name"]}
    }))

    return set_auth_cookie(response, token)  # ⬅ reusing helper


@auth_bp.route("/api/me")
@jwt_required(locations=["cookies"])   # ⬅ fixed — look in cookies
def me():
    user_id = get_jwt_identity()

    result = supabase.table("users").select("*").eq("id", user_id).execute()
    user = result.data[0]

    return jsonify({
        "user": {"id": user["id"], "email": user["email"], "name": user["name"]}
    })


@auth_bp.route("/api/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({"message": "Logged out"}))
    response.delete_cookie("access_token_cookie")  # ⬅ same name as set_cookie
    return response