"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException

import bcrypt
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, get_jwt

api = Blueprint('api', __name__)

@api.route('/users', methods=['GET'])
def get_users():
    all_users = User.query.all()
    serialized_users = list(map(lambda user: user.serialize(), all_users))
    return serialized_users

@api.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        return jsonify(f'User with id: {user_id}, not found in database.'), 404
    else:
        db.session.delete(user)
        db.session.commit()
        return jsonify(f'User with id: {user_id}, is successfully deleted.'), 200

@api.route('/users/register', methods=['POST'])
def create_new_user():
    body = request.get_json()
    hashed = bcrypt.hashpw(body['password'].encode(), bcrypt.gensalt(14))
    new_user = User(body['username'], body['email'], hashed.decode())
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.serialize()), 201

@api.route('/users/login', methods = ['POST'])
def login():
    body = request.get_json()
    user = User.query.filter_by(email = body['email']).one()

    if bcrypt.checkpw(body['password'].encode(), user.password.encode()):
        create_token = create_access_token(identity=user.id)
        return jsonify(create_token)
    else:
        return jsonify('User not exists in database!'), 404

        
# crear ruta privada!
@api.route('/users/app', methods = ['GET'])
@jwt_required()
def get_logged_user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify({ "id": user.id, "username": user.username, "email": user.email }), 200