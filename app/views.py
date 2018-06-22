# -*- coding:utf-8 -*-

from app import app, db, auth
from flask import render_template, json, jsonify, request, make_response,abort, g
from app.models import *

@app.route("/")
@auth.login_required
def index():    
    return jsonify('Hello, %s' % g.user.username)


@app.route('/register', methods = ['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(400) # existing user
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({ 'username': user.username })

@auth.verify_password
def verify_password(username_or_token, password):
    if request.method == 'POST':
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    elif request.method == 'GET':
        user = User.verify_auth_token(username_or_token)
        if not user:
            return False
    g.user = user
    return True


@app.route('/login',methods = ['GET', 'POST'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify(token)

@app.route('/user/content', methods=['GET', 'POST'])
def article():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if title and content:
            inset = Article(title=title, content=content)
            db.session.add(inset)
            db.session.commit()
            response = make_response(jsonify({"code": 0, "message": "OK", "data": {"msg": 1}}))
        else:
            response = make_response(jsonify({"code": 1, "message": "error", "data": {"msg": 0}}))
    # select_ = User.query.filter_by(name=name).first()
    elif request.method == 'GET':
         id = request.args.get('id')
         content = Article.query.filter_by(id=id).first()

         if content:
             response = make_response(jsonify({"code": 0, "message": "OK", "data": {"title":content.title,"content": content.content}}))
         else:
             response = make_response(jsonify({"code": 1, "message": "error", "data": {"msg": 0}}))

    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST'
    response.headers['Access-Control-Allow-Headers'] = 'x-requested-with,content-type'
    return response


@app.route('/article/list', methods=['GET'])
def list():
    if request.method == 'GET':
         count =  Article.query.all()
         list=[]
         for data in count:
             articleList = dict()
             articleList[data.id]=data.title
             list.append(articleList)

         if count:
             response = make_response(jsonify({"code": 0, "message": "OK", "data": {"list": list}}))
         else:
             response = make_response(jsonify({"code": 1, "message": "error", "data": {"msg": 0}}))

    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST'
    response.headers['Access-Control-Allow-Headers'] = 'x-requested-with,content-type'
    return response
