# -*- coding: utf-8 -*-

import os
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = "mysql://root:new123@127.0.0.1/rest?charset=utf8mb4"
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
SQLALCHEMY_TRACK_MODIFICATIONS = True
BASEDIR = basedir
# 安全配置
CSRF_ENABLED = True
SECRET_KEY = 'jklklsadhfjkhwbii9/sdf\sdf'