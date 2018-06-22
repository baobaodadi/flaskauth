from flask import Flask
import MySQLdb
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:new123@localhost/rest?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


class Article(db.Model):
    __table_args__ = {'mysql_collate': 'utf8mb4_unicode_ci'}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80))
    content = db.Column(db.Text)

    def __init__(self, title,content):
        self.title = title
        self.content = content

# inset=User(name='admin', email='new1234', phone='13812345678')
# db.session.add(inset)
# db.session.commit()

# select_=User.query.filter_by(username='admin').first()
# print(select_.email)

if __name__ == '__main__':
    db.create_all()