from flask import Flask,jsonify, request
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from config import Config
from model import db, User

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)
db.init_app(app)
bcrypt = Bcrypt(app)    

@app.router('/')
def home():
    return jsonify({'message': 'Health Record Backend is running'})

@app.route('/api/register', methods=['POST'] )
def register():
    data = request.get_json()
    hashed_pw=bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Login successful', 'user': user.to_dict()})
    return jsonify({'message': 'Invalid credentials'}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

