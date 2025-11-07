import os
class Config:
    SQL_ALCHEMY_DATABASE_URI = 'mysql+pymysql://user:password@localhost/health_records'
    SQL_ALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)