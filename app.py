from typing import List, Any

from flask import (
	Flask, 
	abort, 
	render_template, 
	url_for, 
	request, 
	redirect,
	session
)
from markupsafe import escape
import os
import binascii
import math as m
import pymongo
from flask_pymongo import PyMongo
import json
from hashlib import sha256
from cfg import config
from util import get_random_string
from dateutil import tz
from datetime import datetime

from werkzeug.utils import secure_filename

app = Flask(__name__)

#app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
app.config["MONGO_URI"] = config['mongo_uri']
app.config['SECRET_KEY'] = binascii.hexlify(os.urandom(24))
app.config['UPLOAD_FOLDER'] ='/Users/jsr/flask-app/mycloud/uploads'
# Set the secret key to some random bytes. Keep this really secret!
#app.secret_key = b'jashnnhfg12#fg'

mongo = PyMongo(app)

@app.route('/')
def show_index():
	if not 'userToken' in session:
		session['error'] = 'You must login'
		return redirect('/login')
	# Validate userToken
	#step 2
	token_document = mongo.db.user_tokens.find_one({
		'sessionHash': session['userToken'],
	})

	if token_document is None:
		session.pop('userToken', None)
		session['error'] = 'You must login again to access this page !'
		return redirect('/login')

	error = ''
	if 'error' in session:
		error = session['error']
		# remove the username from the session if it's there
		session.pop('error', None)

	#userId = token_document['userID']
	#print("userID is: " + str(userId))
	userId = token_document['userID']

	user = mongo.db.users.find_one({
		'_id': userId
	})

	uploaded_files = mongo.db.files.find({
		'userId': userId,
		'isActive': True
	}).sort([("createdAt", pymongo.DESCENDING)])

	formatted_file_data = []

	for f in uploaded_files:
		#value = float(f['fileSize']) / m.pow(base, multiple)
		#f['formattedSize'] = format(value, ".2f")
		f['formattedSize'] = f['fileSize']
		# for time in days total seconds/86400
		now = datetime.now()
		then = f['createdAt']
		duration = now - then
		duration_in_s = duration.total_seconds()
		#f['formattedDate'] = int(divmod(duration_in_s, 86400)[0])
		f['formattedDate'] = duration.days
		formatted_file_data.append(f)

	# step 1
	#print('Inside secure dashboard')
	#print(session['userToken'])
	#return 'welcome to secure home pages'
	return render_template(
		'files.html',
		formatted_file_data=formatted_file_data,
		user=user,
		error=error
	)

#@app.route('/login')
#@app.route('/login/<name>')
#def show_login(name=None):
	#return '{}\'s profile'.format(escape(name))
    #return render_template('mylogin.html', name=name)
#def show_login():
    #return 'welcome to login pages'
@app.route('/login')
def show_login():
	signupSucsess = ''
	if 'signupSucsess' in session:
		signupSucsess = session['signupSucsess']
		# remove the username from the session if it's there
		session.pop('signupSucsess', None)
	error = ''
	if 'error' in session:
		error = session['error']
		# remove the username from the session if it's there
		session.pop('error', None)

	return render_template('login.html', 
		signupSucsess=signupSucsess,
		error=error
	)


@app.route('/check_login', methods=['POST'])
def check_login():
	try:
		email=request.form['email']
	except KeyError:
		email=''

	try:
		password=request.form['password']
	except KeyError:
		password=''

	# Check if email is blank
	if not len(email) > 0:
		session['error'] = 'Email is required'
		return redirect('/login')

	# Check if password is blank
	if not len(password) > 0:
		session['error'] = 'password is required'
		return redirect('/login')

	# Find email in database
	user_document = mongo.db.users.find_one({"email": email })
	if user_document is None:
		# if user document not found throw error
		ession['error'] = 'No account exist with this email address'
		return redirect('/login')

	# Verify that password with original
	password_hash = sha256(password.encode('utf-8')).hexdigest()
	if user_document['password'] != password_hash:
		session['error'] = 'Password is wrong'
		return redirect('/login')

	# to do Generate token contains userID,hash and created AT
	random_string = get_random_string()
	randomSessionHash = sha256(random_string.encode('utf-8')).hexdigest()
	token_object = mongo.db.user_tokens.insert_one({
		'userID':user_document['_id'],
		'sessionHash': randomSessionHash,
		'createdAt': datetime.utcnow(),
	})

	# store userToken in session
	session['userToken'] = randomSessionHash



	# redirect to '/'
	return redirect('/')


@app.route('/signup')
def show_signup():
	error = ''
	if 'error' in session:
		error = session['error']
		# remove the username from the session if it's there
		session.pop('error', None)
	return render_template('signup.html', error=error)

@app.route('/handle_signup', methods=['POST'])
def handle_signup():
	try:
		email=request.form['email']
	except KeyError:
		email=''

	try:
		password=request.form['password']
	except KeyError:
		password=''

	print(email)
	print(password)

	# Check if email is blank
	if not len(email)>0:
		session['error'] = 'Email is required'
		return redirect('/signup')
	# Check if email is valid
	if not '@' in email or not '.' in email:
		session['error'] = 'Email is invalid'
		return redirect('/signup')
	# Check if password is blank
	if not len(password) > 0:
		session['error'] = 'password is required'
		return redirect('/signup')
	# Check if email is already exist
	matching_user_count = mongo.db.users.count_documents({ "email": email })
	if matching_user_count >0:
		session['error'] = 'Email-id is already exist'
		return redirect('/signup')

	password = sha256(password.encode('utf-8')).hexdigest()


	# Create user record in database
	result = mongo.db.users.insert_one({
		'email': email,
		'password': password,
		'name': '',
		'lastLoginDate': None,
		'createdAt': datetime.utcnow(),
		'updateAt': datetime.utcnow(),
	})

	# Redirect to login page
	session['signupSucsess'] = 'Your user acount is ready. You can login now.'
	return redirect('/login')

@app.route('/logout')
def logout_user():
	session.pop('userToken', None)
	session['signupSucsess'] = 'You are now logged out'
	return redirect('/login')

def allowed_file(filename):
	ALLOWED_EXTENSIONS=['tif','jpg','jpeg','gif','png','doc','docx','xlsx']
	return '.' in filename and \
		   filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/handle_file_upload', methods=['POST'])
def handle_file_upload():
	if not 'userToken' in session:
		session['error'] = 'You must login'
		return redirect('/login')
	# Validate userToken
	#step 2
	token_document = mongo.db.user_tokens.find_one({
		'sessionHash': session['userToken'],
	})

	if token_document is None:
		session.pop('userToken', None)
		session['error'] = 'You must login again to access this page !'
		return redirect('/login')

	# check if the post request has the file part
	if 'uploadedFile' not in request.files:
		session['error'] = 'No file uploaded'
		return redirect('/')

	file = request.files['uploadedFile']
	#file_size = os.stat(request.files['uploadedFile']).st_size
	file_size = len(file.read())
	print('I have got the file')
	print(file)
	print(file_size)

	# submit an empty part without filename
	if file.filename == '':
		session['error'] = 'No selected file'
		return redirect('/')

	if not allowed_file(file.filename):
		session['error'] = 'File type not allowed'
		return redirect('/')

	# TODO File size_check
	base = 1024
	multiple = 2

	value = file_size / m.pow(base, multiple)
	file_size_in_mb = format(value, ".2f")
	max_size = 2 * 1024 * 1024
	if file_size > max_size:
		session['error'] = 'File is too large'
		return redirect('/')

	extension = file.filename.rsplit('.', 1)[1].lower()
	filename = secure_filename(file.filename)
	filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
	file.save(filepath)

	# Create user record in database
	result = mongo.db.files.insert_one({
		'userId': token_document['userID'],
		'originalFileName': file.filename,
		'fileType': extension,
		'fileSize': file_size_in_mb,
		'fileHash': '',
		'filePath': filepath,
		'isActive': True,
		'createdAt': datetime.utcnow(),
	})

	return redirect('/')


