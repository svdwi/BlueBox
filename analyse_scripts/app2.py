#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
from flask import *
import os
from werkzeug.utils import secure_filename
from werkzeug.datastructures import ImmutableMultiDict
from flask import Flask,render_template,request,redirect
from flask_login import login_required, current_user, login_user, logout_user
from models import UserModel,db,login,keymodel,MalFilesModel
import json
import random
import string
#Import From FI_GetInfo, FileInfo Classe
from FI_GetInfo import FileInfo  
from signaturecheck import *
import pathlib
from strings_all.check_strings import *  
from Calls_Strings import * 
from Yarascan import * 
#from yarascripts.yaragen.YaraGenerator import *


 


app = Flask(__name__, template_folder='templates' ,static_url_path='/static') 
 
UPLOAD_FOLDER = '//home//svdwi//ANSI_ANALYSER//script_Analyzers//BlueBox//uploads//'
YARATEST = '//home//svdwi//ANSI_ANALYSER//script_Analyzers//yarascripts//yaragen//YaraGenerator//test//'
ALLOWED_EXTENSIONS = set(['exe', 'bin','png'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['YARA_TEST'] = YARATEST
app.config['SERVER_NAME'] = "Threat.BlueBox:5000"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'xyz'

db.init_app(app)
login.init_app(app)
login.login_view = 'login'

 
def generate_random_key():
	if ( not keymodel.query.all()):
		fk=""
		for i in range(0,20):
			k = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(25))
			k = (hashlib.md5(k.encode()).hexdigest())
			fk += str(k)+'\n'
			_key_ = keymodel(k)
			db.session.add(_key_)
			db.session.commit()
		f  = open("AUTH_KEYS/keys.txt", "w+")
		f.write(fk)
	else: 
		pass

@app.before_first_request
def create_all():
    db.create_all()
    print(generate_random_key())
     

 

  

@app.route('/dashboard')
@login_required
def dashboard():	
	malfile = MalFilesModel.query.filter().all()
	malfile_count = MalFilesModel.query.count()
	return render_template('index.html' , malfile = malfile ,malfile_count=malfile_count)
    
@app.route('/scan')
@login_required
def scan():
	return render_template('dashboard.html')
    
from feed  import * 
@app.route('/feeds')
@login_required
def feeds():
	n =ThreatFoxFeeds().fetch_threatfox(1)
	return render_template('feeds_ioc.html',feed=n)
    
   

#calls strings return 
def callsStrings(filepath):
	cs = calls_nd_strings(filepath)
	__cs__= cs.run()
	return __cs__
	
#signature return 
def signateur(filepath):
	sg = signateur(filepath)
	_sg_= sg.check_signateur()
	return _sg_
#hashes return 
def fileinfo(filepath):
	fi = FileInfo(filepath)
	_fi_ = fi.run()
	return _fi_  
#strings return 
def stringsAll(filepath):
	sa = strings_all(filepath)
	_sa_ = sa.unicode_strings()
	return _sa_




@app.route('/login', methods = ['POST', 'GET'])
def login():

    if current_user.is_authenticated:
        return redirect('/dashboard')

    if request.method == 'POST':
        email = request.form['email']
        user = UserModel.query.filter_by(email = email).first()
        if user is not None and user.check_password(request.form['password']):
            login_user(user)
            return redirect('/dashboard')
        else: 
            return render_template('login.html' , error_msg='incorrect username or password  ')
     
    return render_template('login.html')


 
 
 
 
    
 
 
@app.route('/register', methods=['POST', 'GET'])
def register(): 
    if request.method == 'GET':
        return render_template('login_access_key.html')
    if request.method == 'POST':
        key = request.form['key']
        if keymodel.query.filter_by(keys = key).first(): 
            # db.session.add(key)
            # db.session.commit()
            return render_template('_register_.html')
        else:
            return render_template('login_access_key.html', error="key Used Not Valide")
        
        return render_template('login_access_key.html')

        

    
 
 
@app.route('/page/register', methods=['POST'])
def _register():
    if current_user.is_authenticated:
        return redirect('/')
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        if UserModel.query.filter_by(email=email).first():
            return ('Email already Present')
        user = UserModel(email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('_register_.html')


 
 
 
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')




def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS



"""

#calls strings return 
def callsStrings(filepath):
	cs = calls_nd_strings(filepath)
	__cs__= cs.run()
	return __cs__
	
#signature return 
def signateur(filepath):
	sg = signateur(filepath)
	_sg_= sg.check_signateur()
	return _sg_
#hashes return 
def fileinfo(filepath):
	fi = FileInfo(filepath)
	_fi_ = fi.run()
	return _fi_  
#strings return 
def stringsAll(filepath):
	sa = strings_all(filepath)
	_sa_ = sa.unicode_strings()
	return _sa_

    <dl class="dl-horizontal row">
    {% for val, status in signa.items() %}
    <dt class="col-sm-6">   {% print(val)%} </dt>
    <dd class="col-sm-6"> {% print(status)%}</dd>






    {% endfor %} 
"""
@app.route('/file/results', methods=['POST', 'GET'])
@login_required
def results_file():
        filename = "WannaCry_Ransomware.exe" 
        filepath = "/home/svdwi/ANSI_ANALYSER/script_Analyzers/WannaCry_Ransomware.exe" 
        #filename = data["file_name"] 
        #Add to list  Name, Hash , Status
		#malfil = MalFilesModel("hello", "5f5d5f4d5f4d5f4d5f4d54fd54f" ,"not detected")
		#db.session.add(malfil)
		#db.session.commit()
        calls = calls_nd_strings(filepath).run()
        yaradetect = yaraScan(filepath).results()
        #createYara("Malware Detect By BlueBox v0.1","exe","BlueBox-Analysis-Box","malicous File","APT")
        #signa = signateur(filepath).check_signateur()
        Hashes_Data = FileInfo(filepath).run()
        st = strings_all(filepath)
        strings = st.unicode_strings()
        email = st.getemail()
        ip = st.getip()
        return render_template('results_file_scan.html',
		email = email ,
		ip=ip , 
		yaradetect = yaradetect, 
		strings = strings ,
		calls = calls,
		Hashes_Data = Hashes_Data)





    
    
@app.route('/profile',  methods=['POST', 'GET'])
@login_required
def xxxs():
    if request.method == 'POST':
        admin = UserModel.query.filter_by(email = request.form['email']).first()
        email = request.form['email']
        old_password = request.form['old-password']
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']
        #print(email, old_password ,new_password, confirm_password)
        if not admin.check_password(old_password):
            return "old password not correct !! "
        elif (new_password != confirm_password):
            return "new_password different confirm_password"
        admin.set_password(confirm_password)
        db.session.commit()
        logout()
        return redirect('/login')

    admin = UserModel.query.filter_by(email = "azizsaadaoui2@gmail.com").first()
    print(admin.username)
    print(admin.email)
    print(admin.password_hash)
    print(admin.check_password("aqzsedrf0"))
    return render_template('sample-page.html')
 
    
        
@app.route('/hell', methods=['POST'])
def path():
	if request.method == 'POST':
		data = request.json
		filename = data["file_name"] 
		#print(path)
		#resp = make_response(json.dumps(data))
		#resp.status_code = 200
		#resp.headers['Access-Control-Allow-Origin'] = '*'
	else: 
		abort(450)
        
        
        
"""

if request.method == 'POST':
        data1 = request.form['file_name']
        data2 = request.form['analyze_type']
        data3 = request.form['options']
        data4 = request.form['yara_rules_generate']
        data5 = request.form['strings']
        data6 = request.form['signature']
        data7 = request.form['externel_services']
        print(data1)
        print(data2)
        print(data3)
        print(data4)
        resp = make_response(json.dumps(data))
        resp.status_code = 200
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return Response(json.dumps({"status_code":"200"}), mimetype='application/json')

    else: 
        abort(450)
        
        
"""
        
from urltotal import * 
from foo import * 
@app.route('/url', methods=['GET', 'POST'])
def scan_url():
	geturltotal = VTotalAPI().run()
	#print(malicious_url_ML("hello.com/file.exe").run())
	
	ml =  malicious_url_ML("hello.com/file.exe").run()
	print(type(ml))
	return render_template('results_url_scan.html',geturltotal = geturltotal , ml=ml)

@app.route('/file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            #print(file.filename)
            #filename = secure_filename(hashlib.md5(file.filename).hexdigest()+'-'+file.filename)
            filename = secure_filename(file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            #yarapath = os.path.join(app.config['YARA_TEST'], filename)
            file.save(path)
            #for file in os.scandir(yarapath):
            #os.remove(file.path)
            #file.save(yarapath)
            filepath = app.config['UPLOAD_FOLDER']+"//"+filename 
            filesize = os.path. getsize(filepath)
            print(filepath)
            calls = calls_nd_strings(filepath).run()
            yaradetect = yaraScan(filepath).results()
            #createYara("Malware Detect By BlueBox v0.1","exe","BlueBox-Analysis-Box","malicous File","APT")
            #signa = signateur(filepath).check_signateur()
            Hashes_Data = FileInfo(filepath).run()
            st = strings_all(filepath)
            strings = st.unicode_strings()
            email = st.getemail()
            ip = st.getip()
            return render_template('results_file_scan.html',filename = filename , filesize = filesize , email = email ,ip=ip , yaradetect = yaradetect,  strings = strings , calls = calls,Hashes_Data = Hashes_Data)
            #return Response(json.dumps({"success":"True","file_name": file.filename }), mimetype='application/json')
            #else: 
            #return Response(json.dumps({"success":"False","file_name": file.filename }), mimetype='application/json')


	   
db.init_app(app)
if __name__ == "__main__":
    app.run(debug=True,ssl_context=('certif/cert.pem', 'certif/key.pem'))
