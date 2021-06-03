from flask import Flask, render_template,jsonify, request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from passlib.hash import pbkdf2_sha256
import random
import smtplib
import time
import pymongo
import uuid

client = pymongo.MongoClient('localhost', 27017)
db = client.user_login_system

app = Flask(__name__)

class User:

    def signup(self):
        try:
            if request.method == 'POST':
                SignUpData = request.json
                email = SignUpData['email']
                username = SignUpData['username']
                userpass = SignUpData['password']

                if len(username)<8:
                    response = jsonify({
                            "statusCode": 400,
                            "status": "Password length not sattisfied",
                            "data": "Password length must be atleast 8"
                        })
                    return response
                
                passMsg=""
                digSet=set([0,1,2,3,4,5,6,7,8,9])
                speSet=set(['$','&','@','#','%'])
                passcheck=['false','false']
                for ele in userpass:
                    if ele in digSet:
                        passcheck[0]=True
                    elif ele in speSet:
                        passcheck[1]=True
                if passcheck[0]==False:
                    passMsg+=" At least one digit in password required \n"
                if passcheck[1]==False:
                    passMsg+=" At least one special character in password required"
                if (passcheck[0]==False or passcheck[1]==False):
                    response = jsonify({
                            "statusCode": 400,
                            "status": "Password validation not sattisfied",
                            "data": passMsg
                    })
                    return response


                otp = ''.join([str(random.randint(0,9)) for i in range(6)])                
                
                user = {
                    "_id": uuid.uuid4().hex,
                    "user": username,
                    "email": email,
                    "pass": userpass,
                    "otpvalue": otp,
                    "counter": 1,
                    "timestamp": time.time()
                }

                vmsg=""

                #Encrypt the password

                user['pass'] = pbkdf2_sha256.encrypt(user['pass'])

                # Check for existing email address
                if db.users.find_one({ "email": user['email']}):
                    response = jsonify({
                            "statusCode": 400,
                            "status": "User is already Registered",
                            "data": "Try changing the password"
                        })
                    return response
                else:
                    if db.verify.find_one({ "email": user['email']}):
                        db.verify.remove({ "email": user['email']})
                        vmsg+="User already in Verify, so removed ...."

                    if db.verify.insert_one(user):
                        vmsg+="User added to verify successfully"

                    # OTP VErification mail
                    pswdVijayantOTP = 'gkgjipzomvptetma'
                    FROM = 'vijayantOTP@gmail.com'
                    TO = email
                    msg = MIMEMultipart()
                    msg['From'] = FROM
                    msg['To'] = TO
                    msg['Subject'] = 'OTP for VijayantOTP'
                    msg['Content-type'] = 'text/html'
                    body = """
                    <b>Your OTP is : """+otp+""" for VijayantOTP</b>
                    <h2>This OTP is valid for 10 minutes</h2>
                    """
                    body = MIMEText(body,'html') # convert the body to a MIME compatible string
                    msg.attach(body) # attach it to your main message
                    server = smtplib.SMTP('smtp.gmail.com',587)
                    server.starttls()
                    server.login( FROM ,pswdVijayantOTP)
                    server.sendmail(FROM,TO,msg.as_string())
                    server.quit()

                    response = jsonify({
                            "statusCode": 200,
                            "status": "Verify OTP Now",
                            "data": vmsg
                        })
                response.headers.add('Access-Control-Allow-Origin',
                                    'http://192.168.43.180:3000/')
                response.headers.add(
                    'Access-Control-Allow-Headers', "Content-Type, Authorization")
                response.headers.add('Access-Control-Allow-Methods', "*")
                response.headers.add('Access-Control-Allow-Credentials', True)
                return response
        except Exception as error:
            # return render_template("signup.html", error = str(error))

            return jsonify({
                "statusCode": 500,
                "status": "Some Error occurred SignUp Again",
                "error": str(error)
            })

class Verify:

    def overify(self):
        try:
            if request.method == 'POST':
                OData = request.json
                email = OData['email']
                ootp = OData['otpvalue']
                searchedUser = db.verify.find_one({ "email": email})
                if (searchedUser):
                    if (searchedUser["otpvalue"] == ootp): # if otp matches transfering the data to users database
                        user = {
                            "_id": uuid.uuid4().hex,
                            "user": searchedUser["user"],
                            "email": str(email),
                            "pass": searchedUser["pass"]
                        }

                        db.users.insert_one(user)
                        db.verify.remove({ "email": email})
                        response = jsonify({
                            "statusCode": 200,
                            "status": "SignUp Successful",
                            "data": "SignUp Done"
                        })
                        
                    else:
                        if (time().time() - searchedUser["timestamp"] >660 ): # Timer of 10 minutes
                            db.verify.remove({ "email": email}) # Deleting the data from the dictionary
                            # return render_template("signup.html", msg = "You took too much time for OTP verification, Try again")
                            response = jsonify({
                                "statusCode": 400,
                                "status": "10 minutes over",
                                "data": email
                            })

                        else:
                            searchedUser["counter"]+=1
                            if(searchedUser["counter"]<4):
                                # return render_template("overify.html",email=email)
                                response = jsonify({
                                    "statusCode": 200,
                                    "status": "Trial number "+str(searchedUser["counter"]),
                                    "data": searchedUser["counter"]
                                })

                            else:
                                # return render_template("signup.html", msg = "3 trials failed for OTP verification, Try Signing Up again")
                                response = jsonify({
                                    "statusCode": 200,
                                    "status": " 3 Trial Done SignUp again ",
                                    "data": "signUp Again"
                                })

                else:
                    # return render_template("signup.html", msg = "You took too much time for OTP verification, Try again")
                    response = jsonify({
                        "statusCode": 400,
                        "status": " Took Too much time SignUp Again ",
                        "data": "signUp Again"
                    })
            response.headers.add('Access-Control-Allow-Origin',
                                'http://192.168.43.180:3000/')
            response.headers.add(
                'Access-Control-Allow-Headers', "Content-Type, Authorization")
            response.headers.add('Access-Control-Allow-Methods', "*")
            response.headers.add('Access-Control-Allow-Credentials', True)

            
            # return render_template("index.html")
            return response
        except Exception as error:
            # return render_template("signup.html", error = str(error))
            return jsonify({
                "statusCode": 500,
                "status": "Some Error occurred during OTP verification",
                "error": str(error)
            })

class Login:

    def login(self):
        try:
            if request.method == 'POST':
                OData = request.json
                email = OData['email']
                password = OData['password']
                searchedUser = db.users.find_one({ "email": email})
                if (searchedUser):
                    if (pbkdf2_sha256.verify(password, searchedUser['pass'])): # if passwords matches Login success
                        
                        response = jsonify({
                            "statusCode": 200,
                            "status": "SignUp Successful",
                            "data": "Welcome, "+str(searchedUser['user'])
                        })
                        
                    else:
                        
                        response = jsonify({
                            "statusCode": 400,
                            "status": " Wrong Password ",
                            "data": "Login Again"
                        })

                else:
                    # return render_template("signup.html", msg = "SignUp")
                    response = jsonify({
                        "statusCode": 400,
                        "status": " User not registered ",
                        "data": "You are not registered"
                    })
            response.headers.add('Access-Control-Allow-Origin',
                                'http://192.168.43.180:3000/')
            response.headers.add(
                'Access-Control-Allow-Headers', "Content-Type, Authorization")
            response.headers.add('Access-Control-Allow-Methods', "*")
            response.headers.add('Access-Control-Allow-Credentials', True)

            
            # return render_template("index.html")
            return response
        except Exception as error:
            # return render_template("signup.html", error = str(error))
            return jsonify({
                "statusCode": 500,
                "status": "Some Error occurred during OTP verification",
                "error": str(error)
            })



@app.route('/signup/', methods=['POST'])
def signup():
    return User().signup()

@app.route('/overify/', methods=['POST'])
def overify():
    return Verify().overify()

@app.route('/login/', methods=['POST'])
def login():
    return Login().login()

if __name__ == '__main__':
    app.run(debug=True)
