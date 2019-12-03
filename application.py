from flask import Flask, render_template, redirect, url_for, request, session, flash, Response, send_file
from datetime import timedelta, datetime
from pymongo import MongoClient
import random
import bcrypt
import re
from DatabaseCheck import database_login, sessionId_check, admin_check, read_user_data, read_all_data, add_data, \
    get_username, download_files, clean_up_downloads
import gridfs
from werkzeug.utils import secure_filename
import json


# Haiku
# TODO: I should probably
# TODO: come back and refactor this
# TODO: I probably wont

# it seems that beanstalk does not like it when this is named anything else
# maybe the object created needs to have the same name as the .py file?
# for our case both are named application and it seems to work so I'll let it slide for now
application = Flask(__name__)
# the secret key needs to be set in order for us to set or access the session dictionary
# I think this is used for encryption, but I'm not sure.
application.secret_key = b'3$,O@r6AQ6oBYrI'  # DON'T SHARE THIS WITH ANYONE
# the session will be saved on the user's computer for 7 days.  Allows user to stay logged in for one week
application.permanent_session_lifetime = timedelta(days=7)
# only allow uploads of up to 16 megabytes
application.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'png', 'jpg', 'jpeg', 'gif', 'wav', 'mp3', 'csv'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# used to sanatize input and get rid of any characters that might be used in attacks
def sanitize(my_string):
    clean_string = re.sub("[^a-zA-Z0-9(),.!?\"\'\s\n\t]", "", my_string)
    return clean_string


# used to check if an input needed to be sanitized.
def sanitize_test(my_string):
    if my_string != sanitize(my_string):
        return False
    return True


def load_check():
    # authenticate on sessionId.  If no sessionId is present then get rid of username if it is present and
    # redirect to login page
    if "sessionId" not in session:
        if "username" in session:
            session.pop("username", None)
        print("no sessionId found in session")
        return False

    # if there is a sessionId present then check to make sure it is valid
    if not sessionId_check(session["sessionId"]):
        if "username" in session:
            session.pop("username", None)
        if "sessionId" in session:
            session.pop("sessionId", None)
        print("failed sessionId_check")
        return False
    return True


# LOGIN
@application.route("/", methods=["POST", "GET"])
def login():
    """
    # for css testing to quickly return the page
    return render_template("login.html")
    """

    # if user is already logged in redirect them to DataUpload page
    if load_check():
        return redirect(url_for("DataUpload"))

    if request.method == "POST":
        username = sanitize(request.form["username"])
        password = request.form["password"]
        message, sessionId = database_login(username, password)
        flash(message, "info")

        if message != "Login Successful":
            print("login was unsuccessful")
            return render_template("login.html")

        # sessionId is the only thing we use to authenticate information on.
        session["sessionId"] = sessionId

        return redirect(url_for("DataUpload"))
    return render_template("login.html")


# UPLOAD/DATABASE PAGE
@application.route("/DataUpload", methods=["POST", "GET"])
def DataUpload():
    """
    # for css testing to quickly return the page
    username = "please delete this"
    displayData = {}
    role="admin"
    return render_template("DataUpload.html", username=username, database=displayData, role=role)
    """


    if not load_check():
        flash("Session Expired.  Please Login", "info")
        return redirect(url_for("login"))

    # don't trust cookies for username
    boolVal, username = get_username(session["sessionId"])
    if not boolVal:
        flash("Session Expired.  Please Login", "info")
        return redirect(url_for("Login"))

    if request.method == "POST":
        if "Logout" in request.form:
            return redirect(url_for("logout"))

        if "Admin Page" in request.form:
            if admin_check(session["sessionId"]):
                redirect(url_for("admin"))

        if "Download Database" in request.form:
            if not admin_check(session["sessionId"]):
                redirect(url_for("DataUpload"))
            redirect(url_for("Download"))

        # parse any uploads
        if "Upload" in request.form:
            # print("starting to parse upload")
            # print("text form: ", request.form)
            error = False
            message = ""
            # return error if user has not added description
            if request.form["shortDescription"] == "":
                message = "Upload incorrect.  Please upload file with short description"
                error = True

            # return error if the user has not uploaded a file
            if request.files["file"].filename == "":
                message = "Upload incorrect.  Please upload file with short description"
                error = True

            # we can now get the file
            file = ''
            if not error:
                file = request.files['file']

            # check for illegal characters in file name:
            if not error:
                if not sanitize_test(file.filename):
                    message += "invalid file name or type"
                    error = True

            # check for multiple extensions:
            if not error:
                if file.filename.count('.') > 2:
                    message += "invalid file name or type"
                    error = True

            # can't ever be too safe with these file names
            if not error:
                file.filename = secure_filename(file.filename)

                # mark each file with the username and datetime
                splitFilename = file.filename.split('.')
                filename = f"{splitFilename[0]}_{username}_{str(datetime.now()).replace(' ', '_').replace(':', '_').replace('.', '_')}_{splitFilename[1]}"

            # parse the upload if formatted correctly
                description = request.form["shortDescription"]
                uploadData = {
                            "username": username,
                            "description": description,
                            "filename": filename,
                            "file": file  # a fs object that will link us back to the file uploaded
                            }
                print(add_data(session["sessionId"], uploadData))

                message = "Upload Successful"
            flash(message, "info")

    # get the database that we want to display to the page
    displayData = ""
    role = ""
    if admin_check(session["sessionId"]):
        print("this person is an admin")
        displayData = read_all_data(session["sessionId"])
        role = "admin"
    else:
        print("this person is a user")
        displayData = read_user_data(session["sessionId"])
        role = "user"
    return render_template("DataUpload.html", username=username, database=displayData, role=role)


# DOWNLOAD BUTTON
@application.route("/Download", methods=["POST"])
def Download():
    if not load_check():
        flash("Session Expired.  Please Login", "info")
        return redirect(url_for("login"))

    if not admin_check(session["sessionId"]):
        return redirect(url_for("DataUpload"))

    displayData = read_all_data(session["sessionId"])
    # print(displayData)
    dataDict = {}
    fileList = []
    for k1, v1 in displayData.items():
        dataDict[str(k1)] = str(v1)
        # find the objectID
        # print(k1, v1)
        for k2, v2 in v1.items():
            for k3, v3 in v2.items():
                # print(v3["file"])
                fileList.append(v3["file"])
    # print(fileList)
    print("DOWNLOADING FILES NOW ##############################################################################")
    dataDict = json.dumps(dataDict)  # convert dictionary to string
    downloadPath = download_files(fileList, dataDict)

    download = "this is where we would put the dict"
    filenameString = f"attachment; filename=database_{str(datetime.now())}.txt"
    print("sending file to admin now")
    return send_file(downloadPath, as_attachment=True)


# LOGOUT
@application.route("/logout")
def logout():
    if "username" in session:
        session.pop("username", None)
    if "sessionId" in session:
        session.pop("sessionId", None)
        flash("Logout Successful", "info")
    return redirect(url_for("login"))


# hopefully this helps against injection?  Since we are never actually considering executing any malicious code input
# then this should in theory redirect all url injection attempts back to the home page
# should project against idor Insecure Direct Object Reference through url tampering
@application.route("/<injectAttempt>")
def inject_attempt(injectAttempt):
    return redirect(url_for("login"))


if __name__ == '__main__':
    # application.run(debug=True)
    application.run()
