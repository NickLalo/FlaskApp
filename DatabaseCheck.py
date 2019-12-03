from pymongo import MongoClient
import bcrypt
import random
from datetime import timedelta, datetime
import time
import gridfs
import os
import re
from zipfile import ZipFile

# Haiku
# TODO: I should probably
# TODO: come back and refactor this
# TODO: I probably wont


# used to sanatize input and get rid of any characters that might be used in attacks
def sanitize(my_string):
    clean_string = re.sub("[^a-zA-Z0-9(),.!?\"\'\s\n\t]", "", my_string)
    return clean_string


def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())


def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(plain_text_password, hashed_password)


def create_new_user(username, role="user"):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:passwordGoesHere@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    count = collection.count_documents({"username": username})
    if count > 0:
        return "Please choose another username.  That one is taken."

    characters = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
    password = ""
    for num in range(0, random.randrange(52, 76)):
        password += random.choice(characters)
    hashed = get_hashed_password(password.encode('utf-8'))

    sessionId = ""
    for num in range(0, random.randrange(52, 76)):
        sessionId += random.choice(characters)

    newPerson = {
        "username": username,
        "hashedPassword": hashed,
        "role": role,
        "sessionId": sessionId,  # will be reset to empty string at the end of session
        "timeoutAt": datetime.now(),  # will be set to datetime.now() whenever a user logs out
        "dataUpload": {}
    }
    collection.insert_one(newPerson)
    return password


def database_login(username, password):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    # check if session is still valid
    count = collection.count_documents({"username": username})
    if count == 0:
        return "incorrect username and password combination", ""

    hashed = b""
    results = collection.find({"username": username})
    for result in results:
        hashed = result["hashedPassword"]

    if check_password(password.encode('utf-8'), hashed):
        # sessionID and timeoutAt creation
        characters = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
        sessionId = ""
        for num in range(0, random.randrange(52, 76)):
            sessionId += random.choice(characters)
        TIME_ON_SITE = timedelta(days=7)  # constant used in database_login
        # TIME_ON_SITE = timedelta(seconds=15)  # for testing purposes
        timeoutAt = datetime.now() + TIME_ON_SITE
        collection.update_one({"username": username}, {"$set": {"sessionId": sessionId}})
        collection.update_one({"username": username}, {"$set": {"timeoutAt": timeoutAt}})
        # save session to the session data
        return "Login Successful", sessionId

    # do not tell the user which part of the combination was incorrect
    time.sleep(2)  # waste some time to slow down brute force attacks
    return "incorrect username and password combination", ""


def sessionId_check(sessionId):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    # testing for empty string
    if sessionId == "":
        print("empty sessionId")
        return False

    # check if session is still valid
    count = collection.count_documents({"sessionId": sessionId})
    if count == 0:
        print("session Id not found in database")
        return False

    # check if the session has passed the timeout value
    timeoutAt = ""
    results = collection.find({"sessionId": sessionId})
    for result in results:
        timeoutAt = result["timeoutAt"]
    if timeoutAt < datetime.now():
        collection.update_one({"sessionId": sessionId}, {"$set": {"sessionId": ""}})
        print("sessionId expired")
        return False
    print("authentication successful")
    return True


def admin_check(sessionId):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    count = collection.count_documents({"sessionId": sessionId})
    if count == 0:
        print("sessionId not found in admin_check")
        return False

    role = ""
    results = collection.find({"sessionId": sessionId})
    for result in results:
        role = result["role"]

    if role != "admin":
        print("person logged in is not an admin")
        return False

    print("person logged in is an admin")
    return True


def delete_user(username):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    count = collection.count_documents({"username": username})
    if count == 0:
        return "user by that username does not exist"

    collection.delete_one({"username": username})
    return "user successfully deleted"


def get_username(sessionId):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    count = collection.count_documents({"sessionId": sessionId})
    if count == 0:
        return False, "user by that username does not exist"

    username = ""
    results = collection.find({"sessionId": sessionId})
    for result in results:
        username = result["username"]
    return True, username


def clean_up_downloads():
    download_path = os.getcwd() + "\\download"
    # clean up download folder if it is currently full
    if "download" in os.listdir():
        files = os.listdir(download_path)
        # clean up
        for file in files:
            # download files and then delete
            os.remove(f"{download_path}\\{file}")


def download_files(fileList, dataDict):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]
    fs = gridfs.GridFS(db, collection="DataCollection")

    # create the folder where our files will live temporarily
    download_path = os.getcwd() + os.sep + "download"
    # clean up download folder if it is currently full
    print(os.listdir(os.getcwd()))
    print(download_path)
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% RIGHT BEFORE WE BREAK %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    if "download" in os.listdir():
        files = os.listdir(download_path)
        # clean up when we are done
        for file in files:
            # download files and then delete
            os.remove(f"{download_path}{os.sep}{file}")

    # move the files saved in database to download folder
    for fileid in fileList:
        fileObj = fs.get(fileid)
        filename = fileObj.filename
        print(f"downloading: {filename}")
        with open(f"{download_path}{os.sep}{filename}", "wb") as f:
            f.write(fileObj.read())

    # move the text based database to download folder
    with open(f"{download_path}{os.sep}dataDict.txt", "w") as f:
        f.write(dataDict)

    print("zipping files now")
    # create a ZipFile object
    files = os.listdir(download_path)
    dateTag = str(datetime.now()).replace(" ", "_").replace(":", "_").replace(".", "_")
    zipFileName = f"{download_path}{os.sep}data_{dateTag}.zip"
    with ZipFile(zipFileName, "w") as zipObj:
        # Add multiple files to the zip
        for file in files:
            print(file)
            os.chdir(download_path)
            zipObj.write(f"{file}")
            # zipObj.write(f"{download_path}\\{file}")
    print(f"before: {os.getcwd()}")
    os.chdir("..")
    print(f"after changing we are now in: {os.getcwd()}")
    return zipFileName


def add_data(sessionId, data):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    fs = gridfs.GridFS(db, collection="DataCollection")

    count = collection.count_documents({"sessionId": sessionId})
    if count == 0:
        return "Unsuccessful data upload"

    file = data["file"]
    data["file"] = fs.put(file, filename=data["filename"])
    collection.update_one({"sessionId": sessionId}, {"$set": {f"dataUpload.{str(datetime.now())}": data}})
    return "Data upload successful!"


def read_user_data(sessionId):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    data = {
        "user_0": "nothing here"
    }
    count = 0
    results = collection.find({"sessionId": sessionId})
    for result in results:
        data[f"user_{str(count)}"] = result["dataUpload"]
        count += 1

    if data["user_0"] == "nothing here":
        return "database was read unsuccessfully"
    return data


def read_all_data(sessionId):
    # SETUP FOR DATABASE CONNECTION
    cluster = \
        MongoClient(
            "mongodb+srv://NickDBA:wHslF2yJ7otystjc@cluster0-blgpv.mongodb.net/test?retryWrites=true&w=majority")
    db = cluster["ElasticBeanDB"]  # database name goes here
    collection = db["DataCollection"]

    # can never be too careful with giving out ALL of our data
    if not admin_check(sessionId):
        return "database was read unsuccessfully"

    data = {
        "user_0": "nothing here"
    }
    count = 0

    results = collection.find({})
    for result in results:
        entry = f"user_{str(count)}"
        data[entry] = result["dataUpload"]
        count += 1

    if data["user_0"] == "nothing here":
        return "database was read unsuccessfully"
    return data


if __name__ == "__main__":
    TIME_ON_SITE = timedelta(days=7)

    # delete our two user accounts so we can restart
    BeginAgain = False

    if BeginAgain:
        print(delete_user("NickAdmin"))
        print(delete_user("NickUser"))

    # recreate the admin and user accounts
    if BeginAgain:
        username = "NickAdmin"
        role = "admin"
        password = create_new_user(username, role)
        print(username)
        print(password)
        print()
        username = "NickUser"
        role = "user"
        password = create_new_user(username, role)
        print(username)
        print(password)
