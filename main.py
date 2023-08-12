import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ["USERPROFILE"]))
USER_DATA = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ["USERPROFILE"]))

def get_secret_key():
    try:
        with open(LOCAL_STATE, "r", encoding = "utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        return win32crypt.CryptUnprotectData(base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]
    except Exception as e:
        print(f"\033[0;31m{e}\033[0m")
        print("ERROR: chrome secret key not found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print(f"\033[0;31m{e}\033[0m")
        print("ERROR: unable to decrypt... chrome version < 80 not supported")
        return ""
    
def get_db_connection(path: str):
    try:
        shutil.copy2(path, "table.db")
        return sqlite3.connect("table.db")
    except Exception as e:
        print(f"\033[0;31m{e}\033[0m")
        print("ERROR: chrome database not found")
        return None
    
def is_chrome_profile(folder_name: str):
    return folder_name.startswith("Profile") or folder_name == "Default"
        
if __name__ == "__main__":
    try:
        with open("details.csv", mode = "w", newline = "", encoding = "utf-8") as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=",")
            csv_writer.writerow(["index", "url", "username", "password"])
            secret_key = get_secret_key()
            folders = [element for element in os.listdir(USER_DATA) if is_chrome_profile(element)]
            for folder in folders:
                path = os.path.normpath(r"%s\%s\Login Data"%(USER_DATA,folder))
                connection = get_db_connection(path)
                if (secret_key and connection):
                    print(f"\033[1mPATH: {path}\033[0m\n")
                    cursor = connection.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        pairs = {
                            "index": index,
                            "url": login[0],
                            "username": login[1],
                        }
                        ciphertext = login[2]
                        if (pairs['index'] != "" and pairs['username'] != "" and ciphertext != ""):
                            pairs['password'] = decrypt_password(ciphertext, secret_key)
                            for key, value in pairs.items():
                                print(f"{key}: {value}")
                            values = pairs.values()
                            csv_writer.writerow(list(values))
                            print()
                    cursor.close()
                    connection.close()
                    os.remove("table.db")
    except Exception as e:
        print(f"ERROR: {e}")