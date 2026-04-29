import secrets
import string
import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManagerV11:
    def __init__(self):
        self.data_file = "passwords.enc"
        
    def generate_key(self, master_password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def encrypt_data(self, data, key):
        f = Fernet(key)
        return f.encrypt(json.dumps(data).encode())

    def decrypt_data(self, encrypted_data, key):
        f = Fernet(key)
        return json.loads(f.decrypt(encrypted_data).decode())

    def generate_password(self, length=16, use_symbols=True):
        chars = string.ascii_letters + string.digits
        if use_symbols:
            chars += "!@#$%^&*()-_=+"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def save_password(self, master_password, service, username, password):
        salt = os.urandom(16)
        key = self.generate_key(master_password, salt)
        
        data = {}
        if os.path.exists(self.data_file):
            with open(self.data_file, 'rb') as f:
                content = f.read()
                old_salt = content[:16]
                old_encrypted = content[16:]
                old_key = self.generate_key(master_password, old_salt)
                try:
                    data = self.decrypt_data(old_encrypted, old_key)
                except:
                    data = {}
        
        data[service] = {"username": username, "password": password}
        encrypted_data = self.encrypt_data(data, key)
        
        with open(self.data_file, 'wb') as f:
            f.write(salt + encrypted_data)
        
        print(f"✅ تم حفظ كلمة سر {service} بنجاح")

    def check_password_strength(self, password):
        score = 0
        if len(password) >= 12: score += 1
        if len(password) >= 16: score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*()-_=+" for c in password): score += 1
        
        levels = ["ضعيف جدا", "ضعيف", "متوسط", "قوي", "قوي جدا", "ممتاز"]
        return levels[min(score, 5)]

def main():
    pm = PasswordManagerV11()
    print("=== Password Manager V11 + Security Suite ===")
    
    while True:
        print("\n1- توليد كلمة سر جديدة")
        print("2- فحص قوة كلمة سر") 
        print("3- حفظ كلمة سر مشفرة")
        print("4- خروج")
        choice = input("اختار: ")
        
        if choice == "1":
            length = int(input("طول كلمة السر: ") or "16")
            pwd = pm.generate_password(length)
            print(f"كلمة السر: {pwd}")
            print(f"القوة: {pm.check_password_strength(pwd)}")
            
        elif choice == "2":
            pwd = input("ادخل كلمة السر: ")
            print(f"القوة: {pm.check_password_strength(pwd)}")
            
        elif choice == "3":
            master = input("الماستر باسورد: ")
            service = input("اسم الموقع/الخدمة: ")
            user = input("اسم المستخدم: ")
            pwd = input("كلمة السر: ")
            pm.save_password(master, service, user, pwd)
            
        elif choice == "4":
            break

if __name__ == "__main__":
    main()
