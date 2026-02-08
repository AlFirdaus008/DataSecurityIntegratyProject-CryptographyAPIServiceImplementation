from cryptography.hazmat.primitives.asymmetric import ec, padding, ed25519, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import requests
import base64
import os
import json
from pathlib import Path
import tkinter as tk
from tkinter import filedialog

BASE_URL = "http://localhost:8080"
KEYS_DIR = Path("client_keys")
KEYS_DIR.mkdir(exist_ok=True)

class SecurityClient:
    def __init__(self, username: str, algorithm: str = "EC_SECP256R1"):
        self.username = username
        self.algorithm = algorithm
        self.private_key = None
        self.public_key = None
        self.token = None
        
    def _parse_response(self, response):
        try:
            return response.json()
        except json.JSONDecodeError:
            return {
                "error": "Server returned non-JSON response", 
                "status": response.status_code, 
                "text": response.text[:200]
            }
        except Exception as e:
            return {"error": str(e)}

    def generate_keypair(self):
        print(f"\n[{self.username}] Generating {self.algorithm} keypair...")
        
        if self.algorithm == "EC_SECP256K1":
            self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
            self.public_key = self.private_key.public_key()
            
        elif self.algorithm == "EC_SECP256R1":
            self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.public_key = self.private_key.public_key()
            
        elif self.algorithm == "ED25519":
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
            
        elif self.algorithm == "RSA":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        
        self.save_keys()
        print(f"✓ Keypair generated and saved")
        
    def save_keys(self):
        priv_path = KEYS_DIR / f"{self.username}_priv.pem"
        pub_path = KEYS_DIR / f"{self.username}_pub.pem"
        
        if self.algorithm in ["EC_SECP256K1", "EC_SECP256R1", "RSA"]:
            priv_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif self.algorithm == "ED25519":
            priv_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
        with open(priv_path, "wb") as f:
            f.write(priv_bytes)
        
        with open(pub_path, "wb") as f:
            f.write(pub_bytes)
    
    def register(self):
        print(f"\n[{self.username}] Registering to server...")
        
        pub_path = KEYS_DIR / f"{self.username}_pub.pem"
        
        try:
            with open(pub_path, "rb") as f:
                files = {"public_key_file": (f"{self.username}_pub.pem", f, "application/x-pem-file")}
                data = {
                    "username": self.username,
                    "algorithm": self.algorithm
                }
                
                response = requests.post(f"{BASE_URL}/store", data=data, files=files)
            
            if response.status_code == 200:
                result = response.json()
                self.token = result["access_token"]
                print(f"✓ Registration successful!")
                print(f"  Key hash: {result['key_hash_short']}")
                print(f"  Token: {self.token[:30]}...")
                return result
            else:
                print(f"✗ Registration failed: {self._parse_response(response)}")
                return None
        except Exception as e:
            print(f"✗ Registration error: {e}")
            return None
    
    def sign_message(self, message: str) -> str:
        message_bytes = message.encode('utf-8')
        
        if self.algorithm in ["EC_SECP256K1", "EC_SECP256R1"]:
            signature = self.private_key.sign(
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        elif self.algorithm == "ED25519":
            signature = self.private_key.sign(message_bytes)
        elif self.algorithm == "RSA":
            signature = self.private_key.sign(
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message: str, signature_b64: str):
        print(f"\n[{self.username}] Verifying signature...")
        
        headers = {"Authorization": f"Bearer {self.token}"}
        data = {
            "username": self.username,
            "message": message,
            "signature_base64": signature_b64
        }
        
        try:
            response = requests.post(f"{BASE_URL}/verify", data=data, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                status = "✓" if result["valid"] else "✗"
                print(f"{status} {result['message']}")
                return result
            else:
                print(f"✗ Verification failed: {self._parse_response(response)}")
                return None
        except Exception as e:
            print(f"✗ Verification error: {e}")
            return None
    
    def send_message(self, receiver: str, message: str, encryption_type: str = "symmetric"):
        print(f"\n[{self.username}] Sending message to {receiver}...")
        
        headers = {"Authorization": f"Bearer {self.token}"}
        data = {
            "sender": self.username,
            "receiver": receiver,
            "message": message,
            "encryption_type": encryption_type
        }
        
        try:
            response = requests.post(f"{BASE_URL}/relay", data=data, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✓ Message relayed successfully!")
                print(f"  Encryption: {result['relay_data']['encryption_type']}")
                print(f"  Algorithm: {result['relay_data'].get('algorithm', 'N/A')}")
                print(f"  Message ID: {result['relay_data']['message_id']}")
                return result
            else:
                print(f"✗ Message relay failed: {self._parse_response(response)}")
                return None
        except Exception as e:
            print(f"✗ Sending error: {e}")
            return None

    def upload_pdf(self, pdf_path: str):
        print(f"\n[{self.username}] Uploading PDF...")
        
        headers = {"Authorization": f"Bearer {self.token}"}
        
        try:
            with open(pdf_path, "rb") as f:
                files = {"file": (os.path.basename(pdf_path), f, "application/pdf")}
                data = {"username": self.username}
                
                response = requests.post(f"{BASE_URL}/upload-pdf", data=data, files=files, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✓ PDF uploaded successfully!")
                print(f"  Hash: {result['hash'][:32]}...")
                return result
            else:
                print(f"✗ Upload failed: {self._parse_response(response)}")
                return None
        except Exception as e:
            print(f"✗ Upload error: {e}")
            return None

def select_pdf_from_system():
    print("\n[SYSTEM] Membuka File Manager...")
    print("Silakan pilih file PDF yang ingin di-upload...")
    
    try:
        root = tk.Tk()
        root.withdraw() 
        root.attributes('-topmost', True) 
        
        file_path = filedialog.askopenfilename(
            title="Select Document PDF for Punk Records",
            filetypes=[("PDF Files", ".pdf"), ("All Files", ".*")]
        )
        
        root.destroy() 

        if file_path:
            print(f"✓ File terpilih: {file_path}")
            return str(file_path)
        else:
            print("Cancel")
            return None
            
    except Exception as e:
        print(f"⚠ Gagal membuka file dialog: {e}")
        try:
            path = input("Enter the PDF file path manually: ").strip().strip('"')
            if os.path.exists(path):
                return path
        except:
            pass
        return None

def demo_complete():
    print(" PUNK RECORDS SECURITY SERVICE - COMPLETE DEMONSTRATION")
    print(" Egghead Laboratory - Dr. Vegapunk")
    
    print("\n[SYSTEM] Checking server health...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            health = response.json()
            print(f"✓ Server is running")
            print(f"  Status: {health['status']}")
            print(f"  Users registered: {health['users_registered']}")
        else:
            print("✗ Server health check failed!")
            return
    except Exception as e:
        print(f"✗ Cannot connect to server: {e}")
        print(f"  Make sure server is running at {BASE_URL}")
        return

    print(" [TEST 1] USER REGISTRATION dengan berbagai algoritma")

    piji = SecurityClient("piji", "EC_SECP256R1")
    piji.generate_keypair()
    piji.register()

    dimas = SecurityClient("dimas", "ED25519")
    dimas.generate_keypair()
    dimas.register()

    dapa = SecurityClient("dapa", "RSA")
    dapa.generate_keypair()
    dapa.register()

    firdaus = SecurityClient("firdaus", "EC_SECP256K1")
    firdaus.generate_keypair()
    firdaus.register()

    print(" [TEST 2] DIGITAL SIGNATURE VERIFICATION")
    
    message = "Punk Records Research Report - Confidential Data from Egghead Lab"

    print(f"\n2.1. piji signs message (EC SECP256R1)")
    sig_piji = piji.sign_message(message)
    print(f"  Signature: {sig_piji[:50]}...")
    piji.verify_signature(message, sig_piji)

    print(f"\n2.2. dimas signs message (ED25519)")  
    sig_dimas = dimas.sign_message(message)
    print(f"  Signature: {sig_dimas[:50]}...")
    dimas.verify_signature(message, sig_dimas)

    print(f"\n2.3. dapa signs message (RSA)")
    sig_dapa = dapa.sign_message(message)
    print(f"  Signature: {sig_dapa[:50]}...")
    dapa.verify_signature(message, sig_dapa)

    print(f"\n2.4. firdaus signs message (EC SECP256K1)")
    sig_firdaus = firdaus.sign_message(message)
    print(f"  Signature: {sig_firdaus[:50]}...")
    firdaus.verify_signature(message, sig_firdaus)
    
    print(f"\n2.5. Testing tampered message (should fail)")
    tampered_message = "Punk Records - TAMPERED DATA"
    piji.verify_signature(tampered_message, sig_piji)

    print(" [TEST 3] ENCRYPTED MESSAGE RELAY")
    
    secret_message = "Coordinates: 12.3456N, 78.9012E - Secret Laboratory Location"

    print("\n3.1. Symmetric encryption (AES-256-GCM)")
    piji.send_message("dimas", secret_message, "symmetric")

    print("\n3.2. Asymmetric encryption (RSA)")
    piji.send_message("dapa", secret_message, "asymmetric")

    print("\n [TEST 4] PDF DOCUMENT UPLOAD")
    pdf_path = select_pdf_from_system()

    if pdf_path and os.path.exists(pdf_path):
        piji.upload_pdf(pdf_path)
    else:
        print("Skip, PDF not found")
    
    print(" [TEST 5] LIST REGISTERED USERS")
    
    headers = {"Authorization": f"Bearer {piji.token}"}
    response = requests.get(f"{BASE_URL}/users", headers=headers)
    if response.status_code == 200:
        result = response.json()
        print(f"\n✓ Total registered users: {result['total_users']}")
        for user in result['users']:
            print(f"  - {user['username']} ({user['algorithm']})")
    
    print(" DEMONSTRATION COMPLETE!")

if __name__ == "__main__":
    demo_complete()