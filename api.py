from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, List
import os
from datetime import datetime, timedelta
import hashlib
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import jwt

app = FastAPI(
    title="Punk Records Security Service", 
    description="Secure Gateway for Egghead Laboratory. Features include Key Management, Digital Signatures, and Hybrid Encryption.",
    version="1.0.0",
    contact={
        "name": "Egghead Lab Security",
        "email": "security@egghead.vegapunk.net"
    }
)
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORAGE_DIR = Path("storage")
USERS_FILE = STORAGE_DIR / "users.txt"
KEYS_DIR = STORAGE_DIR / "keys"
MESSAGES_DIR = STORAGE_DIR / "messages"
PDF_DIR = STORAGE_DIR / "pdfs"
SECRET_KEY = "vegapunk-secret-key-egghead-lab-2025"
ALGORITHM = "HS256"
SECRET_KEY = "vegapunk-secret-key-egghead-lab-2025"
ALGORITHM = "HS256"

for dir_path in [STORAGE_DIR, KEYS_DIR, MESSAGES_DIR, PDF_DIR]:
    dir_path.mkdir(exist_ok=True)

if not USERS_FILE.exists():
    USERS_FILE.write_text("")

PUNKHAZARD_DIR = Path("punkhazard-keys")
SERVER_KEY_PATH = PUNKHAZARD_DIR / "priv.pem"

if SERVER_KEY_PATH.exists():
    print(f"[OK] Loading Server Authority Key from: {SERVER_KEY_PATH}")
    with open(SERVER_KEY_PATH, "rb") as f:
        SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
else:
    print("[WARN] WARNING: Kunci Punk Hazard tidak ditemukan! Generating temporary key...")
    SERVER_PRIVATE_KEY = ec.generate_private_key(ec.SECP256K1(), default_backend())

def create_jwt_token(username: str, expires_delta: timedelta = timedelta(hours=24)) -> str:
    expire = datetime.utcnow() + expires_delta
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def save_user(username: str, algorithm: str, key_hash: str):
    user_entry = f"{username}|{algorithm}|{key_hash}|{datetime.now().isoformat()}\n"
    with open(USERS_FILE, "a") as f:
        f.write(user_entry)

def get_user(username: str) -> Optional[dict]:
    if not USERS_FILE.exists():
        return None
    
    with open(USERS_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 3 and parts[0] == username:
                return {
                    "username": parts[0],
                    "algorithm": parts[1],
                    "key_hash": parts[2],
                    "registered_at": parts[3] if len(parts) > 3 else None
                }
    return None

def get_all_users() -> List[dict]:
    users = []
    if not USERS_FILE.exists():
        return users
    
    with open(USERS_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 3:
                users.append({
                    "username": parts[0],
                    "algorithm": parts[1],
                    "key_hash": parts[2][:16] + "...",
                    "registered_at": parts[3] if len(parts) > 3 else None
                })
    return users

def load_public_key(username: str):
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {username} not found")
    
    key_path = KEYS_DIR / f"{username}_pub.pem"
    if not key_path.exists():
        raise HTTPException(status_code=404, detail=f"Public key for {username} not found")
    
    with open(key_path, "rb") as f:
        key_data = f.read()
    
    algorithm = user["algorithm"]
    
    try:
        if algorithm == "EC_SECP256K1" or algorithm == "EC_SECP256R1":
            return serialization.load_pem_public_key(key_data, backend=default_backend())
        elif algorithm == "ED25519":
            try:
                return serialization.load_pem_public_key(key_data, backend=default_backend())
            except:
                return ed25519.Ed25519PublicKey.from_public_bytes(key_data)
        elif algorithm == "RSA":
            return serialization.load_pem_public_key(key_data, backend=default_backend())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load public key: {str(e)}")

@app.get("/health", tags=["System Status"])
async def health_check():
    user_count = len(get_all_users())
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat(),
        "users_registered": user_count,
        "service": "Punk Records v1"
    }

@app.get("/", tags=["System Status"])
async def get_index() -> dict:
    return {
        "message": "Welcome to Punk Records Security Service!",
        "lab": "Egghead Laboratory",
        "scientist": "Dr. Vegapunk",
        "docs": "http://localhost:8080/docs",
        "endpoints": {
            "health": "/health",
            "store_key": "/store (POST)",
            "verify_signature": "/verify (POST)",
            "relay_message": "/relay (POST)",
            "upload_pdf": "/upload-pdf (POST)",
            "list_users": "/users (GET)"
        }
    }

@app.post("/upload-pdf", tags=["File Integrity"])
async def upload_pdf(
    file: UploadFile = File(...),
    username: str = Form(...),
    current_user: str = Depends(verify_jwt_token)
):
    fname = file.filename
    ctype = file.content_type
    
    if ctype != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")
    
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {username} not found")
    
    try:
        contents = await file.read()
        pdf_hash = compute_hash(contents) 

        pdf_filename = f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{fname}"
        pdf_path = PDF_DIR / pdf_filename
        
        with open(pdf_path, "wb") as f:
            f.write(contents)

        hash_bytes = bytes.fromhex(pdf_hash) 

        server_signature = SERVER_PRIVATE_KEY.sign(
            hash_bytes, 
            ec.ECDSA(hashes.SHA256())
        )

        server_sig_b64 = base64.b64encode(server_signature).decode('utf-8')

        metadata = {
            "filename": fname,
            "saved_as": pdf_filename,
            "owner": username,
            "hash": pdf_hash,
            "server_signature": server_sig_b64, 
            "size": len(contents),
            "uploaded_at": datetime.now().isoformat(),
            "integrity_status": "Notarized by Egghead Authority"
        }
        
        metadata_path = PDF_DIR / f"{pdf_filename}.meta.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    
    return {
        "message": "PDF uploaded & NOTARIZED successfully!",
        "filename": fname,
        "content-type": ctype,
        "hash": pdf_hash,
        "owner": username,
        "server_signature": server_sig_b64, # Tampilkan signature ke user
        "note": "File integrity guaranteed by Server Authority Signature."
    }

@app.post("/store", tags=["Key Management"])
async def store_pubkey(
    username: str = Form(...),
    algorithm: str = Form(...),
    public_key_file: UploadFile = File(...)
):
    existing_user = get_user(username)
    if existing_user:
        raise HTTPException(status_code=400, detail=f"User {username} already exists")
    
    try:
        key_contents = await public_key_file.read()
        key_hash = compute_hash(key_contents)
        
        try:
            if algorithm in ["EC_SECP256K1", "EC_SECP256R1"]:
                serialization.load_pem_public_key(key_contents, backend=default_backend())
            elif algorithm == "ED25519":
                try:
                    serialization.load_pem_public_key(key_contents, backend=default_backend())
                except:
                    ed25519.Ed25519PublicKey.from_public_bytes(key_contents)
            elif algorithm == "RSA":
                serialization.load_pem_public_key(key_contents, backend=default_backend())
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid public key format: {str(e)}")
        
        key_path = KEYS_DIR / f"{username}_pub.pem"
        with open(key_path, "wb") as f:
            f.write(key_contents)
        
        save_user(username, algorithm, key_hash)
        token = create_jwt_token(username)
        
        msg = f"Public key for user '{username}' stored successfully"
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store public key: {str(e)}")
    
    return {
        "message": msg,
        "username": username,
        "algorithm": algorithm,
        "key_hash": key_hash,
        "key_hash_short": key_hash[:32] + "...",
        "access_token": token,
        "token_type": "bearer",
        "registered_at": datetime.now().isoformat()
    }

@app.post("/verify", tags=["Cryptography Operations"])
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature_base64: str = Form(...),
    current_user: str = Depends(verify_jwt_token)
):
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {username} not found")
    
    try:
        public_key = load_public_key(username)
        signature_bytes = base64.b64decode(signature_base64)
        message_bytes = message.encode('utf-8')
        
        key_path = KEYS_DIR / f"{username}_pub.pem"
        with open(key_path, "rb") as f:
            current_key = f.read()
        
        current_hash = compute_hash(current_key)
        if current_hash != user["key_hash"]:
            raise HTTPException(
                status_code=400, 
                detail="Public key integrity check failed! Key has been tampered."
            )
        
        algorithm = user["algorithm"]
        verification_passed = False
        
        if algorithm == "EC_SECP256K1" or algorithm == "EC_SECP256R1":
            try:
                public_key.verify(
                    signature_bytes,
                    message_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                verification_passed = True
            except Exception:
                verification_passed = False
                
        elif algorithm == "ED25519":
            try:
                public_key.verify(signature_bytes, message_bytes)
                verification_passed = True
            except Exception:
                verification_passed = False
                
        elif algorithm == "RSA":
            try:
                public_key.verify(
                    signature_bytes,
                    message_bytes,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                verification_passed = True
            except Exception:
                verification_passed = False
        
        if verification_passed:
            msg = "Signature verification successful! Message is authentic."
            status = "valid"
        else:
            msg = "Signature verification failed! Message may have been tampered."
            status = "invalid"
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")
    
    return {
        "message": msg,
        "status": status,
        "valid": verification_passed,
        "signer": username,
        "algorithm": algorithm,
        "verified_at": datetime.now().isoformat(),
        "integrity_check": "passed"
    }

@app.post("/relay", tags=["Secure Messaging"])
async def relay(
    sender: str = Form(...),
    receiver: str = Form(...),
    message: str = Form(...),
    encryption_type: str = Form(default="symmetric"),
    current_user: str = Depends(verify_jwt_token)
):
    sender_user = get_user(sender)
    if not sender_user:
        raise HTTPException(status_code=404, detail=f"Sender {sender} not found")
    
    receiver_user = get_user(receiver)
    if not receiver_user:
        raise HTTPException(status_code=404, detail=f"Receiver {receiver} not found")
    
    if current_user != sender:
        raise HTTPException(status_code=403, detail="You can only send messages as yourself")
    
    try:
        receiver_pubkey = load_public_key(receiver)
        message_bytes = message.encode('utf-8')
        
        if encryption_type == "symmetric":
            aes_key = os.urandom(32)
            iv = os.urandom(12)
            
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
            tag = encryptor.tag
            
            if receiver_user["algorithm"] == "RSA":
                encrypted_key = receiver_pubkey.encrypt(
                    aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                encrypted_key = aes_key
            
            message_id = f"{sender}_to_{receiver}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message_data = {
                "message_id": message_id,
                "sender": sender,
                "receiver": receiver,
                "encryption_type": "symmetric",
                "algorithm": "AES-256-GCM",
                "encrypted_message": base64.b64encode(ciphertext).decode(),
                "encrypted_key": base64.b64encode(encrypted_key).decode() if isinstance(encrypted_key, bytes) else encrypted_key,
                "iv": base64.b64encode(iv).decode(),
                "tag": base64.b64encode(tag).decode(),
                "timestamp": datetime.now().isoformat()
            }
            
            msg = f"Message encrypted with AES-256-GCM and relayed to {receiver}"
            
        elif encryption_type == "asymmetric":
            if receiver_user["algorithm"] == "RSA":
                ciphertext = receiver_pubkey.encrypt(
                    message_bytes,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                message_id = f"{sender}_to_{receiver}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                message_data = {
                    "message_id": message_id,
                    "sender": sender,
                    "receiver": receiver,
                    "encryption_type": "asymmetric",
                    "algorithm": "RSA-OAEP",
                    "encrypted_message": base64.b64encode(ciphertext).decode(),
                    "timestamp": datetime.now().isoformat()
                }
                
                msg = f"Message encrypted with RSA and relayed to {receiver}"
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Asymmetric encryption only supported for RSA keys. Receiver uses {receiver_user['algorithm']}"
                )
        else:
            raise HTTPException(status_code=400, detail="Invalid encryption type. Use 'symmetric' or 'asymmetric'")
        
        message_file = MESSAGES_DIR / f"{message_id}.json"
        with open(message_file, "w") as f:
            json.dump(message_data, f, indent=2)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Message relay failed: {str(e)}")
    
    return {
        "message": msg,
        "status": "success",
        "relay_data": message_data
    }

@app.get("/users", tags=["Utilities"])
async def list_users(current_user: str = Depends(verify_jwt_token)):
    users = get_all_users()
    return {
        "total_users": len(users),
        "users": users,
        "requested_by": current_user
    }

@app.get("/messages/{receiver}", tags=["Utilities"])
async def get_messages(
    receiver: str,
    current_user: str = Depends(verify_jwt_token)
):
    if current_user != receiver:
        raise HTTPException(status_code=403, detail="You can only view your own messages")
    
    messages = []
    for msg_file in MESSAGES_DIR.glob(f"*_to_{receiver}_*.json"):
        with open(msg_file, "r") as f:
            msg_data = json.load(f)
            messages.append(msg_data)
    
    return {
        "receiver": receiver,
        "message_count": len(messages),
        "messages": messages
    }

@app.post("/generate-keypair", tags=["Testing Tools"])
async def generate_keypair(
    username: str = Form(...),
    algorithm: str = Form(default="EC_SECP256R1")
):
    try:
        if algorithm == "EC_SECP256K1":
            private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        elif algorithm == "EC_SECP256R1":
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif algorithm == "ED25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif algorithm == "RSA":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")
        
        public_key = private_key.public_key()
        
        if algorithm in ["EC_SECP256K1", "EC_SECP256R1", "RSA", "ED25519"]:
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
        client_keys_dir = Path("client_keys")
        client_keys_dir.mkdir(exist_ok=True)
        
        priv_path = client_keys_dir / f"{username}_private.pem"
        pub_path = client_keys_dir / f"{username}_public.pem"
        
        with open(priv_path, "wb") as f:
            f.write(priv_bytes)
        
        with open(pub_path, "wb") as f:
            f.write(pub_bytes)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")
    
    return {
        "message": f"Keypair generated successfully for {username}",
        "algorithm": algorithm,
        "private_key_pem": priv_bytes.decode('utf-8'),
        "public_key_pem": pub_bytes.decode('utf-8'),
        "files_saved": {
            "private": str(priv_path),
            "public": str(pub_path)
        },
        "next_steps": [
            "1. Copy public_key_pem content",
            "2. Save it as a .pem file",
            "3. Use /store endpoint to register this public key",
            "4. Keep private_key_pem secure for signing messages"
        ]
    }

@app.post("/sign-message", tags=["Testing Tools"])
async def sign_message_endpoint(
    username: str = Form(...),
    message: str = Form(...),
    private_key_file: UploadFile = File(...)
):
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {username} not found. Register first using /store")
    
    try:
        private_key_bytes = await private_key_file.read()
        algorithm = user["algorithm"]
        
        if algorithm in ["EC_SECP256K1", "EC_SECP256R1", "RSA"]:
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
                backend=default_backend()
            )
        elif algorithm == "ED25519":
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
                backend=default_backend()
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")
        
        message_bytes = message.encode('utf-8')
        
        if algorithm in ["EC_SECP256K1", "EC_SECP256R1"]:
            signature = private_key.sign(
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        elif algorithm == "ED25519":
            signature = private_key.sign(message_bytes)
        elif algorithm == "RSA":
            signature = private_key.sign(
                message_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")
    
    return {
        "message": "Message signed successfully",
        "original_message": message,
        "signature_base64": signature_b64,
        "signer": username,
        "algorithm": algorithm,
        "signed_at": datetime.now().isoformat(),
        "next_steps": [
            "1. Copy the signature_base64",
            "2. Use /verify endpoint to verify this signature",
            "3. You need JWT token (get from /store when registering)"
        ]
    }

@app.post("/sign-message-text", tags=["Testing Tools"])
async def sign_message_text(
    username: str = Form(...),
    message: str = Form(...),
    private_key_base64: str = Form(...)
):
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {username} not found. Register first using /store")
    
    try:
        try:
            private_key_bytes = base64.b64decode(private_key_base64)
        except:
            private_key_bytes = private_key_base64.encode('utf-8')
        
        algorithm = user["algorithm"]
        
        if algorithm in ["EC_SECP256K1", "EC_SECP256R1", "RSA", "ED25519"]:
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
                backend=default_backend()
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")
        
        message_bytes = message.encode('utf-8')
        
        if algorithm in ["EC_SECP256K1", "EC_SECP256R1"]:
            signature = private_key.sign(
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        elif algorithm == "ED25519":
            signature = private_key.sign(message_bytes)
        elif algorithm == "RSA":
            signature = private_key.sign(
                message_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")
    
    return {
        "message": "Message signed successfully",
        "original_message": message,
        "signature_base64": signature_b64,
        "signer": username,
        "algorithm": algorithm,
        "signed_at": datetime.now().isoformat()
    }