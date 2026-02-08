# Punk Records Security Service - Complete Solution

**Final Exam (UAS) - Data Security and Integrity Bachelor of Data Science**  
**Semester 2025/2026**

## 📁 File Project Structure

```
kid-uas/
├── main.py
├── api.py
├── client.py
├── README.md
├── requirements.txt
├── storage/
│   ├── users.txt
│   ├── keys/
│   ├── messages/
│   └── pdfs/
├── client_keys/
└── punkhazard-keys/
    ├── priv.pem
    ├── pub.pem
    ├── priv19.pem
    └── pub19.pem
```

## 🎯 Implementation Summary |

Feature,Status,Description
Store Public Key :✅,Multiuser + Integrity Check + Secure Session
Verify Signature :✅,Cipher Variations + Integrity Check + Secure Session
Relay Message :✅,Cipher Variations + Multiuser + Secure Session
Sign PDF :✅,Integrity Check + Secure Session

### Implemented Aspects:

1. ✅ Multiuser: The system handles multiple users with different algorithms.
2. ✅ Secure Session: Authentication (Bearer Token) on every request.
3. ✅ Integrity Check: SHA-256 hashing for key and PDF verification.
4. ✅ Cipher Variations:
   Asymmetric: EC (SECP256K1, SECP256R1), ED25519, RSA
   Symmetric: AES-256-GCM

## 🚀 Installation & Setup

### 1. Prerequisites

```bash
# Python 3.9+
python --version
```

### 2. Install Dependencies

Create a file `requirements.txt`:

```txt
fastapi==0.104.0
uvicorn[standard]==0.24.0
cryptography==41.0.0
pyjwt==2.8.0
python-multipart==0.0.6
requests==2.31.0
```

Install:

```bash
pip install -r requirements.txt
# OR using uv
uv pip install -r requirements.txt
```

### 3. Run the Server

```bash
# Method 1: Using uv (Recommended per Lab instructions)
uv run main.py

# Method 2: Standard Python
python main.py

# Method 3: Uvicorn direct
uvicorn api:app --host 0.0.0.0 --port 8080 --reload
```

Server URL: **http://localhost:8080**
API Documentation: **http://localhost:8080/docs**

### 4. Run Client Simulation

Other Terminal:

```bash
python client.py
```

## 📖 Implementation Explaination

### File `api.py` - Server Implementation

#### 1. **Endpoint `/store` - Store Public Key**

```python
@app.post("/store")
async def store_pubkey(
    username: str = Form(...),
    algorithm: str = Form(...),
    public_key_file: UploadFile = File(...)
):
```

**Implementation:**

- ✅ Accepts public key upload from the user.
- ✅ Validates key format according to the algorithm.
- ✅ Computes SHA-256 hash for **integrity check.**
- ✅ Saves to file `storage/keys/{username}_pub.pem.`
- ✅ Saves user metadata to `storage/users.txt` (format: `username|algorithm|key_hash|timestamp`)
- ✅ Generates **JWT token** for secure session.
- ✅ Return token to client

**Storage Format (`users.txt`):**

```
Dimas|EC_SECP256R1|8f3b2d1a4c5e...|2025-12-09T10:30:00
Daffa|ED25519|7a9c4e2f1b8d...|2025-12-09T10:31:00
Piji|RSA|3d5a7f1c9e2b...|2025-12-09T10:32:00
Firdaus|EC_SECP256R1|8f3sd2d13as4c5e...|2025-12-09T10:32:05
```

#### 2. **Endpoint `/verify` - Verifikasi Signature**

```python
@app.post("/verify")
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature_base64: str = Form(...),
    current_user: str = Depends(verify_jwt_token)
):
```

**Implementation:**

- ✅ **Secure session**: Verify JWT token from header
- ✅ Load public key from storage
- ✅ **Integrity check**: Verify key hash is still the same
- ✅ **Variasi cipher**: Support EC, ED25519, RSA
- ✅ Verifies signature according to algorithm:
  - EC: `ECDSA with SHA-256`
  - ED25519: `Native Ed25519 signature`
  - RSA: `PSS with SHA-256`
- ✅ Returns verification result (valid/invalid).

#### 3. **Endpoint `/relay` - Relay Message**

```python
@app.post("/relay")
async def relay(
    sender: str = Form(...),
    receiver: str = Form(...),
    message: str = Form(...),
    encryption_type: str = Form(default="symmetric"),
    current_user: str = Depends(verify_jwt_token)
):
```

**Implementation:**

- ✅ **Multiuser**: Verify sender and receiver exist
- ✅ **Secure session**: JWT authentication
- ✅ **Variation cipher**:

  **Symmetric (AES-256-GCM):**

  1. Generate random AES key (256-bit)
  2. Encrypts message with AES-GCM.
  3. Encrypts AES key with receiver's public key (hybrid encryption).
  4. Save encrypted package to `storage/messages/`

  **Asymmetric (RSA-OAEP):**

  1. Encrypts message directly with receiver's RSA public key.
  2. Save to `storage/messages/`

#### 4. **Endpoint `/upload-pdf` - Upload & Sign PDF**

```python
@app.post("/upload-pdf")
async def upload_pdf(
    file: UploadFile = File(...),
    username: str = Form(...),
    current_user: str = Depends(verify_jwt_token)
):
```

**Implementation:**

- ✅ **Secure session**: JWT authentication
- ✅ Validate content type (must be PDF)
- ✅ **Integrity check**: Compute SHA-256 hash of the PDF
- ✅ Save PDF to `storage/pdfs/`
- ✅ Save metadata (hash, owner, timestamp) to JSON
- ✅ Returns hash that can be signed with private key.

### File `client.py` - Client Implementation

**Class `SecurityClient`:**

```python
class SecurityClient:
    def __init__(self, username: str, algorithm: str):
        # Initialize client with username and algorithm

    def generate_keypair(self):
        # Generate private & public key accordance to algorithm
        # Save to client_keys/

    def register(self):
        # Upload public key ke server via /store
        # Store JWT token

    def sign_message(self, message: str) -> str:
        # Sign message with private key
        # Return base64 signature

    def verify_signature(self, message: str, signature: str):
        # Verify via API /verify

    def send_message(self, receiver: str, message: str, encryption_type: str):
        # Send encrypted message via /relay

    def upload_pdf(self, pdf_path: str):
        # Upload PDF via /upload-pdf
```

**Function `demo_complete()`:**

- Test 1: Register 3 users (Dimas, Daffa, Piji, Firdaus) with different algorithms.
- Test 2: Digital signature verification.
- Test 3: Message relay (symmetric & asymmetric)
- Test 4: PDF upload
- Test 5: List users

## 🔐 Cryptographic Algorithm Details

### 1. Elliptic Curve (EC SECP256R1)

- **Signature**: ECDSA with SHA-256
- **Key size**: 256-bit
- **Use case**: Mobile devices, IoT

### 2. Ed25519

- **Signature**: EdDSA
- **Key size**: 256-bit
- **Speed**: Fastest signature algorithm
- **Use case**: Modern applications

### 3. RSA 2048

- **Signature**: PSS with SHA-256
- **Encryption**: OAEP with SHA-256
- **Key size**: 2048-bit
- **Use case**: Traditional systems, full asymmetric encryption

### 4. AES-256-GCM (Symmetric)

- **Mode**: Galois/Counter Mode (authenticated encryption)
- **Key size**: 256-bit
- **Use case**: Hybrid encryption (encrypt message, then encrypt key)

## 🧪 Testing

### Manual Test with cURL

#### 1. Health Check

```bash
curl http://localhost:8080/health
```

#### 2. Register User

```bash
# Generate key first
python -c "
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

key = ec.generate_private_key(ec.SECP256R1(), default_backend())
pub = key.public_key()

with open('test_pub.pem', 'wb') as f:
    f.write(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
"

# Upload
curl -X POST http://localhost:8080/store \
  -F "username=TestUser" \
  -F "algorithm=EC_SECP256R1" \
  -F "public_key_file=@test_pub.pem"
```

#### 3. List Users (with token)

```bash
curl -X GET http://localhost:8080/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Automated Test

```bash
python client.py
```

Features successfully demonstrated:
✓ Multiuser registration (4 users with different algorithm)
✓ Secure session (JWT token authentication)
✓ Integrity check (SHA-256 key hashing)
✓ Digital signature verification (EC, ED25519, RSA)
✓ Message relay with encryption:

- Symmetric: AES-256-GCM
- Asymmetric: RSA-OAEP
  ✓ PDF document upload with hash verification
  ✓ User management

```

```
