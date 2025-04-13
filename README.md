# 🔐 Encrypt-Decrypt and SQL Injection Detector

A lightweight web application that offers:

- **AES-based encryption and decryption** of user-provided text.
- **Basic SQL Injection detection** by analyzing input strings for common SQL injection patterns.

🌐 Live Demo: [wms.senipatel.vercel.app](https://wms.senipatel.vercel.app)

---

## 🛠️ Features

### 🔒 Encryption & Decryption

- Utilizes the Web Crypto API to perform AES encryption and decryption.
- Users can input plaintext and a secret key to encrypt the text.
- Encrypted text can be decrypted using the same secret key.

### 🛡️ SQL Injection Detection

- Analyzes input strings for patterns commonly associated with SQL injection attacks.
- Flags inputs containing suspicious patterns such as `' OR '1'='1'`, `--`, `;`, etc.
- Provides immediate feedback to the user about potential SQL injection risks.

---

## 🚀 Getting Started

To run the application locally:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/senipatel/Encrypt-Decrypt-and-SQL-Injection-Detector.git
   cd Encrypt-Decrypt-and-SQL-Injection-Detector

2. Open index.html in your web browser:
   - You can simply double-click the index.html file, or serve it using a local development server:

---

 ## 👤 Author
Seni Patel – GitHub Profile

--- 

## 🙌 Acknowledgements
  - Inspired by the need for simple tools to demonstrate encryption and basic SQL injection detection.
  - Utilizes the Web Crypto API for cryptographic functions.
