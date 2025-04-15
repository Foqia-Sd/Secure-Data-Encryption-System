# 🔐 Secure Data Encryption System

A Streamlit-based secure data storage and retrieval system using encryption. This project allows users to register, log in, store encrypted text data, and retrieve or decrypt it securely. Perfect for beginners exploring Streamlit, cryptography, and JSON-based data handling!

---

## ✨ Features

- 📝 **User Registration & Login**
- 🔒 **Password Hashing with Salt**
- 🔐 **Data Encryption & Decryption**
- 💾 **Encrypted Data Storage (JSON File)**
- ⏱️ **Login Throttling After Failed Attempts**
- 📋 **Simple UI Built with Streamlit**

---

## 🧰 Tech Stack

- [Python](https://www.python.org/)
- [Streamlit](https://streamlit.io/)
- [cryptography](https://cryptography.io/)
- Built-in libraries: `hashlib`, `json`, `os`, `time`, etc.

---

## 🚀 How to Run Locally

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/secure-data-encryption.git
cd secure-data-encryption
```

### 2. Create and Activate a Virtual Environment (Optional but Recommended)

```bash
python -m venv venv
source venv/bin/activate     # On macOS/Linux
venv\Scripts\activate      # On Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Streamlit App

```bash
streamlit run datasecure.py
```

---

## 📁 File Structure

```
secure-data-encryption/
│
├── datasecure.py           # Main Streamlit app
├── secure_data.json        # Data storage file (auto-created)
├── requirements.txt        # Python dependencies
└── README.md               # Project description
```

---

## 🛡️ Security Notes

- Passwords are hashed using PBKDF2 + SHA256 and a custom salt.
- Data is encrypted using Fernet symmetric encryption with a user-provided passphrase.
- Login lockout is enforced after 3 failed attempts to prevent brute-force attacks.

---

## 🌐 Deploy on Streamlit Cloud

1. Push your code to GitHub.
2. Go to [Streamlit Cloud](https://share.streamlit.io/).
3. Click **New App** → Connect your repo → Select `datasecure.py`.
4. Ensure `requirements.txt` is in the root.
5. 🎉 Deploy and share your encrypted data system!

---

## 👩‍💻 Foqia Siddiqui

Made with ❤️ using Streamlit & Cryptography.  
Feel free to connect or contribute!
Git Hub: [https://github.com/Foqia-Sd]
LinkedIn: [https://www.linkedin.com/in/foqia-siddiqui-3357152b5/]



