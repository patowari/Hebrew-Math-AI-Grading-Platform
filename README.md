# 📚 Hebrew Math Homework AI Grading Platform

An AI-powered web platform that allows teachers to upload, manage, and grade student submissions. Students can submit assignments, and teachers can leverage Google Gemini AI to analyze and grade submissions automatically.

---

## 🚀 Features

- 🔐 User Authentication (JWT-based)
- 👨‍🏫 Role-based Access (Student / Teacher)
- 📂 Assignment Creation & Management
- 📥 File Upload System with Validation
- 🤖 AI-based Submission Analysis using Gemini API
- ✅ Manual Grading with Feedback
- 📊 Student & Assignment Analytics (via API)
- 🧠 AI JSON Summary for Student Performance
- 🖼️ Supports PDF, Images, Text Files
- 🌍 CORS & Rate Limiting Enabled
- 🗃️ SQLite Lightweight Database
- 📁 Static File Support for Web Interface

---

## 📦 Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **Authentication:** JWT
- **AI Engine:** Google Gemini 1.5 Flash API
- **Rate Limiting:** Flask-Limiter
- **CORS:** Flask-CORS

---

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/patowari/Hebrew-Math-AI-Grading-Platform.git
cd Hebrew-Math-AI-Grading-Platform
````

### 2. Create Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Environment Variables

Create a `.env` file or export manually:

```bash
export SECRET_KEY=your_super_secret_key
export GEMINI_API_KEY=your_gemini_api_key
```

(For Windows CMD: `set SECRET_KEY=...`)

---

## ▶️ Run the Application

```bash
python app.py
```

> Default server runs at: **[http://localhost:5000](http://localhost:5000)**

---

## 🧪 API Endpoints

### 🧑‍🎓 Auth

| Method | Endpoint             | Description            |
| ------ | -------------------- | ---------------------- |
| POST   | `/api/auth/register` | Register new user      |
| POST   | `/api/auth/login`    | Login user and get JWT |
| GET    | `/api/auth/verify`   | Verify JWT token       |

### 📘 Assignments

| Method | Endpoint           | Description                          |
| ------ | ------------------ | ------------------------------------ |
| GET    | `/api/assignments` | Get all assignments                  |
| POST   | `/api/assignments` | Create new assignment (teacher only) |

### 📤 Submissions

| Method | Endpoint                        | Description                       |
| ------ | ------------------------------- | --------------------------------- |
| POST   | `/api/upload`                   | Upload a student assignment       |
| GET    | `/api/submissions`              | Get all submissions               |
| POST   | `/api/submissions/<id>/analyze` | Analyze submission with Gemini AI |
| PUT    | `/api/submissions/<id>/grade`   | Grade a submission manually       |

### 📋 Students

| Method | Endpoint        | Description                                |
| ------ | --------------- | ------------------------------------------ |
| GET    | `/api/students` | Get all registered students (teacher only) |

### 🧠 AI Response Format (Example)

```json
{
  "recommendedGrade": 85,
  "positivePoints": [
    "Well-structured algebraic equations",
    "Correct use of variables"
  ],
  "areasForImprovement": [
    "Minor calculation mistakes",
    "Show more steps for clarity"
  ]
}
```

---

## 📂 File Structure

```
├── app.py
├── data/
│   └── grading_platform.db
├── uploads/
│   └── (uploaded files)
├── templates/
│   └── index.html
├── static/
│   └── (optional assets)
├── requirements.txt
```

---

## ⚠️ Limitations

* File size limited to 10MB
* Supported formats: `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.txt`
* Gemini AI may return unexpected results; structure is validated

---

## ✅ To-Do

* [ ] Add frontend dashboard
* [ ] Add email notifications
* [ ] Add grading history & audit logs
* [ ] Integrate charts for student performance

---

## 🧑‍💻 Developer

**Md Zubayer Hossain Patowari**
GitHub: [@patowari](https://github.com/patowari)
Email: [zpatowari.ai@gmail.com](mailto:zpatowari.ai@gmail.com)
