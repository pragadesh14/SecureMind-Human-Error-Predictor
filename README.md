# SecureMind — Human Error Security Predictor

A full-stack academic cybersecurity-awareness web application.

## Features
- Flask backend + SQLite database
- Registration/login and role-based admin dashboard
- 15 realistic cybersecurity scenarios
- Explainable 0–100 risk score
- LOW / MEDIUM / HIGH classification
- Risk explanations and recommendations
- Dashboard analytics with Chart.js
- Assessment history + CSV export
- Personalized category recommendations
- XP/gamification
- Responsive cybersecurity UI

## Run
1. Install Python 3.10+.
2. Open a terminal in this folder.
3. `pip install -r requirements.txt`
4. `python app.py`
5. Open `http://127.0.0.1:5000`

Demo admin:
- username: demo
- password: demo123

## Important
The predictor is an explainable academic prototype. It is not a professional cybersecurity detection system. The risk engine is intentionally transparent and can later be replaced/extended with a trained ML model or external AI API.
