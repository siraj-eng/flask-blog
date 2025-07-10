# TeamSync HR System

A modern, full-featured HR management system built with Flask, featuring user, HR, and admin dashboards, real-time chat, notifications, lunch order management, repairs, complaints, events, and more. Designed for clarity, maintainability, and a great user experience.

---

## Table of Contents
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Database Schema](#database-schema)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

---

## Features
- **Role-based Dashboards:** Separate dashboards for Users, HR, and Admins with tailored features.
- **Authentication:** Secure registration, login, and session management.
- **Announcements & Comments:** Post, view, and comment on announcements.
- **Real-time Chat:** Modern chat interface with unread message counts and file uploads.
- **Notifications:** In-app notifications for announcements, comments, and system events.
- **Lunch Orders:** Users can submit lunch orders; HR can manage menus and view orders.
- **Repairs & Complaints:** Users can submit, track, and search repairs/complaints; HR can manage them.
- **Events:** Event management for users and HR.
- **PDF Export:** Export employee lists and lunch orders as PDFs.
- **Responsive UI:** Clean, modern design using Material Dashboard, Inter font, and custom styles.

---

## Tech Stack
- **Backend:** Python 3, Flask, Flask-Login, Flask-SQLAlchemy, Flask-WTF, Flask-SocketIO
- **Database:** SQLite (default, easy to set up)
- **Frontend:** Jinja2 templates, Material Dashboard CSS, Font Awesome, Google Fonts (Inter, Montserrat)
- **PDF Generation:** WeasyPrint, ReportLab
- **Other:** WTForms, python-dotenv

---

## Project Structure
```
├── app.py              # Main Flask app (routes, logic)
├── models.py           # SQLAlchemy models (legacy)
├── db.py               # SQLite connection helper
├── helpers.py          # Dashboard, notification, and utility functions
├── config.py           # App configuration (env vars)
├── init_db.py          # Database initialization script
├── schema.sql          # SQL schema for database
├── requirements.txt    # Python dependencies
├── static/             # CSS, JS, images, uploads
├── templates/          # Jinja2 HTML templates (user, hr, admin)
├── venv/               # Python virtual environment (not tracked)
└── ...
```

---

## Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/siraj-eng/flask-blog.git
cd flask-blog
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables (Optional)
- Copy `.env.example` to `.env` and set your `SECRET_KEY` and other variables as needed.
- By default, the app uses SQLite (`hr_system.db`).

### 5. Initialize the Database
```bash
python init_db.py
```
This will create the required tables and indexes in `hr_system.db`.

### 6. Run the Application
```bash
python app.py
```
Or, for real-time chat support:
```bash
python -m flask run
# Or, if using Flask-SocketIO:
python -m flask run --with-threads
```

The app will be available at [http://localhost:5000](http://localhost:5000).

---

## Usage
- Register a new user or log in as the default admin (`admin@hrsystem.com` / `admin123`).
- Explore the user, HR, and admin dashboards.
- Submit lunch orders, repairs, complaints, and comments.
- Use the chat for real-time messaging.
- HR/Admin can manage users, menus, and view reports.

---

## Database Schema (Summary)
- **users:** id, username, email, password_hash, role, full_name, department, position, created_at, notification and theme preferences
- **announcements:** id, title, content, author_id, created_at
- **comments:** id, announcement_id, user_id, content, created_at
- **lunch_orders:** id, user_id, dish, notes, status, created_at
- **lunch_menus:** id, date, main_menu, accompaniment, image_url, notes
- **chat_messages:** id, user_id, username, message, file_url, created_at
- **notifications:** id, user_id, message, is_read, created_at, announcement_id
- **complaints:** id, user_id, title, description, status, created_at
- **repairs:** id, user_id, title, description, status, created_at
- **events:** id, title, description, event_date, location, created_at

See `schema.sql` and `init_db.py` for full details.

---

## Screenshots
> _Add screenshots of the dashboards, chat, and other features here._

---

## Contributing
1. Fork the repo and create your feature branch (`git checkout -b feature/YourFeature`)
2. Commit your changes (`git commit -am 'Add some feature'`)
3. Push to the branch (`git push origin feature/YourFeature`)
4. Open a Pull Request

---

## License
[MIT](LICENSE) 