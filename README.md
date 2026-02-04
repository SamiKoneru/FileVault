# FileVault - Secure File Storage

A fullstack web application that allows users to securely upload, store, and retrieve files with authentication.

## Features

- **User Authentication**: Secure registration and login system
- **File Upload**: Drag-and-drop or click to upload files (up to 16MB)
- **File Preview**: View images, PDFs, videos, and audio directly in browser
- **File Download**: Download your files anytime
- **File Management**: Delete files you no longer need
- **Responsive Design**: Works on desktop and mobile devices
- **Modern UI**: Clean, dark-themed interface

## Supported File Types

- Images: PNG, JPG, JPEG, GIF
- Documents: PDF, DOC, DOCX, TXT
- Spreadsheets: XLS, XLSX, CSV
- Media: MP4, MP3
- Archives: ZIP

## Setup

1. **Create a virtual environment** (recommended):
   ```bash
   cd startup_project
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Run the application**:
   ```bash
   python app.py
   ```

3. **Open in browser**:
   Navigate to `http://localhost:5000`

## Project Structure

```
startup_project/
├── app.py                 # Flask application (backend)
├── README.md             # This file
├── static/
│   ├── css/
│   │   └── style.css     # Styles
│   ├── js/
│   │   └── main.js       # JavaScript
│   └── uploads/          # Uploaded files (created automatically)
└── templates/
    ├── base.html         # Base template
    ├── index.html        # Landing page
    ├── login.html        # Login page
    ├── register.html     # Registration page
    ├── dashboard.html    # User dashboard
    └── view_file.html    # File preview page
```

## Security Features

- Password hashing with Werkzeug
- Session-based authentication
- File ownership verification (users can only access their own files)
- Secure filename handling
- File type validation

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Landing page |
| GET/POST | `/register` | User registration |
| GET/POST | `/login` | User login |
| GET | `/logout` | User logout |
| GET | `/dashboard` | User's file dashboard |
| POST | `/upload` | Upload a file |
| GET | `/file/<id>` | View file details |
| GET | `/download/<id>` | Download a file |
| POST | `/delete/<id>` | Delete a file |
