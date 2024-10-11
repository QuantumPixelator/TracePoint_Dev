# **Secure Document Management System (SDMS)**

## Overview:

- SDMS is a web-based application designed to securely manage documents within an organization.
It provides features such as document upload, search, all while enforcing role-based access control (RBAC) to ensure data security and integrity.

## Features:
### 1. User Authentication and Role Management
  - Ensure secure access to the system through user authentication.
  - Implement role-based access control (RBAC) to define user permissions based on roles such as admin, manager, and user. 

### 2. Document Upload and Management
  - Allow managers and admins to upload documents securely to the system.
  - Provide functionalities to manage uploaded documents

### 3. Document Search and Retrieval
  - Enable users to perform searches to locate documents based on keywords, categories, and metadata.
  - Implement secure algorithms to ensure that search results are only accessible to authorized users.

### 4. Document Viewing and Editing
  - Provide built-in document downloader for users within the application.
  - Allow authorized users to manage documents securely, and maintain document integrity.

### 5. Collaboration and Sharing
  - Facilitate secure sharing of documents among authorized users, with predefined access controls.
  - Implement real-time collaboration features to enable concurrent editing while preventing conflicts and ensuring document consistency.

## Technology Stack:


### Front-End:
  - HTML
  - CSS
    
### Back-End: 
  - Flask
  - Python

### Database:
  - SQLite3
 
### Security Measures:
  - Role-based access control (RBAC) implemented using Flask's authentication and authorization features
  - Hashing passwords using hashlib library
  - Secure password storage
  - Flask-WTF for form validation and CSRF protection
  - Logging sensitive actions and errors using Python's built-in logging module

## Installation:

- Clone the repository:
```bash
git clone IskaIV/Secure-Document-Management-System
```

- Create Python virtual enviroment
```bash
python -m venv .venv/
```

- Activate the  virtual enviroment
```bash
. .venv/bin/activate
```

- Install dependencies:
```bash
pip install -r requirements.txt
```

- Run the program
```bash
python ./main.py
```

## Usage:
- Access the application in your web browser at http://localhost:port (port number may vary depending on your configuration).
- Register as a new user or log in with existing credentials.
- Explore the various features of the application, such as document upload, search, file management, and role based access control.
