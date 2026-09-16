# Secure Management of Competitive Examination Question Papers

## Project Description

The Secure Management of Competitive Examination Question Papers is a cloud-based system designed to securely create, store, manage, and release competitive examination question papers.

The system protects sensitive question papers from unauthorized access, modification, and leakage before the scheduled examination. It provides authentication, role-based access control, confidentiality, integrity verification, secure storage, monitoring, and controlled release.

## Objectives

- Provide secure authentication for authorized users.
- Implement role-based access control.
- Protect question papers from unauthorized access.
- Maintain confidentiality of examination question papers.
- Ensure integrity of stored question papers.
- Provide secure cloud-based storage.
- Monitor important user activities using audit logs.
- Release question papers only at the scheduled examination time.

## Technologies Used

- HTML
- CSS
- JavaScript
- Python Flask
- SQLite / Cloud Database
- Cloud Storage
- Git
- GitHub

## Security Features

### 1. Authentication
Users must log in with valid credentials before accessing the system.

### 2. Role-Based Access Control
Different permissions are provided to Admin, Question Setter, Examination Officer, and Candidate.

### 3. Confidentiality
Question papers are stored securely and are not publicly accessible before the scheduled release time.

### 4. Integrity
A SHA-256 hash is generated for each question paper to detect unauthorized modification.

### 5. Secure Storage
Question papers are stored in protected cloud storage and are accessible only to authorized users.

### 6. Monitoring
Important activities such as login, upload, approval, download, and unauthorized access attempts are recorded in audit logs.

### 7. Controlled Release
Question papers are automatically made available only after the authorized release date and time.

## User Roles

| Role | Main Responsibilities |
|------|------------------------|
| Admin | Manage users and system |
| Question Setter | Upload question papers |
| Examination Officer | Review and approve papers |
| Examination Controller | Schedule and release papers |
| Candidate | Access released question papers |

## Installation and Setup

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_LINK
