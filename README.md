# User Management System

A backend API built with NestJS, Prisma, and Passport JWT providing authentication, authorization, and role-based access control.
Supports access & refresh tokens, role-based permissions, and can be extended with Keycloak for enterprise user management.

## Features

- User registration and login
- Secure password hashing
- Authentication with Passport.js
- Stateless authentication using JWT
- Role-based access control (optional)
- RESTful API endpoints

## Technologies Used

- **Nest Js**: Node js framework
- **Passport.js**: Authentication middleware
- **JWT**: Token-based authentication
- **Prisma**: ORM for PostgreSQL

## Installation

1. Clone the repository:
	```bash
	git clone <repo-url>
	cd user-management
	```
2. Install dependencies:
	```bash
	npm install
	```
3. Set environment variables (see `.env.example`).

## Usage

- Start the server:
  ```bash
  npm start
  ```
- API endpoints:
### Auth
  - `POST /register` — Register a new user
  - `POST /login` — Authenticate user and get tokens
  - `POST /auth/refresh` → Refresh access token
  - `POST /auth/logout` → Revoke refresh token
  - Protected routes require `Authorization: Bearer <token>` header
###  users
- `GET /users/me` → Get current user (requires JWT)
- `GET /users` → List all users (ADMIN only)

## Authentication Flow

1. **Register**: User creates an account
2. **Login**: API returns accessToken (short-lived) & refreshToken (long-lived, stored in DB)
3. **Access Protected Routes**: JWT is sent in headers; Passport.js verifies token.
4. **Logout** → Refresh token is revoked in DB
5. **Refresh Token** → Get a new accessToken using refreshToken
## Configuration

- Update JWT secret and database URI in your `.env` file.


## Next steps
 1. Integrate with Keycloak for enterprise user management
 2. Add account recovery & password reset
 3. Dockerize for deployment