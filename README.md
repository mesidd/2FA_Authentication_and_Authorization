# 2FA_Authentication_and_Authorization

This project demonstrates the implementation of Authentication and Authorization with Two-Factor Authentication (2FA). It provides a secure way to manage user login, password hashing, and session management, ensuring that users authenticate through both their credentials and a second factor (like an OTP) for enhanced security.

## Features

User Registration: Users can sign up and create an account.
2FA Authentication: QR code-based 2FA to verify user identity.
JWT-based Authentication: Secure token-based authentication for access.
Refresh Token Support: Secure refresh token handling to extend session duration.
User Authorization: Role-based access control (Admin, Member, etc.).
Security: Implements strong security practices to protect against unauthorized access.

## Dependencies:

bcrypt: A library for securely hashing passwords before storing them in the database.

cookie-parser: Middleware for parsing cookies, often used for managing sessions or storing JWT tokens.

express: A fast, minimalist web framework for Node.js, used for handling HTTP requests, routing, and middleware.

jsonwebtoken: A library for creating and verifying JSON Web Tokens (JWT), essential for authentication and authorization.

nedb-promises: A lightweight, file-based database that stores data in a simple, NoSQL format (similar to MongoDB), with support for promises for easy asynchronous operations.

node-cache: A simple in-memory cache used for storing temporary data, like session tokens or frequently accessed resources.

otplib: A library for generating and verifying One-Time Passwords (OTP), used in two-factor authentication (2FA) implementations.

qrcode: A library for generating QR codes, useful for displaying authentication codes in 2FA processes.


## License

This project is licensed under the MIT License.