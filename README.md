# 🔐 Spring Boot Authentication System (JWT + Refresh Tokens)

A secure, stateless authentication system built using Spring Boot 3.x and Spring Security 6, implementing JWT access tokens, refresh token rotation, and token revocation (blacklisting).

This project demonstrates industry-standard authentication practices suitable for production systems.

---

## ✨ Features

JWT-based stateless authentication

- Short-lived access token and long-lived refresh token flow
- Refresh token rotation on every refresh request
- Refresh token reuse detection with automatic revocation
- Token revocation with explicit logout support
- Blacklisted access tokens (optional, configurable)
- Secure token hashing (no raw access or refresh tokens stored)
- Device fingerprint cookies for refresh token binding and replay protection
- HttpOnly, Secure, SameSite-protected fingerprint cookies
- MySQL persistence for users, refresh tokens, and blacklists
- Clean Spring Security 6 filter chain implementation

---

## 🧠 Authentication Design Overview
| Token / Cookie     | Purpose                              | Lifetime               | Storage Location                  |
| ------------------ | ------------------------------------ | ---------------------- | --------------------------------- |
| **Access Token**   | API authorization                    | Short (e.g. 15–60 min) | Client (Authorization Header)     |
| **Refresh Token**  | Issue new access tokens              | Long (e.g. 7–30 days)  | Client (HttpOnly Cookie / Header) |
| **Fingerprint ID** | Bind session to device (anti-replay) | Long (matches refresh) | Client (HttpOnly Secure Cookie)   |


---

## 🔄 Authentication Flow

### 🔐 Login

1. User submits username + password
2. Credentials are authenticated by AuthenticationManager
3. Access token (JWT) is issued
4. Refresh token is generated, hashed, and stored in the database
5. Device fingerprint is generated and stored (hashed) with the refresh token
6. Fingerprint is returned to the client as a HttpOnly, Secure cookie
7. Tokens are returned to the client

### 🔓 Access Protected API

1. Client sends access token in the Authorization: Bearer header
2. JWT authentication filter:
   - Validates signature
   - Validates expiration
   - Extracts claims
3. Spring Security context is populated
4. Request proceeds to the controller
  🔹 Fingerprint is not checked for normal API requests

### ♻️ Refresh Token

1. Client sends refresh token
2. Browser automatically sends fingerprint cookie
3. Server validates:
   - Refresh token exists and is not revoked
   - Refresh token is not expired
   - Fingerprint matches stored hash
4. Old refresh token is revoked (reuse detection)
5. A new refresh token is issued (rotation)
6. A new access token is generated
7. Updated tokens are returned to the client

### 🚪 Logout

1. Client sends refresh token
2. Browser sends fingerprint cookie
3. Server validates refresh token and fingerprint
4. Refresh token is revoked
5. Access token is optionally blacklisted
6. Fingerprint cookie is deleted
7. Session is fully terminated

---

## 🛡️ Security Guarantees

- Stateless access token validation
- Refresh token rotation prevents replay attacks
- Fingerprint binding prevents stolen refresh token reuse
- Logout is deterministic (tokens cannot be reused)
- No raw tokens stored in the database

---

## 🏗️ Tech Stack

- Java 17+
- Spring Boot 3.x
- Spring Security 6
- JWT (jjwt)
- MySQL
- Hibernate / JPA
- Maven

---

## 🚀 Possible Enhancements

- Redis for refresh token storage
- OAuth2 login (Google / GitHub)
- Device/session tracking
- Logout-all-devices endpoint
- Rate limiting on auth endpoints

---
