# 🔐 Spring Boot Authentication System (JWT + Refresh Tokens)

A secure, stateless authentication system built using Spring Boot 3.x and Spring Security 6, implementing JWT access tokens, refresh token rotation, and token revocation (blacklisting).

This project demonstrates industry-standard authentication practices suitable for production systems.

---

## ✨ Features

- JWT-based stateless authentication
- Access token + refresh token flow
- Refresh token rotation
- Refresh token reuse detection
- Token revocation (logout support)
- Blacklisted access tokens
- Secure token hashing (no raw tokens stored)
- MySQL persistence
- Clean Spring Security 6 filter chain
- Ready for Redis integration (optional)

---

## 🧠 Authentication Design Overview
| Token         | Purpose                 | Lifetime            | Storage                  |
| ------------- | ----------------------- | ------------------- | ------------------------ |
| Access Token  | API authorization       | Short (e.g. 1 hour) | Client (Header)          |
| Refresh Token | Issue new access tokens | Long (e.g. 7 days)  | Client (Cookie / Header) |

---

## 🔄 Authentication Flow

### Login

1. User submits username + password
2. Credentials authenticated by AuthenticationManager
3. Access token (JWT) issued
4. Refresh token created and stored hashed in DB
5. Tokens returned to client

### Access Protected API

1. Client sends access token in Authorization header
2. JWT filter validates token
3. Security context is populated
4. Request proceeds

### Refresh Token

1. Client sends refresh token
2. Token is validated (exists, not revoked, not expired)
3. Old refresh token is revoked
4. New refresh token is issued (rotation)
5. New access token is generated

### Logout

1. Access token is blacklisted
2. Refresh token is revoked
3. Token can no longer be reused

---

## 🔐 Security Highlights

- ❌ No raw refresh tokens stored
- ❌ No passwords stored in token tables
- ✅ SHA-256 hashing with secret salt
- ✅ Refresh token rotation prevents replay attacks
- ✅ Blacklist prevents JWT reuse after logout
- ✅ Stateless access token validation

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
