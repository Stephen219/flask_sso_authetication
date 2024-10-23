# Single Sign-On (SSO) Implementation in Python Flask

## Overview

This project demonstrates a Single Sign-On (SSO) implementation using Python Flask, where **Server 1** acts as the Identity Provider (IdP) for **Server 2**. This setup allows users to authenticate once and gain access to multiple applications.

## Architecture

- **Server 1 (Identity Provider)**: 
  - Handles user authentication.
  - Issues tokens for successful login.
  
- **Server 2 (Service Provider)**:
  - Relies on Server 1 for user authentication.
  - Validates tokens issued by Server 1.

## Features

- User authentication via Server 1.
- Token-based access management.
- Secure communication between servers.
- Easy integration with existing applications.



### Prerequisites

- Python 3.x
- Flask
- jwt
- flask_migrate
- flask_sqlalchemy
- 
