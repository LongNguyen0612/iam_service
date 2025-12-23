"""
Authentication Use Cases

All authentication-related business logic.
"""

from .signup_use_case import SignupUseCase
from .signup_dto import SignupCommand, SignupResponse, UserInfo, TenantCreated
from .login_use_case import LoginUseCase
from .refresh_token_use_case import RefreshTokenUseCase
from .verify_email_use_case import VerifyEmailUseCase
from .resend_verification_use_case import ResendVerificationUseCase
from .request_password_reset_use_case import RequestPasswordResetUseCase
from .confirm_password_reset_use_case import ConfirmPasswordResetUseCase
from .dtos import (
    VerifyEmailResponse,
    ResendVerificationResponse,
    LoginResponse,
    RefreshTokenResponse,
    TenantInfo,
    RequestPasswordResetResponse,
    ConfirmPasswordResetResponse,
)

__all__ = [
    # Use Cases
    "SignupUseCase",
    "LoginUseCase",
    "RefreshTokenUseCase",
    "VerifyEmailUseCase",
    "ResendVerificationUseCase",
    "RequestPasswordResetUseCase",
    "ConfirmPasswordResetUseCase",
    # DTOs - Commands
    "SignupCommand",
    # DTOs - Responses
    "SignupResponse",
    "VerifyEmailResponse",
    "ResendVerificationResponse",
    "LoginResponse",
    "RefreshTokenResponse",
    "RequestPasswordResetResponse",
    "ConfirmPasswordResetResponse",
    # DTOs - Nested Models
    "UserInfo",
    "TenantCreated",
    "TenantInfo",
]
