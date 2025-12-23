from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, EmailStr, Field

from src.api.error import ClientError, ServerError
from src.app.services.unit_of_work import UnitOfWork
from src.app.use_cases.auth import (
    SignupCommand,
    SignupResponse,
    SignupUseCase,
    LoginUseCase,
    RefreshTokenUseCase,
    VerifyEmailUseCase,
    ResendVerificationUseCase,
    RequestPasswordResetUseCase,
    ConfirmPasswordResetUseCase,
    LoginResponse,
    RefreshTokenResponse,
    VerifyEmailResponse,
    ResendVerificationResponse,
    RequestPasswordResetResponse,
    ConfirmPasswordResetResponse,
)
from src.depends import get_unit_of_work

router = APIRouter(prefix="/auth", tags=["Authentication"])


class SignupRequest(BaseModel):
    """
    Signup HTTP request payload

    Validates incoming HTTP request before converting to SignupCommand.
    API layer responsibility: HTTP validation and serialization.
    """

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password (min 8 chars)")
    tenant_name: str = Field(
        ..., min_length=1, max_length=255, description="Tenant/organization name"
    )


@router.post(
    "/signup", status_code=status.HTTP_201_CREATED, response_model=SignupResponse
)
async def signup(
    request: SignupRequest, uow: UnitOfWork = Depends(get_unit_of_work)
):
    """
    User Signup - AC-1.1, AC-1.2, AC-1.3

    Command/Response Flow:
    1. SignupRequest validates HTTP input (AC-1.3)
    2. Map to SignupCommand (business intent)
    3. Execute SignupUseCase
    4. Map SignupResponse to HTTP response

    Creates a new user account with their own tenant workspace.
    Returns JWT access token and refresh token for authentication.

    Raises:
        - 409 Conflict: Email already exists (AC-1.2)
        - 422 Unprocessable Entity: Invalid input (AC-1.3, handled by FastAPI)
        - 500 Internal Server Error: Server error
    """
    # Map HTTP request to Command (validated business intent)
    command = SignupCommand(
        email=request.email, password=request.password, tenant_name=request.tenant_name
    )

    # Execute use case with command
    use_case = SignupUseCase(uow)
    result = await use_case.execute(command)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code == "EMAIL_ALREADY_EXISTS":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return Pydantic model directly (FastAPI auto-serializes)
    return result.value


class LoginRequest(BaseModel):
    """
    Login HTTP request payload

    Validates incoming login request.
    """

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")


@router.post("/login", status_code=status.HTTP_200_OK, response_model=LoginResponse)
async def login(request: LoginRequest, uow: UnitOfWork = Depends(get_unit_of_work)):
    """
    User Login - AC-2.1, AC-2.2, AC-2.3, AC-2.4, AC-2.5

    Authenticates user and returns tenant-scoped JWT tokens.

    Raises:
        - 401 Unauthorized: Invalid credentials (AC-2.2)
        - 403 Forbidden: User disabled (AC-2.4) or no active membership (AC-2.3)
        - 500 Internal Server Error: Server error
    """
    use_case = LoginUseCase(uow)
    result = await use_case.execute(request.email, request.password)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code == "INVALID_CREDENTIALS":
            raise ClientError(error, status_code=status.HTTP_401_UNAUTHORIZED)
        elif error.code in ("USER_DISABLED", "NO_ACTIVE_MEMBERSHIP"):
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        raise ServerError(error)

    # Return Pydantic model directly (FastAPI auto-serializes)
    return result.value


class RefreshRequest(BaseModel):
    """
    Refresh token HTTP request payload

    Validates incoming refresh request.
    """

    refresh_token: str = Field(..., description="Refresh token")


@router.post("/refresh", status_code=status.HTTP_200_OK, response_model=RefreshTokenResponse)
async def refresh(request: RefreshRequest, uow: UnitOfWork = Depends(get_unit_of_work)):
    """
    Refresh JWT Token - AC-3.1, AC-3.2, AC-3.3, AC-3.4, AC-3.5

    Refreshes access token using a valid refresh token.
    Implements token rotation for security.

    Raises:
        - 401 Unauthorized: Invalid/expired token or revoked session (AC-3.2, AC-3.3)
        - 403 Forbidden: Membership revoked (AC-3.4)
        - 500 Internal Server Error: Server error
    """
    use_case = RefreshTokenUseCase(uow)
    result = await use_case.execute(request.refresh_token)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("INVALID_TOKEN", "SESSION_REVOKED", "SESSION_EXPIRED"):
            raise ClientError(error, status_code=status.HTTP_401_UNAUTHORIZED)
        elif error.code == "MEMBERSHIP_REVOKED":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        raise ServerError(error)

    # Return Pydantic model directly (FastAPI auto-serializes)
    return result.value


class VerifyEmailRequest(BaseModel):
    """
    Verify email HTTP request payload

    Validates incoming email verification request.
    """

    token: str = Field(..., description="Email verification token")


@router.post("/verify-email", status_code=status.HTTP_200_OK, response_model=VerifyEmailResponse)
async def verify_email(request: VerifyEmailRequest, uow: UnitOfWork = Depends(get_unit_of_work)):
    """
    Email Verification - AC-10.1, AC-10.2, AC-10.3, AC-10.4

    Verifies user email address via secure token.
    Sets email_verified flag and clears verification token.

    Raises:
        - 400 Bad Request: Invalid token (AC-10.3)
        - 410 Gone: Expired token (AC-10.2)
        - 500 Internal Server Error: Server error
    """
    use_case = VerifyEmailUseCase(uow)
    result = await use_case.execute(request.token)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code == "INVALID_TOKEN":
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code == "TOKEN_EXPIRED":
            raise ClientError(error, status_code=status.HTTP_410_GONE)
        raise ServerError(error)

    # Return Pydantic model directly (FastAPI auto-serializes)
    return result.value


class ResendVerificationRequest(BaseModel):
    """
    Resend verification email HTTP request payload

    Validates incoming resend verification request.
    """

    email: EmailStr = Field(..., description="User email address")


@router.post("/resend-verification", status_code=status.HTTP_200_OK, response_model=ResendVerificationResponse)
async def resend_verification(request: ResendVerificationRequest, uow: UnitOfWork = Depends(get_unit_of_work)):
    """
    Resend Verification Email - AC-11.1, AC-11.2

    Resends email verification link with new token.
    Invalidates old token and resets expiry to 24 hours.

    Security:
        - No email enumeration (same response for valid/invalid emails)
        - Rate limiting should be applied at middleware layer (AC-11.3)

    Returns:
        - 200 OK: Always returns success (no enumeration)
        - 500 Internal Server Error: Server error
    """
    use_case = ResendVerificationUseCase(uow)
    result = await use_case.execute(request.email)

    # Handle errors
    if result.is_err():
        error = result.error
        raise ServerError(error)

    # Return Pydantic model directly (FastAPI auto-serializes)
    return result.value


class RequestPasswordResetRequest(BaseModel):
    """
    Request password reset HTTP request payload

    Validates incoming password reset request.
    """

    email: EmailStr = Field(..., description="User email address")


@router.post("/request-password-reset", status_code=status.HTTP_200_OK, response_model=RequestPasswordResetResponse)
async def request_password_reset(request: RequestPasswordResetRequest, uow: UnitOfWork = Depends(get_unit_of_work)):
    """
    Request Password Reset - AC-12.1, AC-12.2, AC-12.3

    Generates secure password reset token and sends reset email.
    Token expires in 1 hour and is hashed with SHA-256.

    Security:
        - No email enumeration (same response for valid/invalid emails)
        - Rate limiting should be applied at middleware layer (AC-12.3)
        - Token is cryptographically secure (32 bytes)

    Returns:
        - 200 OK: Always returns success (no enumeration)
        - 500 Internal Server Error: Server error
    """
    use_case = RequestPasswordResetUseCase(uow)
    result = await use_case.execute(request.email)

    # Handle errors
    if result.is_err():
        error = result.error
        raise ServerError(error)

    # Return Pydantic model directly (FastAPI auto-serializes)
    return result.value


class ConfirmPasswordResetRequest(BaseModel):
    """
    Confirm password reset HTTP request payload

    Validates incoming password reset confirmation request.
    """

    token: str = Field(..., description="Password reset token from email")
    new_password: str = Field(..., min_length=8, description="New password (min 8 chars)")


@router.post("/confirm-password-reset", status_code=status.HTTP_200_OK, response_model=ConfirmPasswordResetResponse)
async def confirm_password_reset(request: ConfirmPasswordResetRequest, uow: UnitOfWork = Depends(get_unit_of_work)):
    """
    Confirm Password Reset - AC-13.1, AC-13.2, AC-13.3, AC-13.4

    Validates reset token and updates user password.
    Revokes all existing sessions for security.

    Security:
        - Token must not be expired (1 hour window)
        - Token must not be already used
        - Password must meet complexity requirements
        - All sessions revoked after reset
        - Token marked as used

    Raises:
        - 400 Bad Request: Invalid token or password validation failed (AC-13.2, AC-13.4)
        - 410 Gone: Expired token (AC-13.3)
        - 409 Conflict: Token already used
        - 500 Internal Server Error: Server error
    """
    use_case = ConfirmPasswordResetUseCase(uow)
    result = await use_case.execute(request.token, request.new_password)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code == "INVALID_TOKEN":
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code == "TOKEN_EXPIRED":
            raise ClientError(error, status_code=status.HTTP_410_GONE)
        elif error.code == "TOKEN_ALREADY_USED":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        elif error.code == "INVALID_PASSWORD":
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        raise ServerError(error)

    # Return Pydantic model directly (FastAPI auto-serializes)
    return result.value
