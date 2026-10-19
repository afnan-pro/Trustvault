"""
Input Validators — TrustVault
Validate file uploads, emails, and other user inputs.
"""
import re
from app.config import MAX_FILE_SIZE, ALLOWED_MIME_TYPES


def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Invalid email format"
    if len(email) > 255:
        return False, "Email too long"
    return True, "Valid"


def validate_file_upload(filename: str, content_type: str, file_size: int) -> tuple[bool, str]:
    """Validate file upload parameters."""
    if not filename or len(filename) > 512:
        return False, "Invalid filename"
    
    # Check for path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False, "Invalid filename characters"
    
    # Check mime type
    if content_type not in ALLOWED_MIME_TYPES:
        return False, f"File type '{content_type}' is not allowed"
    
    # Check file size
    if file_size > MAX_FILE_SIZE:
        return False, f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB"
    
    if file_size == 0:
        return False, "File is empty"
    
    return True, "Valid"


def validate_role(role: str) -> tuple[bool, str]:
    """Validate user role."""
    valid_roles = {"admin", "owner", "viewer"}
    if role not in valid_roles:
        return False, f"Invalid role. Must be one of: {', '.join(valid_roles)}"
    return True, "Valid"


def validate_permission_level(level: str) -> tuple[bool, str]:
    """Validate permission level."""
    valid_levels = {"read", "edit"}
    if level not in valid_levels:
        return False, f"Invalid level. Must be one of: {', '.join(valid_levels)}"
    return True, "Valid"


def validate_category(category: str) -> tuple[bool, str]:
    """Validate document category."""
    if not category or len(category) > 100:
        return False, "Category must be between 1 and 100 characters"
    if not re.match(r'^[a-zA-Z0-9\s\-_]+$', category):
        return False, "Category contains invalid characters"
    return True, "Valid"


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent injection."""
    # Remove path separators
    filename = filename.replace('/', '').replace('\\', '').replace('..', '')
    # Remove null bytes
    filename = filename.replace('\x00', '')
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    return filename
