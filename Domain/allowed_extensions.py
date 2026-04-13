# Mapping of permitted file extensions to their expected MIME types.
# Used by the Identifier to validate that a file's magic-byte signature
# matches its declared extension.
ALLOWED_EXTENSIONS: dict[str, str] = {
    ".pdf":  "application/pdf",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".zip":  "application/zip",
    ".txt":  "text/plain",
}

