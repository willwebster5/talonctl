#!/usr/bin/env python3
"""
CrowdStrike NGSIEM Files API Helper Module

This module provides helper functions for interacting with the CrowdStrike
NGSIEM Content API for lookup file upload/download operations.

Uses the same API endpoint as the lookup file provider:
  /ngsiem-content/entities/lookupfiles/v1

Supports CSV and JSON file formats with appropriate content types.
Maximum file sizes: CSV: 209.7 MB, JSON: 104.9 MB
"""

import os
import json
import logging
from typing import Dict, Any, Optional, Union, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# Valid search domain options (same as lookup_file_provider.py)
VALID_SEARCH_DOMAINS = ["all", "falcon", "third-party", "dashboards", "parsers-repository"]

# File size limits
MAX_FILE_SIZE_CSV = 209.7 * 1024 * 1024  # 209.7 MB
MAX_FILE_SIZE_JSON = 104.9 * 1024 * 1024  # 104.9 MB


def upload_file(
    falcon_client, file_path: str, search_domain: str = "falcon", filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Upload a file to CrowdStrike NGSIEM as a lookup file.

    Args:
        falcon_client: An authenticated FalconPy APIHarnessV2 instance
        file_path: Path to the file to upload
        search_domain: NGSIEM search domain (falcon, all, third-party, dashboards, parsers-repository)
        filename: Optional custom filename for the upload (defaults to basename)

    Returns:
        Dictionary containing API response

    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If file exceeds size limits, has unsupported extension, or invalid search_domain
    """
    # Validate search domain
    if search_domain not in VALID_SEARCH_DOMAINS:
        raise ValueError(f"Invalid search_domain: {search_domain}. Must be one of {VALID_SEARCH_DOMAINS}")

    # Validate file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Check file size limits
    file_size = os.path.getsize(file_path)
    file_extension = Path(file_path).suffix.lower()

    if file_extension == ".csv" and file_size > MAX_FILE_SIZE_CSV:
        size_mb = file_size / (1024 * 1024)
        raise ValueError(f"CSV file exceeds 209.7 MB limit: {size_mb:.2f} MB")
    elif file_extension == ".json" and file_size > MAX_FILE_SIZE_JSON:
        size_mb = file_size / (1024 * 1024)
        raise ValueError(f"JSON file exceeds 104.9 MB limit: {size_mb:.2f} MB")

    # Determine content type
    if file_extension == ".csv":
        content_type = "text/csv"
    elif file_extension == ".json":
        content_type = "application/json"
    else:
        content_type = "application/octet-stream"

    # Use custom filename if provided
    upload_filename = filename if filename else os.path.basename(file_path)

    # Read file content
    with open(file_path, "rb") as file_handle:
        file_content = file_handle.read()

    # Prepare multipart file upload
    files = [("file", (upload_filename, file_content, content_type))]

    # API parameters as formData
    data = {"search_domain": search_domain, "filename": upload_filename}

    endpoint = "/ngsiem-content/entities/lookupfiles/v1"
    override = f"POST,{endpoint}"

    response = falcon_client.command(override=override, files=files, data=data)

    return response


def upload_json_data(falcon_client, data: Union[Dict, list], search_domain: str, filename: str) -> Dict[str, Any]:
    """
    Upload JSON data directly to NGSIEM without writing to disk.

    Args:
        falcon_client: An authenticated FalconPy APIHarnessV2 instance
        data: Dictionary or list to upload as JSON
        search_domain: NGSIEM search domain (falcon, all, third-party, dashboards, parsers-repository)
        filename: Name for the file in NGSIEM

    Returns:
        Dictionary containing API response

    Raises:
        ValueError: If JSON data exceeds size limit or invalid search_domain
    """
    # Validate search domain
    if search_domain not in VALID_SEARCH_DOMAINS:
        raise ValueError(f"Invalid search_domain: {search_domain}. Must be one of {VALID_SEARCH_DOMAINS}")

    # Serialize to JSON
    json_content = json.dumps(data, indent=2, sort_keys=True)
    json_bytes = json_content.encode("utf-8")

    # Check size limit
    size_mb = len(json_bytes) / (1024 * 1024)
    if len(json_bytes) > MAX_FILE_SIZE_JSON:
        raise ValueError(f"JSON data exceeds 104.9 MB limit: {size_mb:.2f} MB")

    # Prepare multipart file upload
    files = [("file", (filename, json_bytes, "application/json"))]

    # API parameters as formData
    form_data = {"search_domain": search_domain, "filename": filename}

    endpoint = "/ngsiem-content/entities/lookupfiles/v1"
    override = f"POST,{endpoint}"

    response = falcon_client.command(override=override, files=files, data=form_data)

    return response


def download_file(
    falcon_client, filename: str, search_domain: str = "falcon", output_path: Optional[str] = None
) -> Union[bytes, Dict[str, Any]]:
    """
    Download a file from CrowdStrike NGSIEM lookup files.

    Args:
        falcon_client: An authenticated FalconPy APIHarnessV2 instance
        filename: Name of the file to download
        search_domain: NGSIEM search domain (falcon, all, third-party, dashboards, parsers-repository)
        output_path: Optional path to save the file (if None, returns bytes)

    Returns:
        If output_path is provided: Dict with status
        If output_path is None: Raw bytes of file content or error dict
    """
    endpoint = "/ngsiem-content/entities/lookupfiles/v1"
    override = f"GET,{endpoint}"

    params = {"filename": filename, "search_domain": search_domain}

    response = falcon_client.command(override=override, parameters=params)

    # Check if successful - API may return bytes directly
    if isinstance(response, bytes):
        # Direct bytes response means success
        if output_path:
            with open(output_path, "wb") as f:
                f.write(response)
            return {"status": "success", "message": f"File saved to {output_path}"}
        else:
            return response

    elif isinstance(response, dict):
        # Check for success status code
        status_code = response.get("status_code")

        if status_code in (200, 201):
            body = response.get("body", b"")

            # Body might be bytes or dict with 'resources'
            if isinstance(body, bytes):
                content = body
            elif isinstance(body, dict):
                resources = body.get("resources", [])
                if resources and len(resources) > 0:
                    content = resources[0]
                    if isinstance(content, dict):
                        content = content.get("content", b"")
                else:
                    content = body.get("content", b"")
            else:
                content = b""

            # Ensure content is bytes
            if isinstance(content, str):
                content = content.encode("utf-8")

            if output_path and content:
                with open(output_path, "wb") as f:
                    f.write(content)
                return {"status": "success", "message": f"File saved to {output_path}"}
            else:
                return content if content else response
        else:
            # Error response - return as-is for caller to handle
            return response
    else:
        # Unexpected response type
        return {"error": f"Unexpected response type: {type(response)}", "response": str(response)}


def download_json(
    falcon_client, filename: str, search_domain: str = "falcon"
) -> Tuple[Optional[Union[Dict, list]], Optional[str]]:
    """
    Download and parse a JSON file from NGSIEM.

    Args:
        falcon_client: An authenticated FalconPy APIHarnessV2 instance
        filename: Name of the JSON file to download
        search_domain: NGSIEM search domain (falcon, all, third-party, dashboards, parsers-repository)

    Returns:
        Tuple of (parsed JSON data, error message)
        On success: (data, None)
        On failure: (None, error_message)
    """
    try:
        content = download_file(falcon_client, filename, search_domain)

        # Check if it's a response dict with error
        if isinstance(content, dict):
            # Check for HTTP error status codes
            if "status_code" in content:
                status_code = content.get("status_code")
                if status_code == 404:
                    return None, "File not found"
                elif status_code not in (200, 201):
                    errors = content.get("errors", [])
                    if errors:
                        error_msg = (
                            errors[0].get("message", str(errors[0])) if isinstance(errors[0], dict) else str(errors[0])
                        )
                    else:
                        error_msg = f"HTTP {status_code}"
                    return None, f"API error: {error_msg}"

            if "error" in content:
                return None, f"Error: {content['error']}"
            if "errors" in content and content["errors"]:
                errors = content.get("errors", [])
                error_msg = errors[0].get("message", str(errors[0])) if isinstance(errors[0], dict) else str(errors[0])
                return None, f"API error: {error_msg}"

            # If it's a dict but not an error, it might be valid JSON data
            # Only return if it doesn't look like an API response
            if not set(content.keys()).intersection({"status_code", "headers", "body"}):
                return content, None
            else:
                # Looks like an API response wrapper, not parsed JSON
                return None, "Unexpected API response format (no content)"

        # If it's bytes, try to parse as JSON
        if isinstance(content, bytes):
            try:
                return json.loads(content.decode("utf-8")), None
            except json.JSONDecodeError as e:
                return None, f"Invalid JSON: {e}"
        elif isinstance(content, str):
            try:
                return json.loads(content), None
            except json.JSONDecodeError as e:
                return None, f"Invalid JSON: {e}"
        else:
            return None, f"Unexpected response type: {type(content)}"

    except Exception as e:
        return None, f"Download failed: {e}"


def file_exists(falcon_client, filename: str, search_domain: str = "falcon") -> bool:
    """
    Check if a file exists in NGSIEM lookup files.

    Args:
        falcon_client: An authenticated FalconPy APIHarnessV2 instance
        filename: Name of the file to check
        search_domain: NGSIEM search domain (falcon, all, third-party, dashboards, parsers-repository)

    Returns:
        True if file exists, False otherwise
    """
    try:
        content = download_file(falcon_client, filename, search_domain)

        # Check for success
        if isinstance(content, bytes) and len(content) > 0:
            return True

        if isinstance(content, dict):
            # Check for error indicators
            if "error" in content or "errors" in content:
                return False
            if content.get("status_code", 200) not in (200, 201):
                return False
            return True

        return False
    except Exception:
        return False
