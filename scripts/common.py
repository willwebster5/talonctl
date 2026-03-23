#!/usr/bin/env python3
"""
Common utilities and path management for all scripts in the CrowdStrike Detection project.

This module provides centralized path management and import utilities to make
script reorganization easier and imports more reliable.

Usage in any script:
    import sys
    from pathlib import Path
    
    def find_scripts_dir():
        current = Path(__file__).resolve().parent
        while current.name != 'scripts' and current != current.parent:
            current = current.parent
        return current if current.name == 'scripts' else Path(__file__).parent
    
    SCRIPTS_DIR = find_scripts_dir()
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    
    from common import PATHS, load_auth, setup_imports
"""

import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional

# ============================================================================
# PATH DEFINITIONS (Central location for all script paths)
# ============================================================================

class ScriptPaths:
    """Centralized path definitions for all scripts in the project"""
    
    def __init__(self):
        # Base directories
        self.SCRIPTS_DIR = Path(__file__).parent.resolve()
        self.PROJECT_ROOT = self.SCRIPTS_DIR.parent
        self.UTILS_DIR = self.SCRIPTS_DIR / 'utils'
        
        # Core CI/CD scripts
        self.DETECTION_DEPLOY = self.SCRIPTS_DIR / 'detection_deploy.py'
        self.WORKFLOW_DEPLOY = self.SCRIPTS_DIR / 'workflow_deploy.py'
        self.CREATE_BACKUP = self.SCRIPTS_DIR / 'create_backup.py'
        
        # Utility scripts (moved locations)
        self.CREATE_DETECTION = self.UTILS_DIR / 'create_detection.py'
        self.WORKFLOW_GENERATOR = self.UTILS_DIR / 'workflow_generator.py'
        self.METRICS_COLLECTOR = self.UTILS_DIR / 'metrics_collector.py'
        self.DEPLOYMENT_UTILS = self.UTILS_DIR / 'deployment_utils.py'
        
        # Project directories
        self.RULES_DIR = self.PROJECT_ROOT / 'rules'
        self.DETECTIONS_DIR = self.PROJECT_ROOT / 'detections'
        self.CROWDSTRIKE_DIR = self.PROJECT_ROOT / '.crowdstrike'
        self.DOCS_DIR = self.PROJECT_ROOT / 'docs'
        self.WORKFLOWS_DIR = self.PROJECT_ROOT / '.github' / 'workflows'

# Create global instance
PATHS = ScriptPaths()

# ============================================================================
# IMPORT SETUP UTILITIES
# ============================================================================

def setup_imports() -> None:
    """
    Setup import paths for all scripts.
    Call this after adding scripts directory to sys.path.
    """
    # Ensure utils directory is importable
    utils_dir = str(PATHS.UTILS_DIR)
    if utils_dir not in sys.path:
        sys.path.append(utils_dir)
    

def load_auth() -> Optional[Dict[str, Any]]:
    """
    Load authentication credentials using the utils.auth module.
    Returns None if credentials cannot be loaded.
    """
    try:
        # Import here to avoid circular imports
        from utils.auth import load_credentials
        return load_credentials()
    except ImportError as e:
        print(f"Warning: Could not load auth module: {e}")
        return None
    except Exception as e:
        print(f"Warning: Could not load credentials: {e}")
        return None

def get_falcon_client(service: str = "detection", **kwargs):
    """
    Get a configured FalconPy client for the specified service.
    
    Args:
        service: The FalconPy service to initialize (detection, workflows, etc.)
        **kwargs: Additional arguments to pass to the client
        
    Returns:
        Configured FalconPy client or None if setup fails
    """
    creds = load_auth()
    if not creds:
        return None
    
    try:
        if service.lower() == "detection":
            from falconpy import CustomIOC
            return CustomIOC(
                client_id=creds["falcon_client_id"],
                client_secret=creds["falcon_client_secret"],
                base_url=creds.get("base_url", "US1"),
                **kwargs
            )
        elif service.lower() == "workflows":
            from falconpy import Workflows
            return Workflows(
                client_id=creds["falcon_client_id"],
                client_secret=creds["falcon_client_secret"],
                base_url=creds.get("base_url", "US1"),
                **kwargs
            )
        else:
            print(f"Unknown service: {service}")
            return None
            
    except ImportError as e:
        print(f"Warning: FalconPy not available: {e}")
        return None
    except Exception as e:
        print(f"Warning: Could not create {service} client: {e}")
        return None

# ============================================================================
# SCRIPT LOCATION UTILITIES
# ============================================================================

def find_script_by_name(script_name: str) -> Optional[Path]:
    """
    Find a script by name in the organized directory structure.
    
    Args:
        script_name: Name of the script (with or without .py extension)
        
    Returns:
        Path to the script if found, None otherwise
    """
    if not script_name.endswith('.py'):
        script_name += '.py'
    
    # Check all possible locations
    search_dirs = [
        PATHS.SCRIPTS_DIR,
    ]
    
    for search_dir in search_dirs:
        script_path = search_dir / script_name
        if script_path.exists():
            return script_path
    
    return None

def get_script_category(script_path: Path) -> str:
    """
    Determine the category of a script based on its location.
    
    Args:
        script_path: Path to the script
        
    Returns:
        Category string (cicd, migration, analysis, cleanup, testing, utilities)
    """
    try:
        relative_path = script_path.relative_to(PATHS.SCRIPTS_DIR)
        parts = relative_path.parts
        
        if len(parts) == 1:
            return "cicd"  # Root scripts are CI/CD
        elif len(parts) >= 2 and parts[0] == "manual":
            return parts[1]  # manual/category/script.py
        else:
            return "unknown"
            
    except ValueError:
        return "external"

# ============================================================================
# VALIDATION UTILITIES  
# ============================================================================

def validate_paths() -> bool:
    """
    Validate that all expected paths exist.
    Returns True if all critical paths are valid.
    """
    critical_paths = [
        PATHS.SCRIPTS_DIR,
        PATHS.PROJECT_ROOT,
        PATHS.UTILS_DIR
    ]
    
    missing_paths = []
    for path in critical_paths:
        if not path.exists():
            missing_paths.append(str(path))
    
    if missing_paths:
        print(f"Warning: Missing critical paths: {missing_paths}")
        return False
    
    return True

# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def import_from_script(script_name: str, module_name: str):
    """
    Import a module from a script by name.
    Handles path setup automatically.
    
    Args:
        script_name: Name of the script file
        module_name: Name of the module/class to import
        
    Returns:
        Imported module/class or None if import fails
    """
    script_path = find_script_by_name(script_name)
    if not script_path:
        print(f"Script not found: {script_name}")
        return None
    
    # Add script's directory to path temporarily
    script_dir = str(script_path.parent)
    path_added = False
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
        path_added = True
    
    try:
        # Import the module
        module = __import__(script_path.stem)
        return getattr(module, module_name, module)
    except Exception as e:
        print(f"Failed to import {module_name} from {script_name}: {e}")
        return None
    finally:
        # Clean up path
        if path_added and script_dir in sys.path:
            sys.path.remove(script_dir)

def list_scripts_by_category() -> Dict[str, list]:
    """List all scripts organized by category"""
    categories = {}
    
    for script_file in PATHS.SCRIPTS_DIR.rglob("*.py"):
        if script_file.name == "__init__.py" or script_file.name == "common.py":
            continue
            
        category = get_script_category(script_file)
        if category not in categories:
            categories[category] = []
        categories[category].append(script_file)
    
    return categories

# ============================================================================
# INITIALIZATION
# ============================================================================

def _initialize():
    """Initialize common module - run basic validation"""
    if not validate_paths():
        print("Warning: Some paths are missing. Script functionality may be limited.")

# Run initialization when module is imported
_initialize()

# ============================================================================
# STANDARD HEADER FOR ALL SCRIPTS (Copy this to each script)
# ============================================================================

STANDARD_HEADER = '''
# Standard header for all scripts - copy to top of each script:

import sys
from pathlib import Path

def find_scripts_dir():
    """Find scripts directory from any subdirectory"""
    current = Path(__file__).resolve().parent
    while current.name != 'scripts' and current != current.parent:
        current = current.parent
    return current if current.name == 'scripts' else Path(__file__).parent

SCRIPTS_DIR = find_scripts_dir()
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from common import PATHS, load_auth, setup_imports
setup_imports()

# Now you can import from any script location:
# from utils.auth import load_credentials  # Direct import
# from workflow_generator import WorkflowGenerator  # Import moved scripts
# etc.
'''

if __name__ == "__main__":
    print("CrowdStrike Scripts Common Module")
    print("=" * 50)
    print(f"Scripts Directory: {PATHS.SCRIPTS_DIR}")
    print(f"Project Root: {PATHS.PROJECT_ROOT}")
    print(f"Validation: {'PASSED' if validate_paths() else 'FAILED'}")
    
    print("\nScript Categories:")
    for category, scripts in list_scripts_by_category().items():
        print(f"  {category}: {len(scripts)} scripts")
    
    print(f"\nTo use in your scripts:")
    print(STANDARD_HEADER)