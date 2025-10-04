#!/usr/bin/env python3
"""Quick converter: Transform sync modules to async.

This script automatically converts synchronous attack modules to async versions.
"""
import re
from pathlib import Path

# Modules to convert (in priority order)
MODULES_TO_CONVERT = [
    'xss',
    'ssrf', 
    'command_injection',
    'csrf',
    'path_traversal',
    'open_redirect',
    'lfi_rfi',
    'insecure_headers',
    'cors',
    'insecure_deserialization',
    'api_vulnerabilities',
]

def convert_module_to_async(module_name: str):
    """Convert a sync module to async."""
    
    # Read original file
    sync_file = Path(f'argus/modules/attack_modules/{module_name}.py')
    if not sync_file.exists():
        print(f"❌ {module_name}.py not found")
        return False
    
    content = sync_file.read_text()
    
    # Skip if already has async_base import (already converted)
    if 'from .async_base import' in content or 'AsyncBaseAttackModule' in content:
        print(f"✅ {module_name}.py already async")
        return True
    
    # Basic transformations
    new_content = content
    
    # 1. Update imports
    new_content = new_content.replace(
        'import requests',
        'import httpx'
    )
    new_content = new_content.replace(
        'from .base import BaseAttackModule',
        'from .async_base import AsyncBaseAttackModule'
    )
    new_content = new_content.replace(
        'class .*Module(BaseAttackModule):',
        lambda m: m.group(0).replace('BaseAttackModule', 'AsyncBaseAttackModule')
    )
    
    # 2. Update scan method signature
    new_content = re.sub(
        r'def scan\(self, url: str, parameter: dict, session: requests\.Session\)',
        'async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient)',
        new_content
    )
    
    # 3. Update session.get/post calls to await client.get/post
    new_content = re.sub(
        r'session\.(get|post|put|delete|patch)\(',
        r'await client.\1(',
        new_content
    )
    
    # 4. Mark helper methods that make HTTP calls as async
    # This is tricky - we'll look for methods that call session.get/post
    lines = new_content.split('\n')
    new_lines = []
    in_method = False
    method_makes_requests = False
    method_start_indent = 0
    
    for i, line in enumerate(lines):
        # Check if this is a method definition
        method_match = re.match(r'(\s+)def (_\w+)\(self', line)
        if method_match:
            in_method = True
            method_start_indent = len(method_match.group(1))
            # Check if method body has await client calls
            method_body_start = i + 1
            method_body = '\n'.join(lines[method_body_start:min(method_body_start+50, len(lines))])
            if 'await client.' in method_body or 'await self.' in method_body:
                # Make this method async
                line = line.replace('def ', 'async def ', 1)
        
        new_lines.append(line)
    
    new_content = '\n'.join(new_lines)
    
    # 5. Add await to helper method calls that are now async
    # This requires more sophisticated analysis, so we'll do it conservatively
    new_content = re.sub(
        r'(\s+)(self\._test_\w+\()',
        r'\1await \2',
        new_content
    )
    new_content = re.sub(
        r'(\s+)(self\._check_\w+\()',
        r'\1await \2',
        new_content
    )
    
    # Write to new file
    async_file = Path(f'argus/modules/attack_modules/async_{module_name}.py')
    async_file.write_text(new_content)
    
    print(f"✅ Created async_{module_name}.py")
    return True


if __name__ == '__main__':
    print("🔄 Converting modules to async...\n")
    
    success_count = 0
    for module in MODULES_TO_CONVERT:
        if convert_module_to_async(module):
            success_count += 1
    
    print(f"\n✅ Converted {success_count}/{len(MODULES_TO_CONVERT)} modules")
    print("\n📝 Note: Auto-conversion is approximate. Review each file for:")
    print("   - Nested async calls (await await)")
    print("   - Blocking operations (time.sleep, etc)")
    print("   - Sync libraries (requests should be httpx)")
