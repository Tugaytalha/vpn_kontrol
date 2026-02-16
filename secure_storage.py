"""
Secure Storage Module for VPN Kontrol

This module implements defense-in-depth security for sensitive credentials using:
1. DPAPI (Data Protection API) with entropy for master key protection
2. AES-GCM authenticated encryption for individual secrets
3. Secure file permissions (ACLs) limiting access to current user
4. Windows Credential Manager integration as an alternative
5. Secure memory handling to minimize exposure time

Security Features:
- Master key pattern: One DPAPI-protected master key encrypts all secrets
- AES-GCM provides authenticated encryption (integrity + confidentiality)
- Entropy adds additional protection beyond standard DPAPI
- Tight file ACLs prevent other users/processes from reading secrets
- Secrets are zeroed from memory when no longer needed
- No secrets in exception messages or logs
"""

import os
import sys
import json
import ctypes
import base64
import secrets
import threading
from typing import Optional, Dict, Any, Tuple
from pathlib import Path


class SecureByteArray:
    """Secure byte array that zeros memory when no longer needed"""
    
    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._cleared = False
    
    def get(self) -> bytes:
        """Get the data (use sparingly)"""
        if self._cleared:
            raise ValueError("Data has been cleared")
        return bytes(self._data)
    
    def clear(self):
        """Zero out the data in memory"""
        if not self._cleared:
            # Overwrite with zeros
            for i in range(len(self._data)):
                self._data[i] = 0
            self._cleared = True
    
    def __del__(self):
        """Ensure data is cleared when object is destroyed"""
        self.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


class SecureString:
    """Secure string that clears memory when no longer needed"""
    
    def __init__(self, text: str):
        self._data = SecureByteArray(text.encode('utf-8'))
    
    def get(self) -> str:
        """Get the string value (use sparingly)"""
        return self._data.get().decode('utf-8')
    
    def clear(self):
        """Zero out the string in memory"""
        self._data.clear()
    
    def __del__(self):
        self.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


class WindowsSecurityError(Exception):
    """Raised when Windows security operations fail"""
    pass


class DPAPIProtector:
    """
    Windows DPAPI (Data Protection API) wrapper with entropy support.
    
    Uses CryptProtectData/CryptUnprotectData for per-user encryption.
    Entropy adds an extra layer of protection beyond standard DPAPI.
    """
    
    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]
    
    def __init__(self, entropy: Optional[bytes] = None):
        """
        Initialize DPAPI protector.
        
        Args:
            entropy: Optional additional entropy for DPAPI. Same entropy must be
                    used for encryption and decryption. Provides additional
                    protection but doesn't stop malware running as the same user.
        """
        if sys.platform != "win32":
            raise WindowsSecurityError("DPAPI is only available on Windows")
        
        self.entropy = entropy
    
    def protect(self, plaintext: bytes, description: str = "vpn_kontrol_secret") -> bytes:
        """
        Encrypt data using DPAPI.
        
        Args:
            plaintext: Data to encrypt
            description: Optional description for the encrypted blob
            
        Returns:
            Encrypted bytes
        """
        in_buffer = ctypes.create_string_buffer(plaintext, len(plaintext))
        in_blob = self.DATA_BLOB(len(plaintext), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        out_blob = self.DATA_BLOB()
        
        # Prepare entropy if provided
        entropy_blob = None
        entropy_buffer = None
        if self.entropy:
            entropy_buffer = ctypes.create_string_buffer(self.entropy, len(self.entropy))
            entropy_blob = self.DATA_BLOB(
                len(self.entropy),
                ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte))
            )
        
        crypt_protect_data = ctypes.windll.crypt32.CryptProtectData
        crypt_protect_data.argtypes = [
            ctypes.POINTER(self.DATA_BLOB),  # pDataIn
            ctypes.c_wchar_p,                 # szDataDescr
            ctypes.POINTER(self.DATA_BLOB),   # pOptionalEntropy
            ctypes.c_void_p,                  # pvReserved
            ctypes.c_void_p,                  # pPromptStruct
            ctypes.c_ulong,                   # dwFlags
            ctypes.POINTER(self.DATA_BLOB),   # pDataOut
        ]
        crypt_protect_data.restype = ctypes.c_bool
        
        success = crypt_protect_data(
            ctypes.byref(in_blob),
            description,
            ctypes.byref(entropy_blob) if entropy_blob else None,
            None,
            None,
            self.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        
        if not success:
            error_code = ctypes.get_last_error()
            raise WindowsSecurityError(f"CryptProtectData failed with error code {error_code}")
        
        try:
            encrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return encrypted_bytes
        finally:
            # Free memory allocated by CryptProtectData
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    
    def unprotect(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using DPAPI.
        
        Args:
            ciphertext: Encrypted data
            
        Returns:
            Decrypted bytes
        """
        in_buffer = ctypes.create_string_buffer(ciphertext, len(ciphertext))
        in_blob = self.DATA_BLOB(len(ciphertext), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        out_blob = self.DATA_BLOB()
        
        # Prepare entropy if provided
        entropy_blob = None
        entropy_buffer = None
        if self.entropy:
            entropy_buffer = ctypes.create_string_buffer(self.entropy, len(self.entropy))
            entropy_blob = self.DATA_BLOB(
                len(self.entropy),
                ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte))
            )
        
        crypt_unprotect_data = ctypes.windll.crypt32.CryptUnprotectData
        crypt_unprotect_data.argtypes = [
            ctypes.POINTER(self.DATA_BLOB),  # pDataIn
            ctypes.c_void_p,                  # ppszDataDescr
            ctypes.POINTER(self.DATA_BLOB),   # pOptionalEntropy
            ctypes.c_void_p,                  # pvReserved
            ctypes.c_void_p,                  # pPromptStruct
            ctypes.c_ulong,                   # dwFlags
            ctypes.POINTER(self.DATA_BLOB),   # pDataOut
        ]
        crypt_unprotect_data.restype = ctypes.c_bool
        
        success = crypt_unprotect_data(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(entropy_blob) if entropy_blob else None,
            None,
            None,
            self.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        
        if not success:
            error_code = ctypes.get_last_error()
            raise WindowsSecurityError(f"CryptUnprotectData failed with error code {error_code}")
        
        try:
            decrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return decrypted_bytes
        finally:
            # Free memory allocated by CryptUnprotectData
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)


class AESGCMCipher:
    """
    AES-GCM authenticated encryption wrapper.
    
    Provides both confidentiality and integrity protection for secrets.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize AES-GCM cipher.
        
        Args:
            key: 256-bit (32 byte) encryption key
        """
        if len(key) != 32:
            raise ValueError("AES-GCM key must be 32 bytes")
        
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self.cipher = AESGCM(key)
        except ImportError:
            raise WindowsSecurityError("cryptography library required for AES-GCM")
    
    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data with AES-GCM.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Tuple of (nonce, ciphertext_with_tag)
        """
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        ciphertext = self.cipher.encrypt(nonce, plaintext, None)
        return nonce, ciphertext
    
    def decrypt(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt and verify data with AES-GCM.
        
        Args:
            nonce: The nonce used during encryption
            ciphertext: Encrypted data with authentication tag
            
        Returns:
            Decrypted plaintext
            
        Raises:
            WindowsSecurityError: If authentication fails or data is tampered
        """
        try:
            plaintext = self.cipher.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise WindowsSecurityError(f"Decryption failed - data may be tampered: {type(e).__name__}")


class WindowsACLManager:
    """
    Manages Windows file ACLs (Access Control Lists) to restrict file access.
    """
    
    @staticmethod
    def set_user_only_permissions(file_path: str) -> bool:
        """
        Set file permissions so only the current user and SYSTEM can access it.
        
        Args:
            file_path: Path to file to secure
            
        Returns:
            True if successful, False otherwise
        """
        if sys.platform != "win32":
            # Fallback to Unix permissions
            try:
                os.chmod(file_path, 0o600)
                return True
            except Exception:
                return False
        
        try:
            import win32security
            import ntsecuritycon
            
            # Get current user SID
            user_sid = win32security.GetTokenInformation(
                win32security.OpenProcessToken(
                    win32security.GetCurrentProcess(),
                    win32security.TOKEN_QUERY
                ),
                win32security.TokenUser
            )[0]
            
            # Create new DACL (Discretionary Access Control List)
            dacl = win32security.ACL()
            
            # Add SYSTEM (Full Control)
            system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                ntsecuritycon.FILE_ALL_ACCESS,
                system_sid
            )
            
            # Add current user (Full Control)
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                ntsecuritycon.FILE_ALL_ACCESS,
                user_sid
            )
            
            # Create security descriptor and set DACL
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            
            # Apply to file
            win32security.SetFileSecurity(
                file_path,
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
            
            return True
        except ImportError:
            # pywin32 not available, try icacls
            return WindowsACLManager._set_permissions_with_icacls(file_path)
        except Exception as e:
            print(f"Warning: Could not set file ACLs: {e}")
            return False
    
    @staticmethod
    def _set_permissions_with_icacls(file_path: str) -> bool:
        """Fallback method using icacls.exe command"""
        try:
            import subprocess
            
            # Get current username
            username = os.environ.get('USERNAME', os.environ.get('USER', ''))
            if not username:
                return False
            
            # Reset ACLs to remove inheritance and grant only to current user
            commands = [
                # Disable inheritance and remove all inherited permissions
                ['icacls', file_path, '/inheritance:r'],
                # Grant full control to current user
                ['icacls', file_path, '/grant:r', f'{username}:(F)'],
                # Grant full control to SYSTEM
                ['icacls', file_path, '/grant:r', 'SYSTEM:(F)'],
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                if result.returncode != 0:
                    return False
            
            return True
        except Exception:
            return False


class WindowsCredentialManager:
    """
    Windows Credential Manager integration for storing credentials.
    
    Provides a cleaner alternative to file-based storage for credential-like secrets.
    """
    
    @staticmethod
    def is_available() -> bool:
        """Check if Windows Credential Manager is available"""
        if sys.platform != "win32":
            return False
        try:
            import win32cred
            return True
        except ImportError:
            return False
    
    @staticmethod
    def store_credential(target: str, username: str, password: str) -> bool:
        """
        Store a credential in Windows Credential Manager.
        
        Args:
            target: Target name (e.g., "vpn_kontrol_vpn_password")
            username: Username
            password: Password/secret to store
            
        Returns:
            True if successful
        """
        try:
            import win32cred
            import pywintypes
            
            credential = {
                'Type': win32cred.CRED_TYPE_GENERIC,
                'TargetName': target,
                'UserName': username,
                'CredentialBlob': password,
                'Comment': 'VPN Kontrol Application Credential',
                'Persist': win32cred.CRED_PERSIST_LOCAL_MACHINE
            }
            
            win32cred.CredWrite(credential, 0)
            return True
        except Exception as e:
            print(f"Warning: Could not store credential in Windows Credential Manager: {e}")
            return False
    
    @staticmethod
    def retrieve_credential(target: str) -> Optional[Tuple[str, str]]:
        """
        Retrieve a credential from Windows Credential Manager.
        
        Args:
            target: Target name
            
        Returns:
            Tuple of (username, password) or None if not found
        """
        try:
            import win32cred
            import pywintypes
            
            cred = win32cred.CredRead(target, win32cred.CRED_TYPE_GENERIC)
            username = cred['UserName']
            password = cred['CredentialBlob']
            return (username, password)
        except Exception:
            return None
    
    @staticmethod
    def delete_credential(target: str) -> bool:
        """Delete a credential from Windows Credential Manager"""
        try:
            import win32cred
            win32cred.CredDelete(target, win32cred.CRED_TYPE_GENERIC)
            return True
        except Exception:
            return False


class SecureStorage:
    """
    Master key pattern implementation for secure secret storage.
    
    Architecture:
    1. Generate a random 256-bit master key
    2. Protect master key with DPAPI (with entropy)
    3. Encrypt each secret with AES-GCM using master key
    4. Store: DPAPI(master_key) + {nonce, ciphertext, tag} per secret
    
    Benefits:
    - Single DPAPI operation for all secrets (easier management)
    - Authenticated encryption per secret (integrity protection)
    - Easier key rotation and versioning
    - Clear separation: DPAPI for key, AES-GCM for data
    """
    
    VERSION = 1
    MASTER_KEY_SIZE = 32  # 256 bits
    
    def __init__(self, storage_dir: Optional[str] = None, entropy: Optional[bytes] = None):
        """
        Initialize secure storage.
        
        Args:
            storage_dir: Directory for storing secrets (defaults to %LOCALAPPDATA%/vpn_kontrol)
            entropy: Optional entropy for DPAPI (stored separately)
        """
        if sys.platform != "win32":
            raise WindowsSecurityError("This secure storage implementation requires Windows")
        
        # Default to %LOCALAPPDATA%\vpn_kontrol
        if storage_dir is None:
            local_app_data = os.environ.get('LOCALAPPDATA', '')
            if not local_app_data:
                raise WindowsSecurityError("LOCALAPPDATA environment variable not set")
            storage_dir = os.path.join(local_app_data, 'vpn_kontrol')
        
        self.storage_dir = storage_dir
        self.master_key_file = os.path.join(storage_dir, 'master.key')
        self.secrets_file = os.path.join(storage_dir, 'secrets.dat')
        self.entropy_file = os.path.join(storage_dir, 'entropy.bin')
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_dir, exist_ok=True)
        WindowsACLManager.set_user_only_permissions(storage_dir)
        
        # Initialize entropy
        self._entropy = entropy if entropy else self._load_or_create_entropy()
        
        # Initialize DPAPI with entropy
        self.dpapi = DPAPIProtector(entropy=self._entropy)
        
        # Load or create master key
        self._master_key = None
        self._lock = threading.Lock()
        self._load_or_create_master_key()
    
    def _load_or_create_entropy(self) -> bytes:
        """Load existing entropy or create new random entropy"""
        if os.path.exists(self.entropy_file):
            try:
                with open(self.entropy_file, 'rb') as f:
                    entropy = f.read()
                if len(entropy) == 32:
                    return entropy
            except Exception:
                pass
        
        # Create new entropy
        entropy = secrets.token_bytes(32)
        try:
            with open(self.entropy_file, 'wb') as f:
                f.write(entropy)
            WindowsACLManager.set_user_only_permissions(self.entropy_file)
        except Exception as e:
            print(f"Warning: Could not save entropy file: {e}")
        
        return entropy
    
    def _load_or_create_master_key(self):
        """Load existing master key or create new one"""
        with self._lock:
            if os.path.exists(self.master_key_file):
                try:
                    with open(self.master_key_file, 'rb') as f:
                        protected_key = f.read()
                    
                    # Decrypt master key with DPAPI
                    master_key_bytes = self.dpapi.unprotect(protected_key)
                    self._master_key = SecureByteArray(master_key_bytes)
                    return
                except Exception as e:
                    print(f"Warning: Could not load master key: {e}")
            
            # Create new master key
            master_key_bytes = secrets.token_bytes(self.MASTER_KEY_SIZE)
            self._master_key = SecureByteArray(master_key_bytes)
            
            # Protect with DPAPI and save
            protected_key = self.dpapi.protect(master_key_bytes, "vpn_kontrol_master_key")
            
            try:
                with open(self.master_key_file, 'wb') as f:
                    f.write(protected_key)
                WindowsACLManager.set_user_only_permissions(self.master_key_file)
            except Exception as e:
                raise WindowsSecurityError(f"Failed to save master key: {e}")
    
    def _get_cipher(self) -> AESGCMCipher:
        """Get AES-GCM cipher with master key"""
        if self._master_key is None:
            raise WindowsSecurityError("Master key not initialized")
        return AESGCMCipher(self._master_key.get())
    
    def store_secret(self, key: str, value: str):
        """
        Store a secret securely.
        
        Args:
            key: Secret identifier (e.g., "password", "totp_secret")
            value: Secret value to store
        """
        with self._lock:
            # Load existing secrets
            secrets_data = self._load_secrets_file()
            
            # Encrypt the secret with AES-GCM
            cipher = self._get_cipher()
            nonce, ciphertext = cipher.encrypt(value.encode('utf-8'))
            
            # Store encrypted secret
            secrets_data[key] = {
                'version': self.VERSION,
                'nonce': base64.b64encode(nonce).decode('ascii'),
                'ciphertext': base64.b64encode(ciphertext).decode('ascii')
            }
            
            # Save to file
            self._save_secrets_file(secrets_data)
    
    def retrieve_secret(self, key: str) -> Optional[str]:
        """
        Retrieve a secret.
        
        Args:
            key: Secret identifier
            
        Returns:
            Secret value or None if not found
        """
        with self._lock:
            secrets_data = self._load_secrets_file()
            
            if key not in secrets_data:
                return None
            
            secret_entry = secrets_data[key]
            
            # Decrypt the secret
            nonce = base64.b64decode(secret_entry['nonce'])
            ciphertext = base64.b64decode(secret_entry['ciphertext'])
            
            cipher = self._get_cipher()
            plaintext = cipher.decrypt(nonce, ciphertext)
            
            return plaintext.decode('utf-8')
    
    def delete_secret(self, key: str) -> bool:
        """
        Delete a secret.
        
        Args:
            key: Secret identifier
            
        Returns:
            True if secret was deleted, False if not found
        """
        with self._lock:
            secrets_data = self._load_secrets_file()
            
            if key not in secrets_data:
                return False
            
            del secrets_data[key]
            self._save_secrets_file(secrets_data)
            return True
    
    def list_secrets(self) -> list:
        """Get list of stored secret keys (not values)"""
        with self._lock:
            secrets_data = self._load_secrets_file()
            return list(secrets_data.keys())
    
    def _load_secrets_file(self) -> Dict[str, Any]:
        """Load secrets file"""
        if not os.path.exists(self.secrets_file):
            return {}
        
        try:
            with open(self.secrets_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_secrets_file(self, data: Dict[str, Any]):
        """Save secrets file"""
        temp_file = self.secrets_file + '.tmp'
        
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            # Set permissions before moving
            WindowsACLManager.set_user_only_permissions(temp_file)
            
            # Atomic replace
            os.replace(temp_file, self.secrets_file)
            
            # Ensure final permissions
            WindowsACLManager.set_user_only_permissions(self.secrets_file)
        except Exception as e:
            # Clean up temp file
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
            raise WindowsSecurityError(f"Failed to save secrets file: {e}")
    
    def migrate_from_legacy(self, legacy_secrets: Dict[str, str]):
        """
        Migrate secrets from legacy storage format.
        
        Args:
            legacy_secrets: Dictionary of secret_name -> secret_value
        """
        for key, value in legacy_secrets.items():
            if value:  # Only migrate non-empty values
                self.store_secret(key, value)
    
    def __del__(self):
        """Cleanup: zero master key from memory"""
        if hasattr(self, '_master_key') and self._master_key:
            self._master_key.clear()


# Singleton instance for application-wide use
_secure_storage_instance: Optional[SecureStorage] = None
_storage_lock = threading.Lock()


def get_secure_storage() -> SecureStorage:
    """Get or create singleton SecureStorage instance"""
    global _secure_storage_instance
    
    if _secure_storage_instance is None:
        with _storage_lock:
            if _secure_storage_instance is None:
                _secure_storage_instance = SecureStorage()
    
    return _secure_storage_instance


def store_to_credential_manager(username: str, password: str, totp_secret: str) -> bool:
    """
    Helper to store credentials in Windows Credential Manager (alternative approach).
    
    Args:
        username: VPN username
        password: VPN password
        totp_secret: TOTP secret
        
    Returns:
        True if all credentials stored successfully
    """
    if not WindowsCredentialManager.is_available():
        return False
    
    success = True
    success &= WindowsCredentialManager.store_credential(
        'vpn_kontrol_vpn_creds',
        username,
        password
    )
    success &= WindowsCredentialManager.store_credential(
        'vpn_kontrol_totp_secret',
        username,
        totp_secret
    )
    
    return success


def retrieve_from_credential_manager(username: str) -> Optional[Dict[str, str]]:
    """
    Helper to retrieve credentials from Windows Credential Manager.
    
    Args:
        username: VPN username
        
    Returns:
        Dictionary with password and totp_secret, or None if not found
    """
    if not WindowsCredentialManager.is_available():
        return None
    
    result = {}
    
    cred = WindowsCredentialManager.retrieve_credential('vpn_kontrol_vpn_creds')
    if cred:
        result['password'] = cred[1]
    
    cred = WindowsCredentialManager.retrieve_credential('vpn_kontrol_totp_secret')
    if cred:
        result['totp_secret'] = cred[1]
    
    return result if result else None
