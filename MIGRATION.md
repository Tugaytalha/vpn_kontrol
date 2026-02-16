# VPN Kontrol Migration Guide

## Migrating from Old Security to New Security

### Overview

The VPN Kontrol application has been upgraded with **enterprise-grade security**. This guide explains how to migrate from the old system to the new one.

### What Changed?

**Old System:**
- ❌ Individual DPAPI encryption per secret (no entropy)
- ❌ Secrets stored directly in config.json
- ❌ No file ACL protection
- ❌ Secrets remained in memory
- ❌ No integrity protection

**New System:**
- ✅ Master key pattern (DPAPI + AES-GCM)
- ✅ Entropy for additional DPAPI protection
- ✅ Secrets in secure storage directory
- ✅ File ACLs restrict access
- ✅ Secure memory handling
- ✅ Authenticated encryption (integrity + confidentiality)

### Automatic Migration

**Good News:** Migration happens automatically!

1. **First Run After Update:**
   ```bash
   python app.py
   ```

2. **What Happens:**
   - Application detects old format secrets
   - Decrypts using old method
   - Re-encrypts with new secure storage
   - Updates config.json with new markers
   - Moves secrets to %LOCALAPPDATA%\vpn_kontrol\

3. **You'll See:**
   ```
   Secure storage initialized with DPAPI + AES-GCM master key pattern
   Migrating legacy DPAPI secret 'password' to new secure storage...
   Migrating legacy DPAPI secret 'totp_secret' to new secure storage...
   ```

### File Structure Changes

**Before:**
```
your_project/
├── app.py
├── config.json          ← Contained encrypted secrets
├── templates/
└── vpn_history.json
```

**After:**
```
your_project/
├── app.py
├── secure_storage.py    ← NEW: Security module
├── config.json          ← Now contains only markers
├── templates/
└── vpn_history.json

%LOCALAPPDATA%\vpn_kontrol\  ← NEW: Secure storage location
├── master.key           ← DPAPI-protected master key
├── entropy.bin          ← Random entropy bytes
└── secrets.dat          ← AES-GCM encrypted secrets
```

**Location on Windows:**
```
C:\Users\YourName\AppData\Local\vpn_kontrol\
```

### config.json Format Changes

**Old Format:**
```json
{
  "password": "dpapi:AQAAANCMnd8BFdERjHo...",
  "totp_secret": "dpapi:AQAAANCMnd8BFdER..."
}
```

**New Format:**
```json
{
  "password": "secure_storage:password",
  "totp_secret": "secure_storage:totp_secret"
}
```

**Explanation:**
- Old: Encrypted value stored directly in JSON
- New: Just a marker, actual encrypted data in secure storage

### Manual Migration (if needed)

If automatic migration fails, you can manually migrate:

#### Step 1: Backup Your Old Config
```bash
copy config.json config.json.backup
```

#### Step 2: Extract Secrets
Open `config.json.backup` and note your encrypted secrets.

#### Step 3: Run Migration Script
```python
from secure_storage import SecureStorage
import json

# Load old config
with open('config.json.backup', 'r') as f:
    old_config = json.load(f)

# Create secure storage
storage = SecureStorage()

# Migrate password
if old_config.get('password'):
    # If it's plaintext
    storage.store_secret('password', old_config['password'])
    
# Migrate TOTP secret
if old_config.get('totp_secret'):
    storage.store_secret('totp_secret', old_config['totp_secret'])

print("Migration complete!")
```

#### Step 4: Update Config
```python
import json

config = {
    "vpn_ip": "10.54.2.74",
    "check_interval": 5,
    "vpn_url": "https://your-vpn-url.com",
    "username": "your.username",
    "password": "secure_storage:password",
    "realm": "",
    "totp_secret": "secure_storage:totp_secret",
    "auto_connect": false
}

with open('config.json', 'w') as f:
    json.dump(config, f, indent=4)
```

### Verification

#### Check Migration Success
```python
python -c "from secure_storage import SecureStorage; s = SecureStorage(); print('Secrets:', s.list_secrets())"
```

**Expected Output:**
```
Secrets: ['password', 'totp_secret']
```

#### Verify Secret Retrieval
```python
from secure_storage import SecureStorage

storage = SecureStorage()

# This should return your password (only for testing!)
password = storage.retrieve_secret('password')
print(f"Password length: {len(password)}")  # Don't print actual password!
```

#### Check File Permissions
```powershell
# Check ACLs on Windows
icacls "$env:LOCALAPPDATA\vpn_kontrol\secrets.dat"
```

**Expected Output:**
```
C:\Users\YourName\AppData\Local\vpn_kontrol\secrets.dat
  NT AUTHORITY\SYSTEM:(F)
  YOURDOMAIN\YourName:(F)
```

### Rollback (if needed)

If you need to rollback to old system:

#### Step 1: Restore Backup
```bash
copy config.json.backup config.json
```

#### Step 2: Remove New Files
```bash
Remove-Item -Recurse "$env:LOCALAPPDATA\vpn_kontrol"
Remove-Item secure_storage.py
```

#### Step 3: Restore Old app.py
```bash
# Use version control (git) to restore old version
git checkout HEAD~1 app.py
```

**Note:** We don't recommend rollback - the new system is significantly more secure!

### Troubleshooting

#### Issue: "Could not initialize secure storage"

**Cause:** Missing dependencies or LOCALAPPDATA not set

**Solution:**
```bash
# Install dependencies
pip install cryptography pywin32

# Check environment
echo $env:LOCALAPPDATA
```

#### Issue: Migration doesn't happen

**Cause:** Old secrets already in plaintext

**Solution:**
- Old plaintext secrets ARE migrated automatically
- Check `%LOCALAPPDATA%\vpn_kontrol\secrets.dat` exists
- Enable debug mode: `$env:VPN_KONTROL_DEBUG = "true"`

#### Issue: "Failed to decrypt legacy secret"

**Cause:** DPAPI secrets can only be decrypted by same user

**Solution:**
- Ensure you're logged in as same Windows user who created the secrets
- If not possible, manually re-enter credentials in UI

#### Issue: File permission errors

**Cause:** Antivirus or file system issues

**Solution:**
```powershell
# Grant yourself full control
icacls "$env:LOCALAPPDATA\vpn_kontrol" /grant "$env:USERNAME:(OI)(CI)F" /T

# Or temporarily disable antivirus
```

### Post-Migration Checklist

- [ ] Application starts without errors
- [ ] Secrets are loaded correctly (check in UI)
- [ ] VPN connection works
- [ ] TOTP token generated successfully
- [ ] File ACLs are set correctly
- [ ] config.json shows `secure_storage:` markers
- [ ] Secrets exist in `%LOCALAPPDATA%\vpn_kontrol\secrets.dat`

### Security Benefits After Migration

1. **Stronger Encryption:**
   - Before: Basic DPAPI only
   - After: DPAPI + entropy + AES-GCM

2. **Better File Protection:**
   - Before: Default file permissions
   - After: Restricted ACLs (user + SYSTEM only)

3. **Integrity Protection:**
   - Before: None
   - After: AES-GCM authentication tags detect tampering

4. **Memory Safety:**
   - Before: Secrets in memory indefinitely
   - After: Cleared after use with SecureString

5. **Organized Storage:**
   - Before: Mixed with config
   - After: Dedicated secure location

### Alternative: Windows Credential Manager

If you prefer using Windows Credential Manager instead:

#### Enable Credential Manager Mode
```bash
$env:VPN_USE_CREDENTIAL_MANAGER = "true"
python app.py
```

#### Manual Storage
```python
from secure_storage import WindowsCredentialManager

WindowsCredentialManager.store_credential(
    target='vpn_kontrol_vpn_creds',
    username='your.username',
    password='your_password'
)

WindowsCredentialManager.store_credential(
    target='vpn_kontrol_totp_secret',
    username='your.username',
    password='YOUR_TOTP_SECRET'
)
```

#### View in Control Panel
1. Open Control Panel
2. Go to "Credential Manager"
3. Click "Windows Credentials"
4. Look for `vpn_kontrol_*` entries

### Backup Strategy

#### Backup Secure Storage
```powershell
# Backup entire secure storage directory
Copy-Item -Recurse "$env:LOCALAPPDATA\vpn_kontrol" "$env:USERPROFILE\Desktop\vpn_kontrol_backup"
```

**Important Notes:**
- Backups can only be restored on same Windows account
- DPAPI master key is user-specific
- Don't share backups (they contain your secrets!)

#### Export for Different Machine
If you need to move to a different machine:

1. **Don't try to copy encrypted files** (won't work)
2. **Instead, export secrets temporarily:**
   ```python
   from secure_storage import SecureStorage
   storage = SecureStorage()
   
   password = storage.retrieve_secret('password')
   totp = storage.retrieve_secret('totp_secret')
   
   # Write to secure location, transfer, then delete
   ```
3. **On new machine:** Enter credentials fresh in UI

### Questions?

**Q: Will my old config.json still work?**  
A: Yes! Migration is automatic.

**Q: Can I switch back to old system?**  
A: Yes, but not recommended. See Rollback section.

**Q: What if I lose the secure storage files?**  
A: Re-enter credentials in the application UI. They'll be saved again.

**Q: Are my secrets still tied to my Windows account?**  
A: Yes, even more so now with enhanced DPAPI + entropy.

**Q: Do I need to do anything after migration?**  
A: No, everything works automatically.

**Q: Should I delete config.json.backup?**  
A: After verifying migration worked, yes:
```bash
Remove-Item config.json.backup
```

---

## Summary

Migration is **automatic and seamless**. Just update the code and run the application. The new security system will:
1. Detect old format secrets
2. Decrypt them safely
3. Re-encrypt with new system
4. Store in secure location
5. Update config.json

Your credentials are now protected with **enterprise-grade security**! 🔒
