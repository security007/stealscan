import zipfile
import re
import xml.etree.ElementTree as ET
from collections import defaultdict


def parse_android_manifest(manifest_bytes):
    """Parse AndroidManifest.xml from binary format"""
    try:
        # Try to parse as text first (decompiled APKs)
        manifest_str = manifest_bytes.decode('utf-8')
        root = ET.fromstring(manifest_str)
        return root
    except:
        # Binary format requires special handling
        # For now, return None and handle with androguard if available
        return None


def extract_permissions(apk_zip):
    """Extract and analyze permissions from APK"""
    dangerous_permissions = {
        'android.permission.READ_SMS': 'Read SMS messages',
        'android.permission.SEND_SMS': 'Send SMS messages',
        'android.permission.RECEIVE_SMS': 'Receive SMS messages',
        'android.permission.READ_CONTACTS': 'Read contacts',
        'android.permission.WRITE_CONTACTS': 'Modify contacts',
        'android.permission.CAMERA': 'Access camera',
        'android.permission.RECORD_AUDIO': 'Record audio',
        'android.permission.READ_CALL_LOG': 'Read call logs',
        'android.permission.WRITE_CALL_LOG': 'Modify call logs',
        'android.permission.ACCESS_FINE_LOCATION': 'Access precise location',
        'android.permission.ACCESS_COARSE_LOCATION': 'Access approximate location',
        'android.permission.READ_PHONE_STATE': 'Read phone state and identity',
        'android.permission.CALL_PHONE': 'Make phone calls',
        'android.permission.READ_EXTERNAL_STORAGE': 'Read external storage',
        'android.permission.WRITE_EXTERNAL_STORAGE': 'Write to external storage',
        'android.permission.INTERNET': 'Full network access',
        'android.permission.ACCESS_NETWORK_STATE': 'View network connections',
        'android.permission.RECEIVE_BOOT_COMPLETED': 'Run at startup',
        'android.permission.SYSTEM_ALERT_WINDOW': 'Display over other apps',
        'android.permission.REQUEST_INSTALL_PACKAGES': 'Install packages',
        'android.permission.REQUEST_DELETE_PACKAGES': 'Delete packages',
        'android.permission.BIND_DEVICE_ADMIN': 'Device administrator',
        'android.permission.BIND_ACCESSIBILITY_SERVICE': 'Accessibility service',
        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': 'Notification access',
        'android.permission.READ_LOGS': 'Read system logs',
        'android.permission.WAKE_LOCK': 'Prevent phone from sleeping',
        'android.permission.DISABLE_KEYGUARD': 'Disable lock screen',
        'android.permission.GET_ACCOUNTS': 'Find accounts on device',
        'android.permission.USE_CREDENTIALS': 'Use accounts on device',
        'android.permission.MANAGE_ACCOUNTS': 'Add or remove accounts',
        'android.permission.AUTHENTICATE_ACCOUNTS': 'Act as account authenticator',
    }
    
    permissions_found = []
    
    try:
        # Read AndroidManifest.xml
        manifest_data = apk_zip.read('AndroidManifest.xml')
        
        # Try simple string search first (works on both binary and text)
        manifest_str = str(manifest_data)
        for perm in dangerous_permissions:
            if perm in manifest_str:
                permissions_found.append((perm, dangerous_permissions[perm]))
        
        # Try XML parsing for better accuracy
        root = parse_android_manifest(manifest_data)
        if root:
            for elem in root.iter():
                if 'permission' in elem.tag.lower():
                    perm_name = elem.get('{http://schemas.android.com/apk/res/android}name', '')
                    if perm_name and perm_name not in [p[0] for p in permissions_found]:
                        desc = dangerous_permissions.get(perm_name, 'Custom permission')
                        permissions_found.append((perm_name, desc))
    except Exception as e:
        pass
    
    return permissions_found


def analyze_dex_files(apk_zip):
    """Analyze DEX files for suspicious patterns"""
    detections = []
    
    dex_files = [name for name in apk_zip.namelist() if name.endswith('.dex')]
    
    suspicious_strings = [
        b'Runtime.exec',
        b'ProcessBuilder',
        b'/system/bin/su',
        b'/system/xbin/su',
        b'su -c',
        b'Superuser',
        b'supersu',
        b'magisk',
        b'xposed',
        b'frida',
        b'substrate',
        b'cydia',
        b'shell',
        b'/data/data/',
        b'android.intent.action.BOOT_COMPLETED',
        b'android.permission.RECEIVE_BOOT_COMPLETED',
        b'ClassLoader',
        b'DexClassLoader',
        b'PathClassLoader',
        b'InMemoryDexClassLoader',
        b'BaseDexClassLoader',
        b'loadClass',
        b'getDex',
        b'crypto',
        b'cipher',
        b'encrypt',
        b'decrypt',
        b'keystore',
        b'TelephonyManager',
        b'getDeviceId',
        b'getSubscriberId',
        b'getSimSerialNumber',
        b'getLine1Number',
        b'SmsManager',
        b'sendTextMessage',
        b'sendDataMessage',
        b'LocationManager',
        b'getLastKnownLocation',
        b'requestLocationUpdates',
        b'HttpURLConnection',
        b'HttpsURLConnection',
        b'URLConnection',
        b'Socket',
        b'ServerSocket',
        b'WebView',
        b'addJavascriptInterface',
        b'loadUrl',
        b'evaluateJavascript',
        b'ContentResolver',
        b'query',
        b'Runtime.getRuntime',
        b'exec',
        b'ProcessBuilder',
        b'getInputStream',
        b'getOutputStream',
        b'android.app.admin.DeviceAdminReceiver',
        b'android.app.admin.DevicePolicyManager',
        b'lockNow',
        b'wipeData',
        b'resetPassword',
        b'AccessibilityService',
        b'onAccessibilityEvent',
        b'NotificationListenerService',
        b'onNotificationPosted',
    ]
    
    # Malicious package patterns
    suspicious_packages = [
        b'com.metasploit',
        b'com.example.test',
        b'com.test',
        b'com.android.reverse',
        b'payload',
        b'backdoor',
        b'trojan',
        b'rat',
        b'stealer',
        b'keylog',
    ]
    
    for dex_file in dex_files:
        try:
            dex_data = apk_zip.read(dex_file)
            
            found_strings = defaultdict(int)
            
            # Search for suspicious strings
            for pattern in suspicious_strings:
                if pattern in dex_data:
                    pattern_str = pattern.decode('utf-8', errors='ignore')
                    found_strings[pattern_str] += 1
            
            # Search for suspicious packages
            for package in suspicious_packages:
                if package in dex_data:
                    package_str = package.decode('utf-8', errors='ignore')
                    detections.append(('android_suspicious_package', 
                                     f"Found suspicious package: {package_str} in {dex_file}"))
            
            # Report found strings grouped by severity
            if found_strings:
                high_risk = ['Runtime.exec', 'ProcessBuilder', 'su -c', '/system/bin/su', 
                           'DexClassLoader', 'wipeData', 'lockNow']
                medium_risk = ['TelephonyManager', 'getDeviceId', 'SmsManager', 
                             'LocationManager', 'addJavascriptInterface']
                
                for string, count in found_strings.items():
                    if any(risk in string for risk in high_risk):
                        detections.append(('android_high_risk_api', 
                                         f"{string} found {count}x in {dex_file}"))
                    elif any(risk in string for risk in medium_risk):
                        detections.append(('android_medium_risk_api', 
                                         f"{string} found {count}x in {dex_file}"))
        
        except Exception as e:
            detections.append(('android_dex_error', f"Error analyzing {dex_file}: {str(e)}"))
    
    return detections


def analyze_native_libraries(apk_zip):
    """Analyze native libraries (.so files) for suspicious content"""
    detections = []
    
    lib_files = [name for name in apk_zip.namelist() if name.endswith('.so')]
    
    if not lib_files:
        return detections
    
    detections.append(('android_native_libs', f"Found {len(lib_files)} native libraries"))
    
    suspicious_lib_patterns = [
        b'system/bin/su',
        b'system/xbin/su',
        b'/data/local/tmp',
        b'socket',
        b'connect',
        b'exec',
        b'fork',
        b'ptrace',
        b'inject',
        b'hook',
        b'LD_PRELOAD',
    ]
    
    for lib_file in lib_files:
        try:
            lib_data = apk_zip.read(lib_file)
            
            for pattern in suspicious_lib_patterns:
                if pattern in lib_data:
                    pattern_str = pattern.decode('utf-8', errors='ignore')
                    detections.append(('android_suspicious_native', 
                                     f"Suspicious string '{pattern_str}' in {lib_file}"))
        except Exception as e:
            pass
    
    return detections


def analyze_resources(apk_zip):
    """Analyze resources for suspicious content"""
    detections = []
    
    # Check for hidden APKs or DEX files in assets
    suspicious_extensions = ['.apk', '.dex', '.jar', '.zip', '.so']
    
    for name in apk_zip.namelist():
        if name.startswith('assets/') or name.startswith('res/raw/'):
            for ext in suspicious_extensions:
                if name.endswith(ext):
                    detections.append(('android_hidden_payload', 
                                     f"Hidden file in resources: {name}"))
                    break
    
    return detections


def check_certificate_info(apk_zip):
    """Check APK certificate and signature"""
    detections = []
    
    cert_files = [name for name in apk_zip.namelist() 
                 if name.startswith('META-INF/') and (name.endswith('.RSA') or name.endswith('.DSA'))]
    
    if not cert_files:
        detections.append(('android_no_signature', 'APK is not signed (highly suspicious)'))
    else:
        # Check for debug certificates
        for cert_file in cert_files:
            if 'CERT.RSA' in cert_file or 'debug' in cert_file.lower():
                detections.append(('android_debug_signed', 
                                 'APK is signed with debug certificate'))
    
    return detections


def analyze_permissions_combination(permissions):
    """Analyze dangerous permission combinations"""
    detections = []
    
    perm_names = [p[0] for p in permissions]
    
    # Spyware combination
    spyware_perms = [
        'android.permission.READ_SMS',
        'android.permission.READ_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.INTERNET'
    ]
    if all(perm in perm_names for perm in spyware_perms):
        detections.append(('android_spyware_pattern', 
                         'Permission combination indicates potential spyware'))
    
    # SMS Trojan combination
    sms_trojan_perms = [
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.INTERNET',
        'android.permission.RECEIVE_BOOT_COMPLETED'
    ]
    if all(perm in perm_names for perm in sms_trojan_perms):
        detections.append(('android_sms_trojan_pattern', 
                         'Permission combination indicates potential SMS trojan'))
    
    # Banking Trojan combination
    banking_perms = [
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.INTERNET'
    ]
    if all(perm in perm_names for perm in banking_perms):
        detections.append(('android_banking_trojan_pattern', 
                         'Permission combination indicates potential banking trojan'))
    
    # Device Admin abuse
    admin_perms = [
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.INTERNET'
    ]
    if all(perm in perm_names for perm in admin_perms):
        detections.append(('android_device_admin_abuse', 
                         'Requests device admin privileges with network access'))
    
    # Ransomware combination
    ransomware_perms = [
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.DISABLE_KEYGUARD'
    ]
    if all(perm in perm_names for perm in ransomware_perms):
        detections.append(('android_ransomware_pattern', 
                         'Permission combination indicates potential ransomware'))
    
    return detections


def scan_android(filepath, rules):
    """
    Advanced Android APK/DEX file scanner
    Performs comprehensive analysis of Android packages
    """
    detections = []
    
    try:
        file_ext = filepath.lower().split('.')[-1]
        
        if file_ext == 'apk':
            with zipfile.ZipFile(filepath, 'r') as apk_zip:
                # 1. Basic APK structure check
                required_files = ['AndroidManifest.xml', 'classes.dex']
                file_list = apk_zip.namelist()
                
                for req_file in required_files:
                    if req_file not in file_list:
                        detections.append(('android_malformed', 
                                         f"Missing required file: {req_file}"))
                
                # 2. Extract and analyze permissions
                permissions = extract_permissions(apk_zip)
                if permissions:
                    dangerous_count = len(permissions)
                    if dangerous_count > 15:
                        detections.append(('android_excessive_permissions', 
                                         f"Requests {dangerous_count} dangerous permissions"))
                    
                    # List critical permissions
                    critical_perms = [p for p in permissions if any(x in p[0] for x in 
                                     ['DEVICE_ADMIN', 'SYSTEM_ALERT', 'ACCESSIBILITY', 
                                      'NOTIFICATION_LISTENER', 'INSTALL_PACKAGES'])]
                    
                    for perm, desc in critical_perms:
                        detections.append(('android_critical_permission', 
                                         f"{perm}: {desc}"))
                    
                    # Analyze permission combinations
                    combo_detections = analyze_permissions_combination(permissions)
                    detections.extend(combo_detections)
                
                # 3. Analyze DEX files
                dex_detections = analyze_dex_files(apk_zip)
                detections.extend(dex_detections)
                
                # 4. Analyze native libraries
                native_detections = analyze_native_libraries(apk_zip)
                detections.extend(native_detections)
                
                # 5. Check resources for hidden payloads
                resource_detections = analyze_resources(apk_zip)
                detections.extend(resource_detections)
                
                # 6. Check certificate/signature
                cert_detections = check_certificate_info(apk_zip)
                detections.extend(cert_detections)
                
                # 7. Check for suspicious file names
                suspicious_files = []
                suspicious_patterns = ['payload', 'exploit', 'shell', 'backdoor', 
                                     'trojan', 'rat', 'stealer', 'metasploit',
                                     'reverse', 'bind', 'meterpreter']
                
                for name in file_list:
                    name_lower = name.lower()
                    for pattern in suspicious_patterns:
                        if pattern in name_lower:
                            suspicious_files.append(name)
                            break
                
                if suspicious_files:
                    detections.append(('android_suspicious_files', 
                                     f"Suspicious files: {', '.join(suspicious_files[:5])}"))
                
                # 8. Check for obfuscation indicators
                if any('classes' in name and name.endswith('.dex') 
                      for name in file_list if name.count('.') > 1):
                    detections.append(('android_multiple_dex', 
                                     'Multiple DEX files detected (possible obfuscation)'))
        
        elif file_ext == 'dex':
            # Standalone DEX file analysis
            with open(filepath, 'rb') as f:
                dex_data = f.read()
                
                # Check DEX magic header
                if not dex_data.startswith(b'dex\n'):
                    detections.append(('android_invalid_dex', 
                                     'Invalid DEX file header'))
                else:
                    # Search for suspicious strings in DEX
                    suspicious_strings = [
                        b'Runtime.exec', b'ProcessBuilder', b'/system/bin/su',
                        b'DexClassLoader', b'TelephonyManager', b'SmsManager'
                    ]
                    
                    for pattern in suspicious_strings:
                        if pattern in dex_data:
                            pattern_str = pattern.decode('utf-8', errors='ignore')
                            detections.append(('android_dex_suspicious_string', 
                                             f"Found: {pattern_str}"))
        
        elif file_ext in ['jar', 'class']:
            # Java bytecode analysis
            with open(filepath, 'rb') as f:
                data = f.read()
                
                # Check for Android-specific classes
                android_indicators = [
                    b'android/app/Activity',
                    b'android/content/Context',
                    b'android/os/Bundle',
                ]
                
                for indicator in android_indicators:
                    if indicator in data:
                        detections.append(('android_java_android_code', 
                                         'Contains Android-specific code'))
                        break
        
        # Generate risk score
        if detections:
            high_risk = sum(1 for d in detections if 'high_risk' in d[0] or 
                          'trojan' in d[0] or 'ransomware' in d[0] or 'spyware' in d[0])
            medium_risk = sum(1 for d in detections if 'medium_risk' in d[0] or 
                            'suspicious' in d[0])
            
            total_score = (high_risk * 10) + (medium_risk * 5) + len(detections)
            
            if total_score > 50:
                risk_level = "CRITICAL"
            elif total_score > 30:
                risk_level = "HIGH"
            elif total_score > 15:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            detections.append(('android_risk_assessment', 
                             f"Risk Level: {risk_level} (Score: {total_score})"))
    
    except zipfile.BadZipFile:
        detections.append(('android_error', 'Invalid or corrupted APK/ZIP file'))
    except Exception as e:
        detections.append(('android_error', f"Analysis error: {str(e)}"))
    
    return detections