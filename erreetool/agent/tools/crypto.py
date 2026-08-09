"""
Built-in crypto/encoding tool - no external binary needed.

Supports: Base64, Base32, Base58, Hex, URL, HTML, Unicode, ROT13, Caesar, Morse,
          MD5, SHA1, SHA256, SHA512, AES encrypt/decrypt, JWT encode/decode, auto-decode.
"""

import base64
import hashlib
import html
import json
import urllib.parse
from typing import Optional
from dataclasses import dataclass

from erreetool.agent.tools.base import ToolWrapper, ToolResult


@dataclass
class CryptoResult:
    """Result of a crypto operation."""
    operation: str
    input: str
    output: str
    success: bool
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "input": self.input,
            "output": self.output,
            "success": self.success,
            "error": self.error,
        }


class CryptoTool:
    """Built-in cryptographic and encoding operations."""
    
    # Encoding operations
    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def base64_decode(data: str) -> str:
        return base64.b64decode(data.encode()).decode()
    
    @staticmethod
    def base32_encode(data: str) -> str:
        return base64.b32encode(data.encode()).decode()
    
    @staticmethod
    def base32_decode(data: str) -> str:
        return base64.b32decode(data.encode()).decode()
    
    @staticmethod
    def base58_encode(data: str) -> str:
        """Base58 encoding (Bitcoin-style)."""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(data.encode(), "big")
        if num == 0:
            return alphabet[0]
        result = ""
        while num > 0:
            num, idx = divmod(num, 58)
            result = alphabet[idx] + result
        # Add leading 1s for leading zero bytes
        leading_zeros = len(data) - len(data.lstrip('\x00'))
        return alphabet[0] * leading_zeros + result
    
    @staticmethod
    def base58_decode(data: str) -> str:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = 0
        for char in data:
            num = num * 58 + alphabet.index(char)
        byte_length = (num.bit_length() + 7) // 8
        return num.to_bytes(byte_length, "big").decode()
    
    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()
    
    @staticmethod
    def hex_decode(data: str) -> str:
        return bytes.fromhex(data).decode()
    
    @staticmethod
    def url_encode(data: str) -> str:
        return urllib.parse.quote(data, safe="")
    
    @staticmethod
    def url_decode(data: str) -> str:
        return urllib.parse.unquote(data)
    
    @staticmethod
    def html_encode(data: str) -> str:
        return html.escape(data)
    
    @staticmethod
    def html_decode(data: str) -> str:
        return html.unescape(data)
    
    @staticmethod
    def unicode_escape(data: str) -> str:
        return data.encode("unicode_escape").decode()
    
    @staticmethod
    def unicode_unescape(data: str) -> str:
        return data.encode().decode("unicode_escape")
    
    @staticmethod
    def rot13(data: str) -> str:
        return data.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
    
    @staticmethod
    def caesar_encode(data: str, shift: int = 3) -> str:
        result = ""
        for char in data:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return result
    
    @staticmethod
    def caesar_decode(data: str, shift: int = 3) -> str:
        return CryptoTool.caesar_encode(data, -shift)
    
    @staticmethod
    def morse_encode(data: str) -> str:
        morse = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
            "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
            '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
            '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
            ' ': '/'
        }
        return ' '.join(morse.get(c.upper(), '') for c in data)
    
    @staticmethod
    def morse_decode(data: str) -> str:
        morse = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
            '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
            '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
            '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')',
            '.-...': '&', '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
            '-....-': '-', '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
            '/': ' '
        }
        return ''.join(morse.get(c, '') for c in data.split(' '))
    
    # Hashing operations
    @staticmethod
    def md5(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def sha1(data: str) -> str:
        return hashlib.sha1(data.encode()).hexdigest()
    
    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def sha512(data: str) -> str:
        return hashlib.sha512(data.encode()).hexdigest()
    
    # AES encryption (requires cryptography library)
    @staticmethod
    def aes_encrypt(data: str, key: str, iv: str = None) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            return "ERROR: cryptography library not installed"
        
        key_bytes = key.encode()[:32].ljust(32, b'\x00')
        iv_bytes = iv.encode()[:16].ljust(16, b'\x00') if iv else b'\x00' * 16
        
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        return base64.b64encode(ciphertext).decode()
    
    @staticmethod
    def aes_decrypt(data: str, key: str, iv: str = None) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            return "ERROR: cryptography library not installed"
        
        key_bytes = key.encode()[:32].ljust(32, b'\x00')
        iv_bytes = iv.encode()[:16].ljust(16, b'\x00') if iv else b'\x00' * 16
        
        ciphertext = base64.b64decode(data.encode())
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        
        return plaintext.decode()
    
    # JWT operations
    @staticmethod
    def jwt_decode(token: str) -> str:
        """Decode JWT without verification (for analysis)."""
        parts = token.split('.')
        if len(parts) != 3:
            return "ERROR: Invalid JWT format"
        
        def decode_part(part: str) -> str:
            # Add padding if needed
            padding = 4 - len(part) % 4
            if padding != 4:
                part += '=' * padding
            return base64.urlsafe_b64decode(part).decode()
        
        header = decode_part(parts[0])
        payload = decode_part(parts[1])
        signature = parts[2]
        
        return f"HEADER:\n{json.dumps(json.loads(header), indent=2)}\n\nPAYLOAD:\n{json.dumps(json.loads(payload), indent=2)}\n\nSIGNATURE: {signature}"
    
    @staticmethod
    def jwt_encode(header: dict, payload: dict, secret: str = "secret") -> str:
        """Encode JWT with HS256."""
        import hmac
        import hashlib
        
        def encode_part(part: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(part, separators=(',', ':')).encode()).decode().rstrip('=')
        
        encoded_header = encode_part(header)
        encoded_payload = encode_part(payload)
        signing_input = f"{encoded_header}.{encoded_payload}"
        
        signature = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        ).decode().rstrip('=')
        
        return f"{signing_input}.{signature}"
    
    # Auto-decode: try all common encodings
    @staticmethod
    def auto_decode(data: str) -> list[CryptoResult]:
        """Try all common decodings and return successful ones."""
        results = []
        
        decoders = [
            ("base64", CryptoTool.base64_decode),
            ("base32", CryptoTool.base32_decode),
            ("base58", CryptoTool.base58_decode),
            ("hex", CryptoTool.hex_decode),
            ("url", CryptoTool.url_decode),
            ("html", CryptoTool.html_decode),
            ("unicode", CryptoTool.unicode_unescape),
            ("rot13", CryptoTool.rot13),
            ("caesar", CryptoTool.caesar_decode),
            ("morse", CryptoTool.morse_decode),
        ]
        
        for name, decoder in decoders:
            try:
                output = decoder(data)
                # Check if output looks like valid text
                if output and all(ord(c) < 127 or c in '\n\r\t' for c in output):
                    results.append(CryptoResult(
                        operation=f"{name}_decode",
                        input=data,
                        output=output,
                        success=True
                    ))
            except Exception:
                pass
        
        return results
    
    @staticmethod
    def identify_hash(hash_str: str) -> list[str]:
        """Identify possible hash types based on length and format."""
        hash_str = hash_str.strip().lower()
        results = []
        
        length = len(hash_str)
        
        if length == 32 and all(c in '0123456789abcdef' for c in hash_str):
            results.append("MD5")
        if length == 40 and all(c in '0123456789abcdef' for c in hash_str):
            results.append("SHA1")
        if length == 64 and all(c in '0123456789abcdef' for c in hash_str):
            results.append("SHA256")
        if length == 128 and all(c in '0123456789abcdef' for c in hash_str):
            results.append("SHA512")
        if length == 32 and all(c in '0123456789abcdef' for c in hash_str):
            results.append("NTLM")
        
        return results if results else ["Unknown"]


class CryptoWrapper(ToolWrapper):
    """Tool wrapper interface for crypto operations."""
    
    name = "crypto"
    windows_binary = "python"
    linux_binary = "python"
    DEFAULT_TIMEOUT = 30
    
    def __init__(self):
        super().__init__()
        self.tool = CryptoTool()
    
    def build_args(self, **kwargs) -> list[str]:
        # Not used for built-in tool
        return []
    
    def is_available(self) -> bool:
        return True  # Always available
    
    def run(self, operation: str, data: str, **kwargs) -> ToolResult:
        """Execute a crypto operation."""
        start_time = time.time()
        evidence_id = f"crypto_{operation}_{uuid.uuid4().hex[:8]}"
        
        try:
            # Get the operation method
            method = getattr(self.tool, operation, None)
            if not method:
                return ToolResult(
                    success=False,
                    stdout="",
                    stderr=f"Unknown crypto operation: {operation}",
                    returncode=-1,
                    command=["crypto", operation],
                    duration=time.time() - start_time,
                    evidence_id=evidence_id,
                    tool_name=self.name,
                )
            
            # Call the method with kwargs
            output = method(data, **kwargs)
            
            return ToolResult(
                success=True,
                stdout=str(output),
                stderr="",
                returncode=0,
                command=["crypto", operation],
                duration=time.time() - start_time,
                evidence_id=evidence_id,
                tool_name=self.name,
            )
        
        except Exception as e:
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Crypto operation failed: {e}",
                returncode=-1,
                command=["crypto", operation],
                duration=time.time() - start_time,
                evidence_id=evidence_id,
                tool_name=self.name,
            )
    
    def auto_decode(self, data: str) -> ToolResult:
        """Try all decodings."""
        start_time = time.time()
        evidence_id = f"crypto_auto_decode_{uuid.uuid4().hex[:8]}"
        
        try:
            results = self.tool.auto_decode(data)
            output = "\n\n".join([f"=== {r.operation} ===\n{r.output}" for r in results])
            
            return ToolResult(
                success=len(results) > 0,
                stdout=output or "No successful decodings found",
                stderr="",
                returncode=0 if results else 1,
                command=["crypto", "auto_decode"],
                duration=time.time() - start_time,
                evidence_id=evidence_id,
                tool_name=self.name,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Auto-decode failed: {e}",
                returncode=-1,
                command=["crypto", "auto_decode"],
                duration=time.time() - start_time,
                evidence_id=evidence_id,
                tool_name=self.name,
            )
    
    def identify_hash(self, hash_str: str) -> ToolResult:
        """Identify hash type."""
        start_time = time.time()
        evidence_id = f"crypto_identify_hash_{uuid.uuid4().hex[:8]}"
        
        try:
            types = self.tool.identify_hash(hash_str)
            output = f"Possible hash types for {hash_str}:\n" + "\n".join(f"  - {t}" for t in types)
            
            return ToolResult(
                success=True,
                stdout=output,
                stderr="",
                returncode=0,
                command=["crypto", "identify_hash"],
                duration=time.time() - start_time,
                evidence_id=evidence_id,
                tool_name=self.name,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Hash identification failed: {e}",
                returncode=-1,
                command=["crypto", "identify_hash"],
                duration=time.time() - start_time,
                evidence_id=evidence_id,
                tool_name=self.name,
            )


# Register the tool
from erreetool.agent.tools.base import tool_registry
import time
import uuid
tool_registry.register(CryptoWrapper())