"""
Gobuster/Feroxbuster tool wrapper for directory/file enumeration.

Supports gobuster (Go) and feroxbuster (Rust) for cross-platform compatibility.
"""

from erreetool.agent.tools.base import ToolWrapper, ToolResult


class GobusterWrapper(ToolWrapper):
    """Wrapper for gobuster directory enumeration."""
    
    name = "gobuster"
    windows_binary = "gobuster.exe"
    linux_binary = "gobuster"
    DEFAULT_TIMEOUT = 300
    
    def __init__(self, timeout: int = None, custom_binary: str = None, mode: str = "dir"):
        super().__init__(timeout, custom_binary)
        self.mode = mode  # dir, dns, vhost, fuzz
    
    def build_args(
        self,
        target: str,
        wordlist: str = None,
        extensions: str = "php,html,txt,js,json,xml,asp,aspx,jsp",
        threads: int = 50,
        status_codes: str = "200,204,301,302,307,401,403",
        output_format: str = "json",
        extra_args: list[str] = None,
        **kwargs
    ) -> list[str]:
        """Build gobuster command arguments."""
        args = [self.mode]
        
        # Target URL
        args.extend(["-u", target])
        
        # Wordlist
        if wordlist:
            args.extend(["-w", wordlist])
        
        # Extensions (for dir mode)
        if self.mode == "dir" and extensions:
            args.extend(["-x", extensions])
        
        # Threads
        args.extend(["-t", str(threads)])
        
        # Status codes
        args.extend(["-s", status_codes])
        
        # Output format
        if output_format == "json":
            args.extend(["-o", "-", "--json"])
        elif output_format == "csv":
            args.extend(["-o", "-", "--csv"])
        
        # Quiet
        args.append("-q")
        
        # Extra args
        if extra_args:
            args.extend(extra_args)
        
        return args
    
    def dir_scan(
        self,
        target: str,
        wordlist: str = None,
        extensions: str = "php,html,txt,js,json,xml,asp,aspx,jsp",
        threads: int = 50
    ) -> ToolResult:
        """Directory enumeration scan."""
        self.mode = "dir"
        return self.run(
            target=target,
            wordlist=wordlist,
            extensions=extensions,
            threads=threads
        )
    
    def dns_scan(self, target: str, wordlist: str = None) -> ToolResult:
        """DNS subdomain enumeration."""
        self.mode = "dns"
        return self.run(target=target, wordlist=wordlist)
    
    def vhost_scan(self, target: str, wordlist: str = None) -> ToolResult:
        """Virtual host enumeration."""
        self.mode = "vhost"
        return self.run(target=target, wordlist=wordlist)
    
    def fuzz_scan(
        self,
        target: str,
        wordlist: str = None,
        extensions: str = ""
    ) -> ToolResult:
        """Parameter fuzzing."""
        self.mode = "fuzz"
        return self.run(target=target, wordlist=wordlist, extensions=extensions)


class FeroxbusterWrapper(ToolWrapper):
    """Wrapper for feroxbuster (Rust alternative, often faster)."""
    
    name = "feroxbuster"
    windows_binary = "feroxbuster.exe"
    linux_binary = "feroxbuster"
    DEFAULT_TIMEOUT = 300
    
    def build_args(
        self,
        target: str,
        wordlist: str = None,
        extensions: str = "php,html,txt,js,json,xml,asp,aspx,jsp",
        threads: int = 50,
        status_codes: str = "200,204,301,302,307,401,403",
        output_format: str = "json",
        extra_args: list[str] = None,
        **kwargs
    ) -> list[str]:
        """Build feroxbuster command arguments."""
        args = []
        
        # Target URL
        args.extend(["-u", target])
        
        # Wordlist
        if wordlist:
            args.extend(["-w", wordlist])
        
        # Extensions
        if extensions:
            args.extend(["-x", extensions])
        
        # Threads
        args.extend(["-t", str(threads)])
        
        # Status codes
        args.extend(["-s", status_codes])
        
        # Output format
        if output_format == "json":
            args.extend(["--json", "-"])
        
        # Quiet
        args.extend(["--quiet", "--no-color"])
        
        # Extra args
        if extra_args:
            args.extend(extra_args)
        
        return args
    
    def scan(
        self,
        target: str,
        wordlist: str = None,
        extensions: str = "php,html,txt,js,json,xml,asp,aspx,jsp",
        threads: int = 50
    ) -> ToolResult:
        """Directory enumeration scan."""
        return self.run(
            target=target,
            wordlist=wordlist,
            extensions=extensions,
            threads=threads
        )


# Register the tools
from erreetool.agent.tools.base import tool_registry
tool_registry.register(GobusterWrapper())
tool_registry.register(FeroxbusterWrapper())