"""
SQLMap tool wrapper for SQL injection detection and exploitation.

Automated SQL injection testing and database extraction.
"""

from erreetool.agent.tools.base import ToolWrapper, ToolResult


class SQLMapWrapper(ToolWrapper):
    """Wrapper for sqlmap SQL injection tool."""
    
    name = "sqlmap"
    windows_binary = "sqlmap.exe"
    linux_binary = "sqlmap"
    DEFAULT_TIMEOUT = 600  # SQLMap can take a while
    
    def build_args(
        self,
        target: str,
        url: str = None,
        data: str = None,
        method: str = "GET",
        parameter: str = None,
        risk: int = 1,
        level: int = 1,
        technique: str = "BEUSTQ",
        dbms: str = None,
        tamper: str = None,
        batch: bool = True,
        output_format: str = "json",
        extra_args: list[str] = None,
        **kwargs
    ) -> list[str]:
        """Build sqlmap command arguments."""
        args = []
        
        # Target URL
        if url:
            args.extend(["-u", url])
        else:
            args.extend(["-u", target])
        
        # POST data
        if data:
            args.extend(["--data", data])
            method = "POST"
        
        # HTTP method
        args.extend(["--method", method])
        
        # Parameter to test
        if parameter:
            args.extend(["-p", parameter])
        
        # Risk and level
        args.extend(["--risk", str(risk)])
        args.extend(["--level", str(level)])
        
        # Technique
        args.extend(["--technique", technique])
        
        # DBMS
        if dbms:
            args.extend(["--dbms", dbms])
        
        # Tamper scripts
        if tamper:
            args.extend(["--tamper", tamper])
        
        # Batch mode (non-interactive)
        if batch:
            args.append("--batch")
        
        # Output format
        if output_format == "json":
            args.extend(["--output-dir", "/tmp/sqlmap_out", "--dump-format", "JSON"])
        
        # Common options
        args.extend([
            "--random-agent",
            "--timeout", "30",
            "--retries", "2",
        ])
        
        # Extra args
        if extra_args:
            args.extend(extra_args)
        
        return args
    
    def quick_test(self, url: str, param: str = None) -> ToolResult:
        """Quick SQLi test (low risk/level)."""
        return self.run(
            url=url,
            parameter=param,
            risk=1,
            level=1,
            technique="BEU"
        )
    
    def full_test(self, url: str, param: str = None) -> ToolResult:
        """Comprehensive SQLi test."""
        return self.run(
            url=url,
            parameter=param,
            risk=3,
            level=5,
            technique="BEUSTQ"
        )
    
    def dump_database(self, url: str, param: str = None, db: str = None) -> ToolResult:
        """Dump database contents."""
        args = {
            "url": url,
            "parameter": param,
            "risk": 3,
            "level": 5,
        }
        if db:
            args["extra_args"] = ["--db", db, "--dump"]
        else:
            args["extra_args"] = ["--dump-all"]
        return self.run(**args)
    
    def get_tables(self, url: str, param: str = None, db: str = None) -> ToolResult:
        """Enumerate database tables."""
        args = {
            "url": url,
            "parameter": param,
            "extra_args": ["--tables"]
        }
        if db:
            args["extra_args"] = ["--db", db, "--tables"]
        return self.run(**args)
    
    def get_columns(self, url: str, table: str, db: str = None, param: str = None) -> ToolResult:
        """Enumerate table columns."""
        args = {
            "url": url,
            "parameter": param,
            "extra_args": ["--columns", "-T", table]
        }
        if db:
            args["extra_args"].extend(["-D", db])
        return self.run(**args)
    
    def os_shell(self, url: str, param: str = None) -> ToolResult:
        """Attempt OS shell via SQLi."""
        return self.run(
            url=url,
            parameter=param,
            extra_args=["--os-shell"],
            batch=False  # Interactive needed for shell
        )
    
    def detect_waf(self, url: str, param: str = None) -> ToolResult:
        """Test for WAF/IPS."""
        return self.run(
            url=url,
            parameter=param,
            extra_args=["--identify-waf"],
            risk=1,
            level=1
        )


# Register the tool
from erreetool.agent.tools.base import tool_registry
tool_registry.register(SQLMapWrapper())