"""
Memory CLI commands for managing agent memory.
"""

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

from erreetool.agent.memory import MemoryType, memory_store

console = Console()


def run(
    subcommand: str = typer.Argument(
        "stats", help="Subcommand: list, show, search, stats, clear, export, import"
    ),
    entry_id: str = typer.Option(None, "--entry-id", help="Entry ID for show command"),
    query: str = typer.Option(None, "--query", help="Search query"),
    type: str = typer.Option(None, "--type", help="Filter by memory type"),
    limit: int = typer.Option(20, "--limit", help="Maximum entries to show"),
    tag: str = typer.Option(None, "--tag", help="Filter by tag"),
    raw: bool = typer.Option(False, "--raw", help="Show raw JSON"),
    output: str = typer.Option(
        "memory_export.json", "--output", help="Output file for export"
    ),
    input_file: str = typer.Option(None, "--input", help="Input file for import"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    replace: bool = typer.Option(
        False, "--replace", help="Replace existing memory instead of merging"
    ),
) -> None:
    """Manage agent persistent memory."""
    memory_store.load()

    if subcommand == "list":
        _list_memory(type, limit, tag)
    elif subcommand == "show":
        _show_memory(entry_id, raw)
    elif subcommand == "search":
        _search_memory(query, type, limit)
    elif subcommand == "stats":
        _memory_stats()
    elif subcommand == "clear":
        _clear_memory(type, confirm)
    elif subcommand == "export":
        _export_memory(output, type)
    elif subcommand == "import":
        _import_memory(input_file, not replace)
    else:
        console.print(f"[red]Unknown subcommand: {subcommand}[/red]")
        console.print("Available: list, show, search, stats, clear, export, import")


def _list_memory(type: str | None = None, limit: int = 20, tag: str | None = None):
    """List memory entries."""
    if type:
        try:
            mem_type = MemoryType(type)
            entries = memory_store.get_by_type(mem_type, limit)
        except ValueError:
            console.print(f"[red]Invalid type: {type}[/red]")
            console.print(f"Valid types: {[m.value for m in MemoryType]}")
            return
    elif tag:
        entries = memory_store.get_by_tag(tag, limit)
    else:
        # Show stats by type
        stats = memory_store.get_stats()
        table = Table(title="Memory Store Statistics")
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green")
        for t, count in stats["by_type"].items():
            table.add_row(t, str(count))
        console.print(table)
        console.print(f"\nTotal entries: {stats['total_entries']}")
        console.print(f"Memory directory: {stats['memory_dir']}")
        return

    if not entries:
        console.print("[yellow]No entries found[/yellow]")
        return

    table = Table(title=f"Memory Entries ({len(entries)} found)")
    table.add_column("ID", style="cyan", max_width=36)
    table.add_column("Type", style="yellow")
    table.add_column("Tags", style="green", max_width=40)
    table.add_column("Created", style="dim")
    table.add_column("Preview", style="white", max_width=60)

    for entry in entries:
        from datetime import datetime

        created = datetime.fromtimestamp(entry.created_at).strftime("%Y-%m-%d %H:%M")
        content_str = str(entry.content)[:80]
        table.add_row(
            entry.entry_id,
            entry.memory_type.value,
            ", ".join(entry.tags[:5]),
            created,
            content_str + ("..." if len(str(entry.content)) > 80 else ""),
        )

    console.print(table)


def _show_memory(entry_id: str | None = None, raw: bool = False):
    """Show a specific memory entry."""
    if not entry_id:
        console.print("[red]Entry ID required for show command[/red]")
        return

    entry = memory_store.get(entry_id)

    if not entry:
        console.print(f"[red]Entry not found: {entry_id}[/red]")
        return

    if raw:
        import json

        console.print(JSON(json.dumps(entry.content, indent=2)))
    else:
        from datetime import datetime

        console.print(
            Panel(
                f"[bold]ID:[/bold] {entry.entry_id}\n"
                f"[bold]Type:[/bold] {entry.memory_type.value}\n"
                f"[bold]Created:[/bold] {datetime.fromtimestamp(entry.created_at).isoformat()}\n"
                f"[bold]Updated:[/bold] {datetime.fromtimestamp(entry.updated_at).isoformat()}\n"
                f"[bold]Tags:[/bold] {', '.join(entry.tags)}\n"
                f"[bold]Relevance:[/bold] {entry.relevance_score:.2f}",
                title="Memory Entry",
            )
        )
        import json

        console.print(JSON(json.dumps(entry.content, indent=2)))


def _search_memory(query: str | None = None, type: str | None = None, limit: int = 20):
    """Search memory entries."""
    if not query:
        console.print("[red]Search query required[/red]")
        return

    mem_type = MemoryType(type) if type else None
    results = memory_store.search(query, mem_type, limit)

    if not results:
        console.print(f"[yellow]No results for: {query}[/yellow]")
        return

    table = Table(title=f"Search Results for '{query}' ({len(results)} found)")
    table.add_column("ID", style="cyan", max_width=36)
    table.add_column("Type", style="yellow")
    table.add_column("Tags", style="green", max_width=40)
    table.add_column("Preview", style="white", max_width=80)

    for entry in results:
        content_str = str(entry.content)[:100]
        table.add_row(
            entry.entry_id,
            entry.memory_type.value,
            ", ".join(entry.tags[:5]),
            content_str + ("..." if len(str(entry.content)) > 100 else ""),
        )

    console.print(table)


def _memory_stats():
    """Show memory store statistics."""
    stats = memory_store.get_stats()

    console.print(
        Panel(
            f"[bold]Total Entries:[/bold] {stats['total_entries']}\n"
            f"[bold]Memory Directory:[/bold] {stats['memory_dir']}",
            title="Memory Statistics",
        )
    )

    table = Table(title="Entries by Type")
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="green")
    for t, count in stats["by_type"].items():
        table.add_row(t, str(count))
    console.print(table)

    if stats["tags"]:
        table2 = Table(title="Top Tags")
        table2.add_column("Tag", style="cyan")
        table2.add_column("Count", style="green")
        for tag, count in sorted(stats["tags"].items(), key=lambda x: -x[1])[:20]:
            table2.add_row(tag, str(count))
        console.print(table2)


def _clear_memory(type: str | None = None, confirm: bool = False):
    """Clear memory entries."""
    if not confirm:
        console.print("[yellow]This will permanently delete memory entries![/yellow]")
        try:
            from rich.prompt import Confirm

            response = Confirm.ask("Are you sure?")
            if not response:
                console.print("[dim]Cancelled[/dim]")
                return
        except Exception:
            console.print("[red]Confirmation required. Use --yes flag.[/red]")
            return

    mem_type = MemoryType(type) if type else None
    memory_store.clear(mem_type)

    if type:
        console.print(f"[green]Cleared memory type: {type}[/green]")
    else:
        console.print("[green]Cleared all memory[/green]")


def _export_memory(output: str = "memory_export.json", type: str | None = None):
    """Export memory to JSON file."""
    mem_type = MemoryType(type) if type else None
    entries = (
        memory_store.get_by_type(mem_type)
        if mem_type
        else list(memory_store._entries.values())
    )

    export_data = {
        "exported_at": __import__("time").time(),
        "total_entries": len(entries),
        "entries": [e.to_dict() for e in entries],
    }

    import json

    with open(output, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)

    console.print(f"[green]Exported {len(entries)} entries to {output}[/green]")


def _import_memory(input_file: str | None = None, merge: bool = True):
    """Import memory from JSON file."""
    if not input_file:
        console.print("[red]Input file required for import[/red]")
        return

    import json
    import os

    if not os.path.exists(input_file):
        console.print(f"[red]File not found: {input_file}[/red]")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not merge:
        memory_store.clear()

    from erreetool.agent.memory.schema import MemoryEntry

    imported = 0
    for entry_data in data.get("entries", []):
        try:
            entry = MemoryEntry.from_dict(entry_data)
            memory_store.add(entry)
            imported += 1
        except Exception as e:
            console.print(f"[yellow]Skipped entry: {e}[/yellow]")

    console.print(f"[green]Imported {imported} entries[/green]")
