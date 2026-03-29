"""
NetAutoTool (ict4insat)
================
A production-grade CLI network automation tool for CCNA/DevNet engineers.
Targets: Packet Tracer, GNS3, and real Cisco IOS devices.

Author  : Anas abd elmalek cherif
Requires: colorama, ipaddress (stdlib)

Install : pip install colorama
Run     : python ict_tool.py
"""

import ipaddress
import math
from colorama import Fore, Style, init

init(autoreset=True)

#------------------------------------
#  THEME

C_HEADER  = Fore.YELLOW + Style.BRIGHT
C_SUCCESS = Fore.GREEN  + Style.BRIGHT
C_INFO    = Fore.CYAN
C_WARN    = Fore.MAGENTA
C_ERROR   = Fore.RED    + Style.BRIGHT
C_RESET   = Style.RESET_ALL


# --------------------------------------------
#  HELPERS


def _banner(title: str) -> None:
    width = 48
    bar   = "═" * width
    print(f"\n{C_HEADER}╔{bar}╗")
    print(f"║  {title:<{width - 2}}║")
    print(f"╚{bar}╝{C_RESET}")


def _field(label: str, value, color=C_INFO) -> None:
    print(f"  {Fore.WHITE}{label:<22}{color}{value}{C_RESET}")


def _prompt(msg: str) -> str:
    return input(f"{Fore.YELLOW}  → {msg}: {C_RESET}").strip()


def _prompt_int(msg: str, min_val: int = 1, max_val: int = 9999) -> int:
    while True:
        raw = _prompt(msg)
        if not raw.isdigit():
            print(f"{C_ERROR}  ✗ Enter a valid integer.{C_RESET}")
            continue
        val = int(raw)
        if not (min_val <= val <= max_val):
            print(f"{C_ERROR}  ✗ Value must be between {min_val} and {max_val}.{C_RESET}")
            continue
        return val


def _parse_ipv4_network(raw: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.ip_network(raw, strict=False)  
    except ValueError:
        raise ValueError(f"'{raw}' is not a valid IPv4 network/prefix.")


def _ipv4_class(addr: ipaddress.IPv4Address) -> str:
    first = int(str(addr).split(".")[0]) 
    if first < 128: return "A"
    if first < 192: return "B"
    if first < 224: return "C"
    if first < 240: return "D (Multicast)"
    return "E (Reserved)"


def _ipv4_usable_bounds(net: ipaddress.IPv4Network) -> tuple:
    """Return first/last usable host as strings for IPv4 subnet calculations."""
    if net.num_addresses < 4:
        return None, None
    first = str(net.network_address + 1)
    last = str(net.broadcast_address - 1)
    return first, last


def _mac_normalize(mac: str) -> list:
    """
    Accept any common MAC format and return a list of 6 uppercase hex byte strings.
    Accepted formats:
        52:74:f2:b1:a8:7f   (colon-separated)
        52-74-f2-b1-a8-7f   (dash-separated)
        5274.f2b1.a87f      (Cisco dot notation)
    """
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(cleaned) != 12 or not all(c in "0123456789ABCDEF" for c in cleaned):
        raise ValueError(f"'{mac}' is not a valid 48-bit MAC address.")
    return [cleaned[i:i+2] for i in range(0, 12, 2)]


def _mac_to_link_local(mac: str) -> str:
    """Core EUI-64 algorithm: MAC -> fe80::... Used internally by eui64_tool()."""
    parts = _mac_normalize(mac)
    eui64 = parts[:3] + ["FF", "FE"] + parts[3:]
    b0    = int(eui64[0], 16) ^ 0x02 
    eui64[0] = f"{b0:02X}"
    groups = [eui64[i] + eui64[i+1] for i in range(0, 8, 2)]
    iid    = ":".join(g.lower() for g in groups)
    return str(ipaddress.ip_address(f"fe80:0:0:0:{iid}"))


def _link_local_to_mac(ll: str) -> str:
    """Reverse EUI-64: fe80::... -> MAC. Requires FF:FE at bytes 3-4 of IID."""
    try:
        addr = ipaddress.ip_address(ll)
    except ValueError:
        raise ValueError(f"'{ll}' is not a valid IPv6 address.")
    if addr.version != 6:
        raise ValueError("Must be an IPv6 address.")

    groups    = addr.exploded.split(":")
    iid_grps  = groups[4:]
    iid_bytes = []
    for g in iid_grps:
        iid_bytes.append(g[0:2])
        iid_bytes.append(g[2:4])

    if iid_bytes[3].upper() != "FF" or iid_bytes[4].upper() != "FE":
        raise ValueError(
            "Bytes 3-4 of the IID are not FF:FE — "
            "this address was not generated via EUI-64."
        )

    mac_bytes    = iid_bytes[:3] + iid_bytes[5:]
    b0           = int(mac_bytes[0], 16) ^ 0x02
    mac_bytes[0] = f"{b0:02X}"
    return ":".join(b.upper() for b in mac_bytes)


# -------------------------------------------------------------
#  1. IPv4 CALCULATOR


def ipv4_calc_logic(raw: str) -> dict:
    """Compute IPv4 subnet details from CIDR input and return structured results."""
    net = _parse_ipv4_network(raw)
    first, last = _ipv4_usable_bounds(net)
    usable = max(net.num_addresses - 2, 0)
    return {
        "input": raw,
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "mask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "prefix": net.prefixlen,
        "total": net.num_addresses,
        "usable": usable,
        "class": _ipv4_class(net.network_address),
        "private": net.is_private,
        "first": first,
        "last": last,
    }

def ipv4_calc() -> None:
    """Prompt for IPv4 input and display subnet calculation results."""
    _banner("IPv4 Subnet Calculator")
    raw = _prompt("IPv4/prefix (e.g. 192.168.1.10/24)")

    try:
        result = ipv4_calc_logic(raw)
    except ValueError as e:
        print(f"{C_ERROR}  ✗ {e}{C_RESET}")
        return

    _field("Network Address", result["network"], C_SUCCESS) 
    _field("Broadcast", result["broadcast"], C_WARN)
    _field("Subnet Mask", result["mask"])
    _field("Wildcard Mask", result["wildcard"])
    _field("CIDR Prefix", f"/{result['prefix']}")
    _field("Total Addresses", result["total"])
    _field("Usable Hosts", result["usable"])
    _field("IP Class", result["class"])
    _field("Private?", "Yes" if result["private"] else "No")

    if result["first"] and result["last"]:
        _field("First Host", result["first"], C_INFO)
        _field("Last Host", result["last"], C_INFO)


# -----------------------------------------------
#  2. IPv6 CALCULATOR


def ipv6_calc_logic(raw: str) -> dict:
    """Compute IPv6 prefix boundaries and metadata without host enumeration."""
    net = ipaddress.ip_network(raw, strict=False)
    if net.version != 6:
        raise ValueError("Not an IPv6 address.")

    first_host = net.network_address
    last_host = net.network_address + (net.num_addresses - 1)

    return {
        "input": raw,
        "network": str(net.network_address),
        "prefix": net.prefixlen,
        "first": str(first_host),
        "last": str(last_host),
        "count_exp": 128 - net.prefixlen,
        "count": net.num_addresses,
        "is_global": net.is_global,
        "is_link_local": net.is_link_local,
        "is_multicast": net.is_multicast,
    }

def ipv6_calc() -> None:
    """Prompt for IPv6 input and display prefix calculation results."""
    _banner("IPv6 Prefix Calculator")
    raw = _prompt("IPv6/prefix (e.g. 2001:db8::1/64)")

    try:
        result = ipv6_calc_logic(raw)
    except ValueError as e:
        print(f"{C_ERROR}  ✗ {e}{C_RESET}")
        return

    _field("Network", result["network"], C_SUCCESS)
    _field("Prefix Length", f"/{result['prefix']}")
    _field("First Host", result["first"], C_INFO)
    _field("Last Host", result["last"], C_INFO)
    _field("Total Addresses", f"2^{result['count_exp']} = {result['count']:,}")
    _field("Is Global Unicast", result["is_global"])
    _field("Is Link-Local", result["is_link_local"])
    _field("Is Multicast", result["is_multicast"])


#--------------------------------------------------------
#  3. VLSM PLANNER


def vlsm_logic(base_raw: str, requirements: list) -> dict:
    """Allocate VLSM subnets from a base network using largest-first strategy."""
    base = _parse_ipv4_network(base_raw)
    sorted_reqs = sorted(requirements, key=lambda x: x[0], reverse=True)

    base_end = base.broadcast_address
    current_ip = base.network_address
    rows = []

    for hosts_needed, label in sorted_reqs:
        required_size = hosts_needed + 2
        bits = max((required_size - 1).bit_length(), 1)
        prefix = 32 - bits

        try:
            subnet = ipaddress.ip_network(f"{current_ip}/{prefix}", strict=False)
        except ValueError:
            return {
                "base": str(base),
                "rows": rows,
                "error": f"Cannot allocate '{label}' — address space exhausted.",
            }

        if subnet.broadcast_address > base_end:
            return {
                "base": str(base),
                "rows": rows,
                "error": f"'{label}' exceeds base network boundary!",
            }

        first, last = _ipv4_usable_bounds(subnet)
        rows.append({
            "label": label,
            "subnet": str(subnet),
            "first": first,
            "last": last,
            "usable": max(subnet.num_addresses - 2, 0),
        })
        current_ip = subnet.broadcast_address + 1

    return {
        "base": str(base),
        "rows": rows,
        "error": None,
    }

def vlsm() -> None:
    """Prompt subnet requirements and display VLSM allocation table."""
    _banner("VLSM Subnet Planner")
    raw = _prompt("Base network (e.g. 192.168.1.0/24  or  10.0.0.0/14)")

    n = _prompt_int("Number of subnets", min_val=1, max_val=50)

    requirements = []
    for i in range(n):
        h    = _prompt_int(f"Hosts needed for subnet {i + 1}")
        name = _prompt(f"Label for subnet {i + 1} (e.g. LAN_A)")
        requirements.append((h, name))

    try:
        result = vlsm_logic(raw, requirements)
    except ValueError as e:
        print(f"{C_ERROR}  ✗ {e}{C_RESET}")
        return

    print(f"\n{C_HEADER}{'─'*60}")
    print(f"  {'Label':<14} {'Network':<20} {'Range':<36} {'Hosts':>6}")
    print(f"{'─'*60}{C_RESET}")

    for row in result["rows"]:
        host_range = "N/A"
        if row["first"] and row["last"]:
            host_range = f"{row['first']} – {row['last']}"
        print(
            f"  {C_SUCCESS}{row['label']:<14}{C_RESET}"
            f"  {C_INFO}{row['subnet']:<20}{C_RESET}"
            f"  {host_range:<36}"
            f"  {C_WARN}{row['usable']:>6}{C_RESET}"
        )

    if result["error"]:
        print(f"{C_ERROR}  ✗ {result['error']}{C_RESET}")

    print(f"{C_HEADER}{'─'*60}{C_RESET}")


# ----------------------------------------------------
#  4. EUI-64  |  MAC <-> IPv6 LINK-LOCAL


def eui64_tool_logic(direction: str, value: str) -> dict:
    """Convert MAC and link-local addresses using EUI-64 logic and return steps."""
    if direction == "1":
        parts = _mac_normalize(value)
        eui64 = parts[:3] + ["FF", "FE"] + parts[3:]
        b0_original = int(eui64[0], 16)
        b0_flipped = b0_original ^ 0x02
        eui64[0] = f"{b0_flipped:02X}"
        groups = [eui64[i] + eui64[i + 1] for i in range(0, 8, 2)]
        iid = ":".join(g.lower() for g in groups)
        result = str(ipaddress.ip_address(f"fe80:0:0:0:{iid}"))

        return {
            "direction": "mac_to_ll",
            "parts": parts,
            "eui64": eui64,
            "b0_original": b0_original,
            "b0_flipped": b0_flipped,
            "iid": iid,
            "result": result,
        }

    if direction == "2":
        mac_result = _link_local_to_mac(value)
        addr = ipaddress.ip_address(value)
        groups = addr.exploded.split(":")
        iid_grps = groups[4:]
        iid_bytes = []
        for g in iid_grps:
            iid_bytes.append(g[0:2])
            iid_bytes.append(g[2:4])
        mac_bytes = iid_bytes[:3] + iid_bytes[5:]
        b0_ll = int(mac_bytes[0], 16)
        b0_mac = b0_ll ^ 0x02

        return {
            "direction": "ll_to_mac",
            "expanded": addr.exploded,
            "iid_groups": iid_grps,
            "iid_bytes": iid_bytes,
            "mac_bytes": mac_bytes,
            "b0_ll": b0_ll,
            "b0_mac": b0_mac,
            "result": mac_result,
        }

    raise ValueError("Invalid choice. Enter 1 or 2.")

def eui64_tool() -> None:
    """Prompt conversion direction and display EUI-64 step-by-step results."""
    _banner("EUI-64  |  MAC <-> IPv6 Link-Local")

    print(f"  {C_INFO}[1]{C_RESET}  MAC  ->  Link-Local address")
    print(f"  {C_INFO}[2]{C_RESET}  Link-Local  ->  MAC address")
    direction = _prompt("Choose direction (1/2)")

    if direction == "1":
        mac = _prompt("MAC address (e.g. 52:74:f2:b1:a8:7f  or  5274.f2b1.a87f)")

        try:
            result = eui64_tool_logic(direction, mac)
        except ValueError as e:
            print(f"{C_ERROR}  ✗ {e}{C_RESET}")
            return

        print(f"\n  {C_HEADER}Step-by-step EUI-64 derivation:{C_RESET}")

        print(f"\n  {C_INFO}Step 1 - Original MAC bytes:{C_RESET}")
        print(f"    {':'.join(result['parts'])}")

        print(f"\n  {C_INFO}Step 2 - Insert FF:FE after byte 3:{C_RESET}")
        print(f"    {':'.join(result['parts'][:3])}:{C_WARN}FF:FE{C_RESET}:{':'.join(result['parts'][3:])}")

        print(f"\n  {C_INFO}Step 3 - Flip U/L bit (bit index 6) of first byte:{C_RESET}")
        print(f"    Before : {result['parts'][0]} = {result['b0_original']:08b}  (bit 6 = {(result['b0_original'] >> 1) & 1})")
        print(f"    XOR 02 :      ^ 00000010")
        print(f"    After  : {result['b0_flipped']:02X} = {result['b0_flipped']:08b}  (bit 6 = {(result['b0_flipped'] >> 1) & 1})")

        print(f"\n  {C_INFO}Step 4 - Group into 4x16-bit chunks:{C_RESET}")
        print(f"    {result['iid']}")

        print(f"\n  {C_INFO}Step 5 - Prepend fe80:: (link-local prefix):{C_RESET}")
        print(f"\n  {C_SUCCESS}  Result: {result['result']}{C_RESET}")

    elif direction == "2":
        ll = _prompt("Link-local address (e.g. fe80::5074:f2ff:feb1:a87f)")

        try:
            result = eui64_tool_logic(direction, ll)
        except ValueError as e:
            print(f"{C_ERROR}  ✗ {e}{C_RESET}")
            return

        print(f"\n  {C_HEADER}Step-by-step reversal:{C_RESET}")

        print(f"\n  {C_INFO}Step 1 - Expanded address:{C_RESET}")
        print(f"    {result['expanded']}")

        print(f"\n  {C_INFO}Step 2 - Extract IID (last 64 bits):{C_RESET}")
        print(f"    {':'.join(result['iid_groups'])}")

        print(f"\n  {C_INFO}Step 3 - Remove FF:FE (bytes 3-4):{C_RESET}")
        print(f"    {':'.join(result['iid_bytes'][:3])} + {C_WARN}[FF:FE]{C_RESET} + {':'.join(result['iid_bytes'][5:])}")

        print(f"\n  {C_INFO}Step 4 - Flip U/L bit back:{C_RESET}")
        print(f"    {result['mac_bytes'][0]} ({result['b0_ll']:08b}) -> {result['b0_mac']:02X} ({result['b0_mac']:08b})")

        print(f"\n  {C_SUCCESS}  Result MAC: {result['result']}{C_RESET}")

    else:
        print(f"{C_ERROR}  ✗ Invalid choice. Enter 1 or 2.{C_RESET}")


# ------------------------------------------
#  5. SUBNET SUMMARY TABLE


def subnet_summary_logic(base_raw: str, target_prefix: int, include_rows: bool = True) -> dict:
    """Generate all child subnets at target prefix with host-range metadata."""
    base = _parse_ipv4_network(base_raw)
    if target_prefix < base.prefixlen:
        raise ValueError(
            f"Target prefix /{target_prefix} is larger than base network /{base.prefixlen}."
        )
    if target_prefix > 32:
        raise ValueError("Target prefix must be /32 or less.")

    subnet_count = 1 << (target_prefix - base.prefixlen) 
    result = {
        "base": str(base),
        "target_prefix": target_prefix,
        "subnet_count": subnet_count,
        "rows": [],
    }

    if not include_rows:
        return result

    for subnet in base.subnets(new_prefix=target_prefix):
        first, last = _ipv4_usable_bounds(subnet)
        result["rows"].append({
            "network": str(subnet.network_address),
            "prefix": subnet.prefixlen,
            "first": first,
            "last": last,
            "broadcast": str(subnet.broadcast_address),
        })
    return result


def subnet_summary() -> None:
    """Prompt subnet carving inputs and display a full child-subnet summary table."""
    _banner("Subnet Summary Table")
    base_raw = _prompt("Base IPv4 network (e.g. 192.168.1.0/24)")

    try:
        base = _parse_ipv4_network(base_raw)
    except ValueError as e:
        print(f"{C_ERROR}  ✗ {e}{C_RESET}")
        return

    target_prefix = _prompt_int(
        "Target prefix length (e.g. 26)",
        min_val=base.prefixlen,
        max_val=32,
    )

    try:
        preview = subnet_summary_logic(base_raw, target_prefix, include_rows=False)
    except ValueError as e:
        print(f"{C_ERROR}  ✗ {e}{C_RESET}")
        return

    _field("Base Network", preview["base"], C_SUCCESS)
    _field("Target Prefix", f"/{preview['target_prefix']}")
    _field("Total Subnets", preview["subnet_count"], C_WARN)

    if preview["subnet_count"] > 512:
        confirm = _prompt("This will print more than 512 rows. Continue? (y/n)").lower()
        if confirm not in ("y", "yes"):
            print(f"{C_WARN}  i Output cancelled by user.{C_RESET}")
            return

    result = subnet_summary_logic(base_raw, target_prefix, include_rows=True)

    print(f"\n{C_HEADER}{'─'*96}")
    print(f"  {'#':<4} {'Subnet':<35} {'First Host':<16} {'Last Host':<16} {'Broadcast':<16}")
    print(f"{'─'*96}{C_RESET}")

    for idx, row in enumerate(result["rows"], start=1):
        first = row["first"] if row["first"] else "N/A"
        last = row["last"] if row["last"] else "N/A"
        print(
            f"  {idx:<4} "
            f"{C_INFO}{row['network']}/{row['prefix']:<20}{C_RESET} "
            f"{first:<16} "
            f"{last:<16} "
            f"{C_WARN}{row['broadcast']:<16}{C_RESET}"
        )
    print(f"{C_HEADER}{'─'*96}{C_RESET}")


#----------------------------
#  MENU


MENU_ITEMS = [
    ("1", "IPv4 Subnet Calculator",      ipv4_calc),
    ("2", "IPv6 Prefix Calculator",      ipv6_calc),
    ("3", "VLSM Subnet Planner",         vlsm),
    ("4", "EUI-64  |  MAC <-> Link-Local", eui64_tool),
    ("5", "Subnet Summary Table",        subnet_summary),
    ("0", "Exit",                        None),
]


def menu() -> None:
    while True:
        print(f"\n{C_HEADER}╔══════════════════════════════════════╗")
        print(  f"║       NetAutoTool (ict_insat)        ║")
        print(  f"║   Network Automation for Engineers   ║")
        print(  f"╚══════════════════════════════════════╝{C_RESET}")

        for key, label, _ in MENU_ITEMS:
            if key == "0":
                print(f"  {C_ERROR}  [{key}]{C_RESET}  {label}")
            else:
                print(f"  {C_INFO}  [{key}]{C_RESET}  {label}")

        choice = input(f"\n{Fore.YELLOW}  Choice: {C_RESET}").strip()

        if choice == "0":
            print(f"\n{C_SUCCESS}  Goodbye. Stay routing!{C_RESET}\n")
            break

        handler = next((fn for k, _, fn in MENU_ITEMS if k == choice), None)

        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                print(f"\n{C_WARN}  <- Cancelled. Returning to menu.{C_RESET}")
        else:
            print(f"{C_ERROR}  ✗ Invalid choice.{C_RESET}")


# -------------------------------
#  ENTRY POINT


if __name__ == "__main__":
    menu()
