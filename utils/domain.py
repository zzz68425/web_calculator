"""Domain naming rules shared by the scan workflow."""


def extract_root_domain(domain: str) -> str:
    """Apply the existing three-label .edu.tw or two-label fallback rule."""
    parts = domain.lower().split(".")
    if len(parts) >= 3 and parts[-2] == "edu" and parts[-1] == "tw":
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def infer_storage_root(domain: str, area_domains: set[str]) -> str:
    """Keep area domains and their direct school children as storage roots."""
    domain = domain.strip().lower().rstrip(".")
    root = extract_root_domain(domain)
    if root in area_domains:
        parts = domain.split(".")
        root_parts = root.split(".")
        if len(parts) > len(root_parts):
            return ".".join(parts[-(len(root_parts) + 1):])
        return root
    return root
