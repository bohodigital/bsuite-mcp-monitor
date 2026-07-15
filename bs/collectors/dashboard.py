from __future__ import annotations

from typing import Any

from bs.config import MonitorConfig
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT
from bs.collectors.mcp import collect_mcp
from bs.collectors.network_detail import collect_network_detail
from bs.collectors.ssh import collect_ssh
from bs.collectors.status import collect_status


def collect_dashboard(
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
    monitor_config: MonitorConfig | None = None,
    monitor_config_source: str | None = None,
) -> dict[str, Any]:
    mcp_kwargs: dict[str, Any] = {
        "lines": 40,
        "resolve": resolve,
        "geo": geo,
        "geo_db": geo_db,
        "lookup_limit": lookup_limit,
    }
    if monitor_config is not None:
        mcp_kwargs["config"] = monitor_config
        mcp_kwargs["config_source"] = monitor_config_source
    return {
        "status": collect_status(),
        "network": collect_network_detail(resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit),
        "ssh": collect_ssh(
            include_history=False,
            lines=12,
            attack_hours=1,
            resolve=resolve,
            geo=geo,
            geo_db=geo_db,
            lookup_limit=lookup_limit,
        ),
        "mcp": collect_mcp(**mcp_kwargs),
    }
