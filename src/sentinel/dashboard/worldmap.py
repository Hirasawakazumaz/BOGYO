"""ASCII world map with attacker -> home defense arrows (CASIO-watch vibe).

Equirectangular projection onto a fixed character grid. Continents are filled
from coarse bounding boxes (deterministic, testable — accuracy is cosmetic). A
home marker sits at your country's centroid; each attacker country gets a marker
and an arrow drawn toward home. Blocked attackers render differently from active
ones so a glance says "the world's hacking is being stopped".

This module returns a plain character grid and per-cell *style tags*; the Textual
app colors it. No colors or I/O here, so it is trivially unit-tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

W, H = 66, 19

# Coarse continent boxes: (lat_max, lat_min, lon_min, lon_max).
_CONTINENTS = [
    (72, 15, -168, -52),    # North America
    (15, 7, -92, -77),      # Central America
    (12, -55, -81, -35),    # South America
    (71, 36, -10, 40),      # Europe
    (37, -35, -17, 51),     # Africa
    (75, 5, 40, 150),       # Asia
    (6, -10, 95, 141),      # SE Asia / Indonesia
    (-11, -39, 113, 154),   # Australia
]

# cell glyphs
OCEAN, LAND = " ", "."
HOME = "@"
ATK_BLOCKED, ATK_ACTIVE = "x", "!"
ARROW_CHARS = {"h": "-", "v": "|", "d1": "\\", "d2": "/"}


@dataclass(frozen=True)
class Marker:
    lat: float
    lon: float
    blocked: bool = True
    label: str = ""


def project(lat: float, lon: float) -> tuple[int, int]:
    x = int(round((lon + 180.0) / 360.0 * (W - 1)))
    y = int(round((90.0 - lat) / 180.0 * (H - 1)))
    return max(0, min(W - 1, x)), max(0, min(H - 1, y))


def _blank_land_grid() -> list[list[str]]:
    grid = [[OCEAN] * W for _ in range(H)]
    for y in range(H):
        lat = 90.0 - (y / (H - 1)) * 180.0
        for x in range(W):
            lon = (x / (W - 1)) * 360.0 - 180.0
            for latmax, latmin, lonmin, lonmax in _CONTINENTS:
                if latmin <= lat <= latmax and lonmin <= lon <= lonmax:
                    grid[y][x] = LAND
                    break
    return grid


def _draw_arrow(grid: list[list[str]], x0: int, y0: int, x1: int, y1: int) -> None:
    """Bresenham line from (x0,y0) to (x1,y1), endpoints excluded."""
    dx, dy = abs(x1 - x0), abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx - dy
    if dx > dy:
        ch = ARROW_CHARS["h"]
    elif dy > dx:
        ch = ARROW_CHARS["v"]
    else:
        ch = ARROW_CHARS["d1"] if sx == sy else ARROW_CHARS["d2"]
    x, y = x0, y0
    first = True
    while True:
        if (x, y) == (x1, y1):
            break
        if not first and grid[y][x] in (OCEAN, LAND):
            grid[y][x] = ch
        first = False
        e2 = 2 * err
        if e2 > -dy:
            err -= dy
            x += sx
        if e2 < dx:
            err += dx
            y += sy


def render_grid(home: Optional[tuple[float, float]], attackers: list[Marker]) -> list[str]:
    """Return the map as a list of H strings of width W."""
    grid = _blank_land_grid()
    hx = hy = None
    if home is not None:
        hx, hy = project(home[0], home[1])
    for mk in attackers:
        ax, ay = project(mk.lat, mk.lon)
        if hx is not None:
            _draw_arrow(grid, ax, ay, hx, hy)
    # markers on top of arrows
    for mk in attackers:
        ax, ay = project(mk.lat, mk.lon)
        grid[ay][ax] = ATK_BLOCKED if mk.blocked else ATK_ACTIVE
    if hx is not None:
        grid[hy][hx] = HOME
    return ["".join(row) for row in grid]
