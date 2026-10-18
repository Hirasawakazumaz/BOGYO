"""High-resolution Braille world map with attacker→home defense arrows.

Land is defined by coarse continent *polygons* (point-in-polygon), sampled at
Braille sub-cell resolution (2×4 dots per character) so the coastline reads as a
real map rather than Famicom-style blocks. The static land layer is computed once
and cached; each render overlays home/attacker markers and arrows.

Public API is unchanged: ``render_grid(home, attackers) -> list[str]`` plus the
marker/`W`/`H` constants the dashboard imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# character-cell grid size (each cell = 2×4 Braille dots)
W, H = 78, 30
DW, DH = W * 2, H * 4  # dot resolution: 156 × 120

# glyphs
OCEAN = " "
HOME = "◉"
ATK_BLOCKED = "✖"
ATK_ACTIVE = "▲"
ARROW_H, ARROW_V, ARROW_D1, ARROW_D2, ARROW_HEAD = "─", "│", "╲", "╱", "►"
ARROWS = (ARROW_H, ARROW_V, ARROW_D1, ARROW_D2, ARROW_HEAD)

# Braille dot bit for (dx in 0..1, dy in 0..3)
_BRAILLE = {
    (0, 0): 0x01, (0, 1): 0x02, (0, 2): 0x04, (0, 3): 0x40,
    (1, 0): 0x08, (1, 1): 0x10, (1, 2): 0x20, (1, 3): 0x80,
}

# Rough continent polygons as (lon, lat) vertices — recognizable, not cartographic.
_POLYGONS: list[list[tuple[float, float]]] = [
    # North America
    [(-168, 65), (-150, 71), (-120, 71), (-95, 72), (-82, 63), (-64, 60), (-52, 47),
     (-70, 42), (-75, 35), (-81, 25), (-97, 18), (-105, 23), (-115, 30), (-124, 40),
     (-130, 54), (-160, 58)],
    # South America
    [(-81, 8), (-77, 1), (-80, -18), (-70, -55), (-66, -52), (-62, -40), (-58, -34),
     (-48, -25), (-35, -8), (-50, 0), (-60, 6), (-77, 12)],
    # Europe
    [(-10, 43), (-5, 36), (3, 38), (18, 40), (28, 41), (40, 47), (42, 60), (28, 71),
     (10, 64), (-5, 58), (-10, 50)],
    # Africa
    [(-17, 21), (-16, 14), (-10, 5), (8, 4), (9, -1), (13, -6), (12, -17), (18, -35),
     (26, -34), (33, -28), (40, -15), (51, 12), (43, 11), (32, 30), (10, 37), (-6, 36),
     (-17, 28)],
    # Asia
    [(40, 47), (60, 45), (90, 52), (110, 48), (130, 52), (145, 60), (160, 62), (140, 40),
     (122, 30), (120, 22), (108, 10), (103, 1), (95, 6), (80, 8), (77, 22), (68, 24),
     (58, 25), (48, 30), (44, 38)],
    # Australia
    [(114, -22), (130, -12), (142, -11), (153, -25), (150, -38), (138, -35), (129, -32),
     (118, -34), (113, -26)],
    # Greenland
    [(-45, 60), (-20, 60), (-18, 72), (-30, 82), (-50, 80), (-55, 68)],
    # British Isles
    [(-6, 50), (-1, 50), (1, 53), (-3, 59), (-8, 56)],
    # Japan
    [(130, 31), (140, 35), (143, 44), (139, 37), (131, 33)],
    # Indonesia / SE-Asia islands
    [(95, 6), (103, -3), (120, -9), (141, -8), (141, -1), (120, 3), (100, 4)],
    # Madagascar
    [(43, -13), (50, -16), (49, -25), (44, -22)],
    # New Zealand
    [(166, -41), (175, -37), (178, -46), (168, -47)],
]


@dataclass(frozen=True)
class Marker:
    lat: float
    lon: float
    blocked: bool = True
    label: str = ""


def _point_in_poly(lon: float, lat: float, poly: list[tuple[float, float]]) -> bool:
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if ((yi > lat) != (yj > lat)) and (
            lon < (xj - xi) * (lat - yi) / ((yj - yi) or 1e-9) + xi
        ):
            inside = not inside
        j = i
    return inside


def _is_land(lon: float, lat: float) -> bool:
    return any(_point_in_poly(lon, lat, p) for p in _POLYGONS)


_BASE_CELLS: Optional[list[list[str]]] = None


def _base_cells() -> list[list[str]]:
    """Braille land layer, computed once and cached."""
    global _BASE_CELLS
    if _BASE_CELLS is not None:
        return [row[:] for row in _BASE_CELLS]
    # land bitmap at dot resolution
    land = [[False] * DW for _ in range(DH)]
    for dy in range(DH):
        lat = 90.0 - (dy / (DH - 1)) * 180.0
        for dx in range(DW):
            lon = -180.0 + (dx / (DW - 1)) * 360.0
            if _is_land(lon, lat):
                land[dy][dx] = True
    cells = [[OCEAN] * W for _ in range(H)]
    for cy in range(H):
        for cx in range(W):
            bits = 0
            for (ddx, ddy), bit in _BRAILLE.items():
                if land[cy * 4 + ddy][cx * 2 + ddx]:
                    bits |= bit
            cells[cy][cx] = chr(0x2800 + bits) if bits else OCEAN
    _BASE_CELLS = cells
    return [row[:] for row in cells]


def project(lat: float, lon: float) -> tuple[int, int]:
    x = int(round((lon + 180.0) / 360.0 * (W - 1)))
    y = int(round((90.0 - lat) / 180.0 * (H - 1)))
    return max(0, min(W - 1, x)), max(0, min(H - 1, y))


def is_braille(ch: str) -> bool:
    return len(ch) == 1 and 0x2800 <= ord(ch) <= 0x28FF


def _draw_arrow(grid: list[list[str]], x0: int, y0: int, x1: int, y1: int) -> None:
    dx, dy = abs(x1 - x0), abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx - dy
    ch = ARROW_H if dx > dy else ARROW_V if dy > dx else (ARROW_D1 if sx == sy else ARROW_D2)
    x, y = x0, y0
    first = True
    while (x, y) != (x1, y1):
        if not first:
            # draw over ocean or land, but never over an existing marker
            cur = grid[y][x]
            if cur == OCEAN or is_braille(cur):
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
    grid = _base_cells()
    hx = hy = None
    if home is not None:
        hx, hy = project(home[0], home[1])
    for mk in attackers:
        ax, ay = project(mk.lat, mk.lon)
        if hx is not None and (ax, ay) != (hx, hy):
            _draw_arrow(grid, ax, ay, hx, hy)
    for mk in attackers:
        ax, ay = project(mk.lat, mk.lon)
        grid[ay][ax] = ATK_BLOCKED if mk.blocked else ATK_ACTIVE
    if hx is not None:
        grid[hy][hx] = HOME
    return ["".join(row) for row in grid]
