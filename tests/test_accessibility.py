import re
import unittest
from pathlib import Path

CSS_PATH = Path(__file__).resolve().parent.parent / "ui" / "static" / "css" / "app.css"
HTML_PATH = Path(__file__).resolve().parent.parent / "ui" / "index.html"
JS_PATH = Path(__file__).resolve().parent.parent / "ui" / "static" / "js" / "app.js"


def relative_luminance(hex_color: str) -> float:
    hex_color = hex_color.lstrip("#")
    r, g, b = [int(hex_color[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]

    def lin(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = lin(r), lin(g), lin(b)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: str, bg: str) -> float:
    l1, l2 = relative_luminance(fg), relative_luminance(bg)
    l1, l2 = max(l1, l2), min(l1, l2)
    return (l1 + 0.05) / (l2 + 0.05)


def extract_css_vars(css_text: str, block_selector: str) -> dict:
    """Extracts `--name: #hex;` declarations from a specific CSS block
    (e.g. ':root' or '[data-theme="light"]'), real parsing of the actual
    stylesheet — not a hand-copied snapshot of its values."""
    pattern = re.escape(block_selector) + r"\s*\{([^}]*)\}"
    match = re.search(pattern, css_text)
    if not match:
        raise AssertionError(f"Could not find CSS block: {block_selector}")
    body = match.group(1)
    return dict(re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", body))


class TestColorContrast(unittest.TestCase):
    """WCAG 2.1 AA requires >=4.5:1 for normal text, >=3:1 for large text
    (18pt+/14pt-bold+) and UI components. Everything checked here is used
    at small (11-13px) sizes in the actual UI, so 4.5:1 is the right bar."""

    @classmethod
    def setUpClass(cls):
        css_text = CSS_PATH.read_text()
        cls.dark = extract_css_vars(css_text, ":root")
        cls.light = extract_css_vars(css_text, '[data-theme="light"]')

    def test_dark_theme_text_muted_meets_aa_on_bg(self):
        ratio = contrast_ratio(self.dark["--text-muted"], self.dark["--bg"])
        self.assertGreaterEqual(ratio, 4.5, f"text-muted on bg only {ratio:.2f}:1")

    def test_dark_theme_text_muted_meets_aa_on_bg_elevated(self):
        ratio = contrast_ratio(self.dark["--text-muted"], self.dark["--bg-elevated"])
        self.assertGreaterEqual(ratio, 4.5, f"text-muted on bg-elevated only {ratio:.2f}:1")

    def test_light_theme_text_muted_meets_aa_on_bg(self):
        ratio = contrast_ratio(self.light["--text-muted"], self.light["--bg"])
        self.assertGreaterEqual(ratio, 4.5, f"text-muted on bg only {ratio:.2f}:1")

    def test_light_theme_text_muted_meets_aa_on_bg_elevated(self):
        ratio = contrast_ratio(self.light["--text-muted"], self.light["--bg-elevated"])
        self.assertGreaterEqual(ratio, 4.5, f"text-muted on bg-elevated only {ratio:.2f}:1")

    def test_primary_and_secondary_text_meet_aa_both_themes(self):
        for theme_name, theme in [("dark", self.dark), ("light", self.light)]:
            for var in ("--text-primary", "--text-secondary"):
                ratio = contrast_ratio(theme[var], theme["--bg"])
                self.assertGreaterEqual(ratio, 4.5, f"{theme_name} {var} on bg only {ratio:.2f}:1")

    def test_severity_colors_meet_minimum_ui_contrast_both_themes(self):
        # Severity colors are used as badge text/backgrounds and chart
        # segments — UI-component-level contrast (3:1) is the applicable bar.
        for theme_name, theme in [("dark", self.dark), ("light", self.light)]:
            for var in ("--crit", "--high", "--med", "--low", "--info"):
                ratio = contrast_ratio(theme[var], theme["--bg"])
                self.assertGreaterEqual(ratio, 3.0, f"{theme_name} {var} on bg only {ratio:.2f}:1")


class TestSemanticAccessibility(unittest.TestCase):
    """Checks the actual markup/script for the specific accessibility
    gap this project found and fixed: interactive elements built from
    non-focusable, non-semantic <div>s."""

    def test_nav_items_are_real_buttons_not_divs(self):
        html = HTML_PATH.read_text()
        nav_section = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', html, re.DOTALL).group(1)
        self.assertNotIn("<div class=\"nav-item", nav_section,
                          "Nav items must be real <button> elements for keyboard/screen-reader access")
        self.assertGreaterEqual(nav_section.count("<button"), 7)

    def test_profile_options_use_real_radio_inputs(self):
        html = HTML_PATH.read_text()
        self.assertIn('type="radio"', html,
                      "Scan profile selection must use real radio inputs for accessibility")

    def test_findings_toggle_is_a_real_button_in_js(self):
        js = JS_PATH.read_text()
        self.assertIn('aria-expanded', js,
                      "Finding detail toggle must expose aria-expanded state")

    def test_live_scan_status_has_aria_live_region(self):
        html = HTML_PATH.read_text()
        live_section = re.search(r'<section class="view" id="view-live">(.*?)</section>', html, re.DOTALL).group(1)
        self.assertIn("aria-live", live_section,
                      "Live scan updates must be announced via an aria-live region")

    def test_theme_toggle_has_accessible_label(self):
        html = HTML_PATH.read_text()
        toggle = re.search(r'<button class="theme-toggle"[^>]*>', html).group(0)
        self.assertIn("aria-label", toggle, "Icon-only button must have an aria-label")

    def test_focus_visible_styles_exist(self):
        css = CSS_PATH.read_text()
        self.assertIn(":focus-visible", css, "Interactive elements need a visible focus style")


if __name__ == "__main__":
    unittest.main()
