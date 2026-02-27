"""Sphinx configuration for PromptGuard documentation."""

import os
import sys

# Make the package importable without installing it
sys.path.insert(0, os.path.abspath(".."))

# ── Project information ────────────────────────────────────────────────────────

project = "PromptGuard"
copyright = "2024, Hasanain Ghafoor"
author = "Hasanain Ghafoor"
release = "0.1.0"
version = "0.1.0"

# ── Extensions ─────────────────────────────────────────────────────────────────

extensions = [
    "sphinx.ext.autodoc",        # Auto-generate docs from docstrings
    "sphinx.ext.napoleon",       # Google / NumPy style docstrings
    "sphinx.ext.viewcode",       # [source] links on API pages
    "sphinx.ext.intersphinx",    # Cross-link to Python standard library
    "sphinx_copybutton",         # Copy button on code blocks
    "sphinx_autodoc_typehints",  # Render type hints in API docs
    "sphinx_design",             # Grid cards on the landing page
    "myst_parser",               # Markdown support
]

# ── Paths ──────────────────────────────────────────────────────────────────────

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
html_static_path = ["_static"]

# ── Theme ──────────────────────────────────────────────────────────────────────

html_theme = "furo"

html_theme_options = {
    "sidebar_hide_name": False,
    "light_css_variables": {
        "color-brand-primary": "#2563eb",
        "color-brand-content": "#2563eb",
        "color-admonition-background": "rgba(37, 99, 235, 0.05)",
    },
    "dark_css_variables": {
        "color-brand-primary": "#60a5fa",
        "color-brand-content": "#60a5fa",
    },
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/Hgaffa/promptguard",
            "html": (
                '<svg stroke="currentColor" fill="currentColor" stroke-width="0" '
                'viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 '
                "3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37"
                "-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 "
                "1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64"
                "-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 "
                "2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82"
                ".44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95"
                ".29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013"
                ' 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path></svg>'
            ),
            "class": "",
        }
    ],
}

html_title = "PromptGuard"
html_css_files = ["custom.css"]

# ── intersphinx ────────────────────────────────────────────────────────────────

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# ── autodoc ────────────────────────────────────────────────────────────────────

# Mock heavy dependencies so autodoc can import the package without installing
# PyTorch, Transformers, etc.
autodoc_mock_imports = [
    "torch",
    "transformers",
    "vaderSentiment",
    "spacy",
    "tqdm",
    "numpy",
    "pydantic",
]

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "exclude-members": "__weakref__",
}

autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"
always_document_param_types = False

# ── napoleon ───────────────────────────────────────────────────────────────────

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = False
napoleon_use_rtype = False        # Types shown inline via typehints
napoleon_preprocess_types = True

# ── copybutton ─────────────────────────────────────────────────────────────────

copybutton_prompt_text = r">>> |\.\.\. |\$ "
copybutton_prompt_is_regexp = True

# ── MyST parser ────────────────────────────────────────────────────────────────

myst_enable_extensions = ["colon_fence", "deflist"]
