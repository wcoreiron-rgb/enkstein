"""The sidebar must open as three workspace modes, not the full module list.

These are source-level contracts rather than rendering tests: they pin the
structural decisions that are easy to regress silently, and the Playwright
specs cover the interactive behaviour.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIDEBAR = (ROOT / "frontend" / "src" / "components" / "Sidebar.tsx").read_text(encoding="utf-8")

TOP_LEVEL = ("Chat", "Cowork", "Security")


def test_exactly_three_top_level_categories():
    for label in TOP_LEVEL:
        assert f"label: '{label}'" in SIDEBAR, f"missing top-level category: {label}"
    start = SIDEBAR.index("const SIDEBAR_CATEGORIES")
    block = SIDEBAR[start:SIDEBAR.index("];", start)]
    assert block.count("label:") == len(TOP_LEVEL)


def test_security_groups_start_closed():
    """Security opens to disclosure headers; Arms and nodes stay hidden."""
    assert "defaultOpen: true" not in SIDEBAR


def test_categories_start_closed_and_open_one_at_a_time():
    assert "useState<SidebarCategory['id'] | null>(null)" in SIDEBAR
    # Expanded state is a single id rather than a set, so opening one category
    # cannot leave the previous one expanded underneath it.
    assert "const expanded = openCategory === category.id" in SIDEBAR


def test_disclosure_state_is_persisted_locally():
    assert "enkstein-nav-category" in SIDEBAR
    assert "enkstein-nav-open-groups" in SIDEBAR


def test_active_route_forces_its_group_open():
    """Deep-linking to a nested page must not hide the selected item."""
    assert "if (hasActive) setOpen(true);" in SIDEBAR


def test_security_children_are_not_reachable_from_chat_or_cowork():
    """Chat and Cowork render only the workspace nav; Arms stay under Security."""
    assert "{category.id === 'security' && NAV_GROUPS.map" in SIDEBAR
    assert "(category.id === 'chat' || category.id === 'cowork') && (" in SIDEBAR


def test_chat_and_cowork_keep_separate_project_storage():
    assert "CHAT_PROJECT_STORAGE_KEY = 'marcellus-chat-project'" in SIDEBAR
    assert "COWORK_PROJECT_STORAGE_KEY = 'marcellus-cowork-project'" in SIDEBAR
    # The key is chosen from the rendered mode, so a Chat selection can never
    # be written into Cowork's remembered project.
    assert "mode === 'chat' ? CHAT_PROJECT_STORAGE_KEY : COWORK_PROJECT_STORAGE_KEY" in SIDEBAR


def test_project_and_conversation_names_render_per_mode():
    assert "{project.name}" in SIDEBAR
    assert "{conversation.title}" in SIDEBAR
    # Each mode fetches its own kind, so a Chat folder never lists in Cowork.
    assert "getCortexProjects(mode)" in SIDEBAR
    assert "getCortexConversations(mode" in SIDEBAR


def test_brain_connections_stays_under_security():
    assert "{ label: 'Brain Connections',href: '/marcellus/brains'" in SIDEBAR
