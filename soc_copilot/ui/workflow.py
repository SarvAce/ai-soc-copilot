"""Drawing the compiled workflow as a graph, for the Architecture page (§14.2).

The picture is read from the compiled ``StateGraph`` itself, through LangGraph's
own ``get_graph()``, so it cannot drift from the graph the case actually ran: a
node or an edge added in ``graph/build.py`` appears here without this file
changing. What is overlaid on it comes from the run — which nodes executed, how
often, and which of the Table 25 routes were taken.

The output is a DOT string, which ``st.graphviz_chart`` renders on its own. No
new dependency: Streamlit ships the renderer, and nothing here imports graphviz.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from soc_copilot.graph.build import EVIDENCE_ROUTES, REPORT_ROUTES
from soc_copilot.ui.chain import Step
from soc_copilot.ui.components import role_of

START, END = "__start__", "__end__"
PENDING_LINE = "#1e40af"

# The decision each conditional edge carries, in Table 25's own words. This is
# presentation only — ``graph/build.py`` remains the one implementation of the
# routing — and ``tests/test_architecture.py`` pins it against the compiled
# graph's conditional edges, so a new route cannot go unlabelled.
ROUTE_LABELS: dict[tuple[str, str], tuple[str, ...]] = {
    ("evidence_gate", "planner"): ("re-plan",),
    ("evidence_gate", "reporter"): ("pass", "unresolved"),
    ("report_gate", "reporter"): ("redraft", "template"),
    ("report_gate", "analyst_review"): ("pass", "flagged"),
}

# The three loops of Table 25, which the page marks when a run takes them.
LOOP_EDGES = {
    "re-plan": ("evidence_gate", "planner"),
    "redraft": ("report_gate", "reporter"),
    "template": ("report_gate", "reporter"),
}

RAN_FILL, RAN_LINE = "#dcfce7", "#166534"
IDLE_FILL, IDLE_LINE = "#f8fafc", "#cbd5e1"
LOOP_LINE = "#b45309"
# One muted text colour for everything a run did not touch. It has to stay
# legible both inside a near-white node box and on the page background, which
# is dark in Streamlit's default theme, so it sits midway between the two.
IDLE_TEXT = "#64748b"


def edges_of(graph: Any) -> list[tuple[str, str, bool]]:
    """Every edge of the compiled graph, as (from, to, is_conditional)."""
    return sorted({(edge.source, edge.target, bool(edge.conditional))
                   for edge in graph.get_graph().edges})


def nodes_of(graph: Any) -> list[str]:
    """Every node of the compiled graph, START and END included."""
    return list(graph.get_graph().nodes)


def executions(chain: list[Step]) -> Counter:
    """How many times each node completed in this run (spec §14.5)."""
    return Counter(step.node for step in chain)


def edges_taken(chain: list[Step]) -> Counter:
    """Which edges the run actually walked, and how often.

    Read off consecutive node executions rather than from the ``next`` channel,
    so the drawing shows what happened rather than what was intended.
    """
    walked: Counter = Counter()
    if not chain:
        return walked
    walked[(START, chain[0].node)] += 1
    for step, following in zip(chain, chain[1:]):
        walked[(step.node, following.node)] += 1
    if chain[-1].node == "finalize":
        walked[("finalize", END)] += 1
    return walked


def pending_edge(chain: list[Step]) -> tuple[str, str] | None:
    """The edge the graph is sitting on, when it stopped at a gate's route.

    A run paused at the analyst interrupt has had its route decided but not yet
    walked, so the edge is neither taken nor untaken. Naming it is what shows
    where the thread is waiting.
    """
    if not chain or not chain[-1].route:
        return None
    last = chain[-1]
    routes = EVIDENCE_ROUTES if last.node == "evidence_gate" else REPORT_ROUTES
    target = routes.get(last.route)
    return (last.node, target) if target else None


def decisions_on(chain: list[Step]) -> dict[tuple[str, str], Counter]:
    """The gate decisions that carried each edge, so a label says what happened."""
    taken: dict[tuple[str, str], Counter] = {}
    for step, following in zip(chain, chain[1:]):
        if step.node not in ("evidence_gate", "report_gate"):
            continue
        taken.setdefault((step.node, following.node), Counter())[step.decision] += 1
    return taken


def _node_line(name: str, ran: int) -> str:
    """One DOT node, filled when it ran and labelled with its execution count."""
    # The role names carry a middle dot; DOT takes a line break there instead,
    # so a two-word node stays inside its box.
    label = role_of(name).replace(" · ", "\\n")
    if name in (START, END):
        colour = RAN_LINE if ran else IDLE_LINE
        return (f'  "{name}" [label="{label}" shape=circle width=0.45 '
                f'fixedsize=true fontsize=8 style=filled fillcolor="white" '
                f'color="{colour}"];')
    if ran:
        suffix = f"\\n×{ran}" if ran > 1 else ""
        return (f'  "{name}" [label="{label}{suffix}" fillcolor="{RAN_FILL}" '
                f'color="{RAN_LINE}" penwidth=2];')
    return (f'  "{name}" [label="{label}" fillcolor="{IDLE_FILL}" '
            f'color="{IDLE_LINE}" style="rounded,filled,dashed" '
            f'fontcolor="{IDLE_TEXT}"];')


def _edge_label(pair: tuple[str, str], chosen: Counter | None) -> str:
    """What to write beside an edge: the decisions taken, or the ones available."""
    if chosen:
        return " / ".join(f"{name} ×{count}" if count > 1 else name
                          for name, count in sorted(chosen.items()))
    return " / ".join(ROUTE_LABELS.get(pair, ()))


def _edge_line(source: str, target: str, conditional: bool, count: int,
               chosen: Counter | None, pending: bool = False) -> str:
    """One DOT edge, bold when the run walked it."""
    pair = (source, target)
    label = _edge_label(pair, chosen)
    is_loop = pair in LOOP_EDGES.values()
    if count:
        colour = LOOP_LINE if is_loop else RAN_LINE
        attributes = [f'color="{colour}"', "penwidth=2", f'fontcolor="{colour}"']
    elif pending:
        attributes = [f'color="{PENDING_LINE}"', "penwidth=2",
                      f'fontcolor="{PENDING_LINE}"']
        label = f"{label} — waiting here" if label else "waiting here"
    else:
        attributes = [f'color="{IDLE_LINE}"', f'fontcolor="{IDLE_TEXT}"']
    if conditional:
        # A dashed conditional edge is one this run never chose; the pending
        # edge is dashed too, because the route is decided but not yet walked.
        attributes.append("style=solid" if count else "style=dashed")
    if label:
        attributes.append(f'label=" {label} "')
    return f'  "{source}" -> "{target}" [{" ".join(attributes)}];'


def workflow_dot(graph: Any, chain: list[Step]) -> str:
    """The DOT source for one case's workflow, with the run overlaid on it."""
    ran = executions(chain)
    walked = edges_taken(chain)
    chosen = decisions_on(chain)
    # START and END append no audit entry, so they are marked from the ends of
    # the chain instead: the graph was entered, and it reached END if it closed.
    if chain:
        ran[START] = 1
    if chain and chain[-1].node == "finalize":
        ran[END] = 1
    lines = [
        "digraph workflow {",
        '  rankdir=TB; bgcolor="transparent"; nodesep=0.35; ranksep=0.45;',
        '  node [shape=box style="rounded,filled" fontname="Helvetica" '
        'fontsize=10 margin="0.16,0.09"];',
        '  edge [fontname="Helvetica" fontsize=9 arrowsize=0.7];',
    ]
    waiting = pending_edge(chain)
    if waiting:
        # The gate's own decision is a better label than the list of routes it
        # could have taken, so the paused edge says what was actually decided.
        chosen.setdefault(waiting, Counter())[chain[-1].decision] += 1
    lines += [_node_line(name, ran.get(name, 0)) for name in nodes_of(graph)]
    for source, target, conditional in edges_of(graph):
        lines.append(_edge_line(source, target, conditional,
                                walked.get((source, target), 0),
                                chosen.get((source, target)),
                                pending=waiting == (source, target)))
    lines.append("}")
    return "\n".join(lines)
