#!/usr/bin/env python3
"""Générateur du dashboard SOC UEBA v4 — « SOC Operations Console » (Kibana 8.19).

Console SOC orientée triage (pyramide inversée) :
  1. Bandeau d'en-tête (contexte, légende)
  2. Ligne de KPI exécutifs (entités à risque, CRITIQUES, MTTD, anomalies)
  3. FILE DE TRIAGE prioritaire : Top entités à risque (user×jour) avec niveau
     d'alerte + action recommandée + votes forts — la pièce maîtresse
  4. Contexte temporel : timeline + heatmap
  5. Analytique : distribution des niveaux, MITRE ATT&CK, top utilisateurs
  6. Détail : alertes corrélées + MTTD par utilisateur
  + Filtres interactifs (control group) : niveau d'alerte, utilisateur

Auto-suffisant (data views inclus). Champs RÉELS uniquement.
"""

import json

KBN = "8.19.0"
DV_ANOM = "ueba-anomalies-dv"
DV_ALERT = "ueba-alerts-dv"
DV_MTTD = "ueba-mttd-dv"
DV_ENTITY = "ueba-entity-alerts-dv"
USERS = ["a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"]
KQL_USERS = "ueba.user.keyword : (" + " or ".join(f'"{u}"' for u in USERS) + ")"
KQL_CRIT = KQL_USERS + ' and risk_level.keyword : "CRITIQUE"'

objs = []


# ───────────────────────── helpers colonnes Lens ─────────────────────────
def c_count(label="Nombre d'anomalies"):
    return {
        "label": label,
        "dataType": "number",
        "operationType": "count",
        "sourceField": "___records___",
        "isBucketed": False,
        "scale": "ratio",
        "params": {"emptyAsNull": False},
    }


def c_date(field="@timestamp", interval="auto", label=None):
    return {
        "label": label or field,
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": field,
        "isBucketed": True,
        "scale": "interval",
        "params": {"interval": interval, "includeEmptyRows": True, "dropPartials": False},
    }


def c_terms(field, size, order_col, label=None, direction="desc"):
    return {
        "label": label or f"Top {size} {field}",
        "dataType": "string",
        "operationType": "terms",
        "sourceField": field,
        "isBucketed": True,
        "scale": "ordinal",
        "params": {
            "size": size,
            "orderBy": {"type": "column", "columnId": order_col},
            "orderDirection": direction,
            "otherBucket": False,
            "missingBucket": False,
            "parentFormat": {"id": "terms"},
        },
    }


def c_metric(op, field, label=None, data_type="number", fmt=None):
    col = {
        "label": label or f"{op} {field}",
        "dataType": data_type,
        "operationType": op,
        "sourceField": field,
        "isBucketed": False,
        "scale": "ratio",
        "params": {"emptyAsNull": False},
    }
    if fmt:
        col["params"]["format"] = fmt
    return col


# ───────────────────────── helper objet Lens ─────────────────────────
def lens(
    obj_id,
    title,
    viz_type,
    layer_id,
    columns,
    column_order,
    visualization,
    dv_id,
    query_kql=None,
    description="",
):
    state = {
        "visualization": visualization,
        "query": {"language": "kuery", "query": query_kql or ""},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": columns,
                        "columnOrder": column_order,
                        "incompleteColumns": {},
                        "sampling": 1,
                    }
                }
            }
        },
        "internalReferences": [],
        "adHocDataViews": {},
    }
    return {
        "id": obj_id,
        "type": "lens",
        "managed": False,
        "coreMigrationVersion": KBN,
        "typeMigrationVersion": "8.9.0",
        "attributes": {
            "title": title,
            "description": description,
            "visualizationType": viz_type,
            "state": state,
        },
        "references": [
            {
                "type": "index-pattern",
                "id": dv_id,
                "name": f"indexpattern-datasource-layer-{layer_id}",
            }
        ],
    }


def index_pattern(dv_id, title, name):
    return {
        "id": dv_id,
        "type": "index-pattern",
        "managed": False,
        "coreMigrationVersion": KBN,
        "typeMigrationVersion": "8.0.0",
        "attributes": {"title": title, "name": name, "timeFieldName": "@timestamp"},
        "references": [],
    }


def xy(layer_id, accessor, x_acc, series_type, split=None, legend=True, value_labels="hide"):
    layer = {
        "layerId": layer_id,
        "accessors": [accessor],
        "position": "top",
        "seriesType": series_type,
        "showGridlines": False,
        "layerType": "data",
        "xAccessor": x_acc,
    }
    if split:
        layer["splitAccessor"] = split
    return {
        "legend": {"isVisible": legend, "position": "right"},
        "valueLabels": value_labels,
        "fittingFunction": "None",
        "axisTitlesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "preferredSeriesType": series_type,
        "layers": [layer],
    }


def metric_viz(layer_id, acc, color, subtitle):
    return {
        "layerId": layer_id,
        "layerType": "data",
        "metricAccessor": acc,
        "color": color,
        "subtitle": subtitle,
        "showBar": False,
    }


# ───────────────────────── data views ─────────────────────────
objs.append(index_pattern(DV_ANOM, "ueba-anomalies-*", "UEBA Anomalies"))
objs.append(index_pattern(DV_ALERT, "ueba-alerts", "UEBA Alerts"))
objs.append(index_pattern(DV_MTTD, "ueba-mttd", "UEBA MTTD"))
objs.append(index_pattern(DV_ENTITY, "ueba-entity-alerts", "UEBA Entity Alerts"))

fmt1 = {"id": "number", "params": {"decimals": 1}}

# ── 1. Timeline (area empilée) ──
objs.append(
    lens(
        "ueba-v3-timeline",
        "Timeline des anomalies comportementales",
        "lnsXY",
        "l1",
        {
            "x": c_date(label="Date"),
            "s": c_terms("ueba.user.keyword", 7, "y", "Utilisateur"),
            "y": c_count(),
        },
        ["x", "s", "y"],
        xy("l1", "y", "x", "area_stacked", split="s"),
        DV_ANOM,
        KQL_USERS,
        "Évolution temporelle des fenêtres anormales (T1110.003).",
    )
)

# ── 2. KPI Total anomalies (rouge) ──
objs.append(
    lens(
        "ueba-v3-kpi-anomalies",
        "Total anomalies détectées",
        "lnsMetric",
        "l2",
        {"m": c_count("Total anomalies")},
        ["m"],
        metric_viz("l2", "m", "#da1e28", "Fenêtres anormales (7 utilisateurs)"),
        DV_ANOM,
        KQL_USERS,
    )
)

# ── 3. KPI Alertes critiques (orange) ──
objs.append(
    lens(
        "ueba-v3-kpi-alerts",
        "Alertes critiques (recall 100%)",
        "lnsMetric",
        "l3",
        {"m": c_count("Alertes")},
        ["m"],
        metric_viz("l3", "m", "#ff832b", "Alertes corrélées — recall 14/14"),
        DV_ALERT,
    )
)

# ── 4. Donut MITRE ATT&CK ──
objs.append(
    lens(
        "ueba-v3-mitre",
        "Techniques MITRE ATT&CK détectées",
        "lnsPie",
        "l4",
        {"g": c_terms("mitre_technique.keyword", 5, "m", "Technique MITRE"), "m": c_count()},
        ["g", "m"],
        {
            "shape": "donut",
            "layers": [
                {
                    "layerId": "l4",
                    "primaryGroups": ["g"],
                    "metrics": ["m"],
                    "numberDisplay": "value",
                    "categoryDisplay": "default",
                    "legendDisplay": "show",
                    "legendPosition": "right",
                    "nestedLegend": False,
                    "layerType": "data",
                }
            ],
        },
        DV_ANOM,
        KQL_USERS,
        "100% des détections -> T1110.003 Password Spraying.",
    )
)

# ── 5. Top utilisateurs (bar horizontal) ──
objs.append(
    lens(
        "ueba-v3-topusers",
        "Top utilisateurs — Fenêtres anormales",
        "lnsXY",
        "l5",
        {"x": c_terms("ueba.user.keyword", 10, "y", "Utilisateur"), "y": c_count()},
        ["x", "y"],
        xy("l5", "y", "x", "bar_horizontal", legend=False, value_labels="show"),
        DV_ANOM,
        KQL_USERS,
        "Classement des utilisateurs par fenêtres anormales.",
    )
)

# ── 6. Heatmap users × jours ──
objs.append(
    lens(
        "ueba-v3-heatmap",
        "Carte de chaleur — Activité anormale",
        "lnsHeatmap",
        "l6",
        {
            "x": c_date(interval="1d", label="Jour"),
            "y": c_terms("ueba.user.keyword", 10, "v", "Utilisateur"),
            "v": c_count(),
        },
        ["x", "y", "v"],
        {
            "shape": "heatmap",
            "layerId": "l6",
            "layerType": "data",
            "legend": {"isVisible": True, "position": "right", "type": "heatmap_legend"},
            "gridConfig": {
                "type": "heatmap_grid",
                "isCellLabelVisible": True,
                "isYAxisLabelVisible": True,
                "isXAxisLabelVisible": True,
                "isYAxisTitleVisible": False,
                "isXAxisTitleVisible": False,
            },
            "valueAccessor": "v",
            "xAccessor": "x",
            "yAccessor": "y",
        },
        DV_ANOM,
        KQL_USERS,
        "Intensité des anomalies par utilisateur et par jour.",
    )
)

# ── 7. Tableau détail alertes ──
objs.append(
    lens(
        "ueba-v3-alerts-table",
        "Détail des alertes UEBA",
        "lnsDatatable",
        "l7",
        {
            "user": c_terms("user", 10, "risk", "Utilisateur"),
            "day": c_date(interval="1d", label="Jour"),
            "rl": c_terms("risk_level", 3, "risk", "Niveau"),
            "risk": c_metric("max", "risk_score", "Risk score", fmt=fmt1),
            "cas2": c_metric("max", "score_cas2", "Score CAS2", fmt=fmt1),
        },
        ["user", "day", "rl", "risk", "cas2"],
        {
            "layerId": "l7",
            "layerType": "data",
            "columns": [
                {"columnId": "user"},
                {"columnId": "day"},
                {"columnId": "rl"},
                {"columnId": "risk"},
                {"columnId": "cas2"},
            ],
            "sorting": {"columnId": "risk", "direction": "desc"},
            "rowHeight": "single",
            "rowHeightLines": 1,
        },
        DV_ALERT,
        description="Détail trié des 14 alertes corrélées.",
    )
)

# ── 8. KPI MTTD moyen (bleu) ──
objs.append(
    lens(
        "ueba-v3-kpi-mttd",
        "MTTD moyen (minutes)",
        "lnsMetric",
        "l8",
        {"m": c_metric("average", "mttd_minutes", "MTTD moyen", fmt=fmt1)},
        ["m"],
        metric_viz("l8", "m", "#0f62fe", "Mean Time To Detect — campagne T1110.003"),
        DV_MTTD,
    )
)

# ── 9. Tableau MTTD par utilisateur ──
objs.append(
    lens(
        "ueba-v3-mttd-table",
        "MTTD par utilisateur",
        "lnsDatatable",
        "l9",
        {
            "user": c_terms("user", 10, "mttd", "Utilisateur"),
            "attack": c_metric("max", "attack_start", "Début attaque", data_type="date"),
            "first": c_metric("max", "first_detection", "1ère détection", data_type="date"),
            "mttd": c_metric("max", "mttd_minutes", "MTTD (min)", fmt=fmt1),
        },
        ["user", "attack", "first", "mttd"],
        {
            "layerId": "l9",
            "layerType": "data",
            "columns": [
                {"columnId": "user"},
                {"columnId": "attack"},
                {"columnId": "first"},
                {"columnId": "mttd"},
            ],
            "sorting": {"columnId": "mttd", "direction": "desc"},
            "rowHeight": "single",
            "rowHeightLines": 1,
        },
        DV_MTTD,
        description="Délai de détection par utilisateur ciblé.",
    )
)

# ── 10. Bar chart Risk Score par user ──
objs.append(
    lens(
        "ueba-v3-risk-bar",
        "Risk Score moyen par utilisateur",
        "lnsXY",
        "l10",
        {
            "x": c_terms("ueba.user.keyword", 10, "y", "Utilisateur"),
            "y": c_metric("average", "risk_score", "Risk score moyen", fmt=fmt1),
        },
        ["x", "y"],
        xy("l10", "y", "x", "bar", legend=False, value_labels="show"),
        DV_ANOM,
        KQL_USERS,
        "Score de risque moyen (0–100) par utilisateur.",
    )
)

# ── 11. Pie niveaux d'alerte ──
objs.append(
    lens(
        "ueba-v3-risk-pie",
        "Distribution des niveaux d'alerte",
        "lnsPie",
        "l11",
        {"g": c_terms("risk_level.keyword", 5, "m", "Niveau d'alerte"), "m": c_count()},
        ["g", "m"],
        {
            "shape": "pie",
            "layers": [
                {
                    "layerId": "l11",
                    "primaryGroups": ["g"],
                    "metrics": ["m"],
                    "numberDisplay": "percent",
                    "categoryDisplay": "default",
                    "legendDisplay": "show",
                    "legendPosition": "right",
                    "nestedLegend": False,
                    "layerType": "data",
                }
            ],
        },
        DV_ANOM,
        KQL_USERS,
        "Répartition CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE.",
    )
)

# ── 12. KPI utilisateurs CRITIQUES (rouge) ──
objs.append(
    lens(
        "ueba-v3-kpi-critical",
        "Utilisateurs niveau CRITIQUE",
        "lnsMetric",
        "l12",
        {"m": c_metric("unique_count", "ueba.user.keyword", "Users CRITIQUE")},
        ["m"],
        metric_viz("l12", "m", "#a2191f", "Utilisateurs avec ≥1 fenêtre CRITIQUE"),
        DV_ANOM,
        KQL_CRIT,
    )
)

# ── KPI entités à risque (DV_ENTITY) ──
objs.append(
    lens(
        "ueba-v4-kpi-entities",
        "Entités à risque",
        "lnsMetric",
        "l14",
        {"m": c_count("Entités à risque")},
        ["m"],
        metric_viz("l14", "m", "#8a3ffc", "Couples utilisateur × jour signalés"),
        DV_ENTITY,
    )
)

# ── KPI entités CRITIQUE (DV_ENTITY, rouge) ──
objs.append(
    lens(
        "ueba-v4-kpi-crit-entities",
        "Entités CRITIQUE",
        "lnsMetric",
        "l15",
        {"m": c_count("Entités CRITIQUE")},
        ["m"],
        metric_viz("l15", "m", "#da1e28", "Entités niveau CRITIQUE à investiguer"),
        DV_ENTITY,
        query_kql='risk_level : "CRITIQUE"',
    )
)

# ── FILE DE TRIAGE : Top entités à risque (pièce maîtresse) ──
objs.append(
    lens(
        "ueba-v4-entity-table",
        "🚨 File de triage — Top entités à risque (utilisateur × jour)",
        "lnsDatatable",
        "l13",
        {
            "user": c_terms("user", 50, "risk", "Utilisateur"),
            "day": c_terms("day", 5, "risk", "Jour"),
            "rl": c_terms("risk_level", 5, "risk", "Niveau"),
            "action": c_terms("recommended_action", 5, "risk", "Action recommandée"),
            "strong": c_metric("max", "strong_count", "Votes forts (≥3)"),
            "risk": c_metric("max", "max_risk_score", "Risk score", fmt=fmt1),
        },
        ["user", "day", "rl", "strong", "risk", "action"],
        {
            "layerId": "l13",
            "layerType": "data",
            "columns": [
                {"columnId": "user"},
                {"columnId": "day"},
                {"columnId": "rl"},
                {"columnId": "strong"},
                {"columnId": "risk"},
                {"columnId": "action"},
            ],
            "sorting": {"columnId": "risk", "direction": "desc"},
            "rowHeight": "single",
            "rowHeightLines": 1,
        },
        DV_ENTITY,
        description="File de triage classée par risque : l'analyste traite le haut de la pile.",
    )
)

# ── Bandeau d'en-tête (markdown) ──
_HEADER_MD = (
    "## 🛡️ UEBA — SOC Operations Console\n"
    "**Détection comportementale** · campagne *password spraying* MITRE **T1110.003** "
    "(13 & 16 mai 2026) · 7 utilisateurs ciblés.\n\n"
    "**Légende risque :** 🔴 CRITIQUE (≥80) · 🟠 ÉLEVÉ (≥60) · 🟡 MOYEN (≥40) · ⚪ FAIBLE — "
    "traiter la *file de triage* du haut vers le bas. Plage : 11–21 mai 2026."
)
objs.append(
    {
        "id": "ueba-v4-header",
        "type": "visualization",
        "managed": False,
        "coreMigrationVersion": KBN,
        "typeMigrationVersion": "8.5.0",
        "attributes": {
            "title": "UEBA SOC — Bandeau",
            "visState": json.dumps(
                {
                    "title": "UEBA SOC — Bandeau",
                    "type": "markdown",
                    "aggs": [],
                    "params": {"fontSize": 12, "openLinksInNewTab": True, "markdown": _HEADER_MD},
                }
            ),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "references": [],
    }
)

# ───────────────────────── dashboard (console SOC) ─────────────────────────
# (id, type, x, y, w, h) — grille 48 colonnes, pyramide inversée.
panels = [
    ("ueba-v4-header", "visualization", 0, 0, 48, 5),
    # KPI exécutifs
    ("ueba-v4-kpi-entities", "lens", 0, 5, 12, 8),
    ("ueba-v4-kpi-crit-entities", "lens", 12, 5, 12, 8),
    ("ueba-v3-kpi-mttd", "lens", 24, 5, 12, 8),
    ("ueba-v3-kpi-anomalies", "lens", 36, 5, 12, 8),
    # File de triage (centerpiece)
    ("ueba-v4-entity-table", "lens", 0, 13, 48, 18),
    # Contexte temporel
    ("ueba-v3-timeline", "lens", 0, 31, 32, 12),
    ("ueba-v3-heatmap", "lens", 32, 31, 16, 12),
    # Analytique
    ("ueba-v3-risk-pie", "lens", 0, 43, 16, 14),
    ("ueba-v3-mitre", "lens", 16, 43, 16, 14),
    ("ueba-v3-topusers", "lens", 32, 43, 16, 14),
    # Détail
    ("ueba-v3-alerts-table", "lens", 0, 57, 24, 14),
    ("ueba-v3-mttd-table", "lens", 24, 57, 24, 14),
]
panels_json, refs = [], []
for i, (vid, vtype, x, y, w, h) in enumerate(panels, start=1):
    name = f"panel_{i}"
    panels_json.append(
        {
            "version": KBN,
            "type": vtype,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": name,
        }
    )
    refs.append({"name": name, "type": vtype, "id": vid})

# Filtres interactifs (control group) : niveau d'alerte + utilisateur.
_CTRL = {
    "ctrl-risk": {
        "order": 0,
        "width": "small",
        "grow": True,
        "type": "optionsListControl",
        "explicitInput": {
            "id": "ctrl-risk",
            "fieldName": "risk_level",
            "title": "Niveau d'alerte",
            "dataViewId": DV_ENTITY,
            "enhancements": {},
        },
    },
    "ctrl-user": {
        "order": 1,
        "width": "medium",
        "grow": True,
        "type": "optionsListControl",
        "explicitInput": {
            "id": "ctrl-user",
            "fieldName": "user",
            "title": "Utilisateur",
            "dataViewId": DV_ENTITY,
            "enhancements": {},
        },
    },
}
control_refs = [
    {
        "name": "controlGroup_ctrl-risk:optionsListDataView",
        "type": "index-pattern",
        "id": DV_ENTITY,
    },
    {
        "name": "controlGroup_ctrl-user:optionsListDataView",
        "type": "index-pattern",
        "id": DV_ENTITY,
    },
]

objs.append(
    {
        "id": "ueba-soc-dashboard-v4",
        "type": "dashboard",
        "managed": False,
        "coreMigrationVersion": KBN,
        "typeMigrationVersion": "8.9.0",
        "attributes": {
            "title": "UEBA — SOC Operations Console (v4)",
            "description": "Console SOC orientée triage : file d'entités à risque priorisée, "
            "KPI exécutifs, MITRE T1110.003, filtres interactifs.",
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps(
                {
                    "useMargins": True,
                    "syncColors": False,
                    "syncCursor": True,
                    "syncTooltips": False,
                    "hidePanelTitles": False,
                }
            ),
            "timeRestore": True,
            "timeFrom": "2026-05-11T00:00:00.000Z",
            "timeTo": "2026-05-21T23:59:59.000Z",
            "refreshInterval": {"pause": True, "value": 60000},
            "controlGroupInput": {
                "controlStyle": "oneLine",
                "chainingSystem": "HIERARCHICAL",
                "showApplySelections": False,
                "ignoreParentSettingsJSON": json.dumps(
                    {
                        "ignoreFilters": False,
                        "ignoreQuery": False,
                        "ignoreTimerange": False,
                        "ignoreValidations": False,
                    }
                ),
                "panelsJSON": json.dumps(_CTRL),
            },
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"language": "kuery", "query": ""}, "filter": []}
                )
            },
        },
        "references": refs + control_refs,
    }
)

out_path = "docs/kibana/ueba-dashboard-v4.ndjson"
with open(out_path, "w") as f:
    for o in objs:
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
    f.write(
        json.dumps({"exportedCount": len(objs), "missingRefCount": 0, "missingReferences": []})
        + "\n"
    )
print(f"OK — {len(objs)} objets écrits dans {out_path}")
