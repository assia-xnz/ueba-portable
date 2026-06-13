#!/usr/bin/env python3
"""
Générateur du dashboard SOC UEBA (Kibana 8.19, visualisations Lens natives).

Produit ueba-dashboard-v2.ndjson, auto-suffisant :
  - 2 data views (index-pattern) bundlés avec IDs déterministes
  - 7 visualisations Lens
  - 1 dashboard assemblé

Champs RÉELS utilisés (vérifiés via diagnostic ES) :
  ueba-anomalies-*  : @timestamp, ueba.user.keyword, ueba.vote_count,
                      mitre_technique.keyword (enrichi)
  ueba-alerts       : @timestamp, user, risk_score, risk_level,
                      score_cas2, n_low, window_start/end
"""
import json

KBN = "8.19.0"
DV_ANOM = "ueba-anomalies-dv"
DV_ALERT = "ueba-alerts-dv"
USERS = ["a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"]
# Filtre KQL réutilisé par toutes les viz basées sur les anomalies
KQL_USERS = "ueba.user.keyword : (" + " or ".join(f'"{u}"' for u in USERS) + ")"

objs = []

# ───────────────────────── helpers colonnes Lens ─────────────────────────
def c_count(label="Nombre d'anomalies"):
    return {"label": label, "dataType": "number", "operationType": "count",
            "sourceField": "___records___", "isBucketed": False, "scale": "ratio",
            "params": {"emptyAsNull": False}}

def c_date(field="@timestamp", interval="auto", label=None):
    return {"label": label or field, "dataType": "date", "operationType": "date_histogram",
            "sourceField": field, "isBucketed": True, "scale": "interval",
            "params": {"interval": interval, "includeEmptyRows": True, "dropPartials": False}}

def c_terms(field, size, order_col, label=None, direction="desc"):
    return {"label": label or f"Top {size} {field}", "dataType": "string",
            "operationType": "terms", "sourceField": field, "isBucketed": True,
            "scale": "ordinal",
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_col},
                       "orderDirection": direction, "otherBucket": False,
                       "missingBucket": False, "parentFormat": {"id": "terms"}}}

def c_max(field, label=None, fmt=None):
    col = {"label": label or f"Max {field}", "dataType": "number", "operationType": "max",
           "sourceField": field, "isBucketed": False, "scale": "ratio",
           "params": {"emptyAsNull": False}}
    if fmt:
        col["params"]["format"] = fmt
    return col

# ───────────────────────── helper objet Lens ─────────────────────────
def lens(obj_id, title, viz_type, layer_id, columns, column_order, visualization,
         dv_id, query_kql=None, description=""):
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
            {"type": "index-pattern", "id": dv_id,
             "name": f"indexpattern-datasource-layer-{layer_id}"}
        ],
    }

# ───────────────────────── data views ─────────────────────────
objs.append({
    "id": DV_ANOM, "type": "index-pattern", "managed": False,
    "coreMigrationVersion": KBN, "typeMigrationVersion": "8.0.0",
    "attributes": {"title": "ueba-anomalies-*", "name": "UEBA Anomalies",
                   "timeFieldName": "@timestamp"},
    "references": [],
})
objs.append({
    "id": DV_ALERT, "type": "index-pattern", "managed": False,
    "coreMigrationVersion": KBN, "typeMigrationVersion": "8.0.0",
    "attributes": {"title": "ueba-alerts", "name": "UEBA Alerts",
                   "timeFieldName": "@timestamp"},
    "references": [],
})

# ───── V1 — Timeline (area, split par user) ─────
L = "l1"
objs.append(lens(
    "ueba-v2-timeline", "Timeline des anomalies comportementales", "lnsXY", L,
    columns={
        "x": c_date(label="Date"),
        "s": c_terms("ueba.user.keyword", 7, "y", label="Utilisateur"),
        "y": c_count(),
    },
    column_order=["x", "s", "y"],
    visualization={
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "hide", "fittingFunction": "None",
        "axisTitlesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "preferredSeriesType": "area_stacked",
        "layers": [{
            "layerId": L, "accessors": ["y"], "position": "top",
            "seriesType": "area_stacked", "showGridlines": False, "layerType": "data",
            "xAccessor": "x", "splitAccessor": "s",
        }],
    },
    dv_id=DV_ANOM, query_kql=KQL_USERS,
    description="Évolution temporelle des fenêtres anormales par utilisateur (T1110.003).",
))

# ───── V2 — Top utilisateurs (bar horizontal) ─────
L = "l2"
objs.append(lens(
    "ueba-v2-topusers", "Top utilisateurs — Fenêtres anormales", "lnsXY", L,
    columns={
        "x": c_terms("ueba.user.keyword", 10, "y", label="Utilisateur"),
        "y": c_count(),
    },
    column_order=["x", "y"],
    visualization={
        "legend": {"isVisible": False, "position": "right"},
        "valueLabels": "show", "fittingFunction": "None",
        "axisTitlesVisibilitySettings": {"x": True, "yLeft": False, "yRight": True},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "preferredSeriesType": "bar_horizontal",
        "layers": [{
            "layerId": L, "accessors": ["y"], "position": "top",
            "seriesType": "bar_horizontal", "showGridlines": False, "layerType": "data",
            "xAccessor": "x",
        }],
    },
    dv_id=DV_ANOM, query_kql=KQL_USERS,
    description="Classement des utilisateurs par nombre de fenêtres anormales.",
))

# ───── V3 — MITRE ATT&CK (donut) ─────
L = "l3"
objs.append(lens(
    "ueba-v2-mitre", "Techniques MITRE ATT&CK détectées", "lnsPie", L,
    columns={
        "g": c_terms("mitre_technique.keyword", 5, "m", label="Technique MITRE"),
        "m": c_count(),
    },
    column_order=["g", "m"],
    visualization={
        "shape": "donut",
        "layers": [{
            "layerId": L, "primaryGroups": ["g"], "metrics": ["m"],
            "numberDisplay": "value", "categoryDisplay": "default",
            "legendDisplay": "show", "legendPosition": "right",
            "nestedLegend": False, "layerType": "data",
        }],
    },
    dv_id=DV_ANOM, query_kql=KQL_USERS,
    description="100% des détections cartographiées sur T1110.003 — Password Spraying.",
))

# ───── V4 — KPI Total anomalies ─────
L = "l4"
objs.append(lens(
    "ueba-v2-kpi-anomalies", "Total anomalies détectées", "lnsMetric", L,
    columns={"m": c_count(label="Total anomalies")},
    column_order=["m"],
    visualization={
        "layerId": L, "layerType": "data", "metricAccessor": "m",
        "color": "#da1e28", "subtitle": "Fenêtres anormales (7 utilisateurs)",
        "showBar": False,
    },
    dv_id=DV_ANOM, query_kql=KQL_USERS,
    description="Nombre total de fenêtres anormales détectées.",
))

# ───── V5 — KPI Alertes critiques ─────
L = "l5"
objs.append(lens(
    "ueba-v2-kpi-alerts", "Alertes critiques (recall 100%)", "lnsMetric", L,
    columns={"m": c_count(label="Alertes")},
    column_order=["m"],
    visualization={
        "layerId": L, "layerType": "data", "metricAccessor": "m",
        "color": "#ff832b", "subtitle": "Alertes corrélées — recall 14/14",
        "showBar": False,
    },
    dv_id=DV_ALERT,
    description="Alertes UEBA corrélées (rappel opérationnel 100%).",
))

# ───── V6 — Tableau détail des alertes ─────
L = "l6"
fmt_num = {"id": "number", "params": {"decimals": 1}}
objs.append(lens(
    "ueba-v2-table", "Détail des alertes UEBA", "lnsDatatable", L,
    columns={
        "user": c_terms("user", 10, "risk", label="Utilisateur"),
        "day": c_date(interval="1d", label="Jour"),
        "rl": c_terms("risk_level", 3, "risk", label="Niveau de risque"),
        "risk": c_max("risk_score", label="Risk score", fmt=fmt_num),
        "cas2": c_max("score_cas2", label="Score CAS2", fmt=fmt_num),
        "nlow": c_max("n_low", label="Tentatives (n_low)"),
    },
    column_order=["user", "day", "rl", "risk", "cas2", "nlow"],
    visualization={
        "layerId": L, "layerType": "data",
        "columns": [
            {"columnId": "user"}, {"columnId": "day"}, {"columnId": "rl"},
            {"columnId": "risk"}, {"columnId": "cas2"}, {"columnId": "nlow"},
        ],
        "sorting": {"columnId": "risk", "direction": "desc"},
        "rowHeight": "single", "rowHeightLines": 1,
    },
    dv_id=DV_ALERT,
    description="Détail trié des 14 alertes corrélées (risk score, scores par cas).",
))

# ───── V7 — Heatmap utilisateurs × jours ─────
L = "l7"
objs.append(lens(
    "ueba-v2-heatmap", "Carte de chaleur — Activité anormale", "lnsHeatmap", L,
    columns={
        "x": c_date(interval="1d", label="Jour"),
        "y": c_terms("ueba.user.keyword", 10, "v", label="Utilisateur"),
        "v": c_count(),
    },
    column_order=["x", "y", "v"],
    visualization={
        "shape": "heatmap", "layerId": L, "layerType": "data",
        "legend": {"isVisible": True, "position": "right", "type": "heatmap_legend"},
        "gridConfig": {"type": "heatmap_grid", "isCellLabelVisible": True,
                       "isYAxisLabelVisible": True, "isXAxisLabelVisible": True,
                       "isYAxisTitleVisible": False, "isXAxisTitleVisible": False},
        "valueAccessor": "v", "xAccessor": "x", "yAccessor": "y",
    },
    dv_id=DV_ANOM, query_kql=KQL_USERS,
    description="Intensité des anomalies par utilisateur et par jour.",
))

# ───────────────────────── dashboard ─────────────────────────
# Grille Kibana = 48 colonnes de large
panels = [
    ("ueba-v2-kpi-anomalies", 0,  0, 12, 8),
    ("ueba-v2-kpi-alerts",    12, 0, 12, 8),
    ("ueba-v2-mitre",         24, 0, 24, 8),
    ("ueba-v2-timeline",      0,  8, 48, 12),
    ("ueba-v2-topusers",      0, 20, 24, 14),
    ("ueba-v2-heatmap",       24,20, 24, 14),
    ("ueba-v2-table",         0, 34, 48, 14),
]
panels_json, refs = [], []
for i, (vid, x, y, w, h) in enumerate(panels, start=1):
    name = f"panel_{i}"
    panels_json.append({
        "version": KBN, "type": "lens",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i),
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": name,
    })
    refs.append({"name": name, "type": "lens", "id": vid})

objs.append({
    "id": "ueba-soc-dashboard-v2", "type": "dashboard", "managed": False,
    "coreMigrationVersion": KBN, "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "UEBA — SOC Dashboard",
        "description": "Détection de password spraying (MITRE T1110.003) — "
                       "campagne des 13 & 16 mai 2026, 7 utilisateurs ciblés.",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False,
                                   "syncCursor": True, "syncTooltips": False,
                                   "hidePanelTitles": False}),
        "timeRestore": True,
        "timeFrom": "2026-05-11T00:00:00.000Z",
        "timeTo": "2026-05-21T23:59:59.000Z",
        "refreshInterval": {"pause": True, "value": 60000},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""},
                                            "filter": []})
        },
    },
    "references": refs,
})

# Ligne finale exportedCount (format export Kibana)
out_path = "docs/kibana/ueba-dashboard-v2.ndjson"
with open(out_path, "w") as f:
    for o in objs:
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
    f.write(json.dumps({"exportedCount": len(objs),
                        "missingRefCount": 0, "missingReferences": []}) + "\n")
print(f"OK — {len(objs)} objets écrits dans {out_path}")
