#!/usr/bin/env python3
"""Générateur du dashboard SOC UEBA v3 (Kibana 8.19, visualisations Lens natives).

Produit ueba-dashboard-v3.ndjson, auto-suffisant : 3 data views + 12 visualisations
Lens + 1 dashboard. Étend la v2 (7 viz) avec les améliorations MTTD et risk scoring :

  8.  KPI MTTD moyen (bleu)              — index ueba-mttd
  9.  Tableau MTTD par utilisateur       — index ueba-mttd
  10. Bar chart Risk Score par user      — index ueba-anomalies-* (risk_score)
  11. Pie chart niveaux d'alerte         — index ueba-anomalies-* (risk_level)
  12. KPI utilisateurs CRITIQUES (rouge) — index ueba-anomalies-* (risk_level)

Champs RÉELS uniquement (vérifiés via diagnostic ES).
"""

import json

KBN = "8.19.0"
DV_ANOM = "ueba-anomalies-dv"
DV_ALERT = "ueba-alerts-dv"
DV_MTTD = "ueba-mttd-dv"
USERS = ["a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"]
KQL_USERS = "ueba.user.keyword : (" + " or ".join(f'"{u}"' for u in USERS) + ")"
KQL_CRIT = KQL_USERS + ' and risk_level.keyword : "CRITIQUE"'

objs = []


# ───────────────────────── helpers colonnes Lens ─────────────────────────
def c_count(label="Nombre d'anomalies"):
    return {
        "label": label, "dataType": "number", "operationType": "count",
        "sourceField": "___records___", "isBucketed": False, "scale": "ratio",
        "params": {"emptyAsNull": False},
    }


def c_date(field="@timestamp", interval="auto", label=None):
    return {
        "label": label or field, "dataType": "date", "operationType": "date_histogram",
        "sourceField": field, "isBucketed": True, "scale": "interval",
        "params": {"interval": interval, "includeEmptyRows": True, "dropPartials": False},
    }


def c_terms(field, size, order_col, label=None, direction="desc"):
    return {
        "label": label or f"Top {size} {field}", "dataType": "string",
        "operationType": "terms", "sourceField": field, "isBucketed": True, "scale": "ordinal",
        "params": {
            "size": size, "orderBy": {"type": "column", "columnId": order_col},
            "orderDirection": direction, "otherBucket": False, "missingBucket": False,
            "parentFormat": {"id": "terms"},
        },
    }


def c_metric(op, field, label=None, data_type="number", fmt=None):
    col = {
        "label": label or f"{op} {field}", "dataType": data_type, "operationType": op,
        "sourceField": field, "isBucketed": False, "scale": "ratio",
        "params": {"emptyAsNull": False},
    }
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
                        "columns": columns, "columnOrder": column_order,
                        "incompleteColumns": {}, "sampling": 1,
                    }
                }
            }
        },
        "internalReferences": [],
        "adHocDataViews": {},
    }
    return {
        "id": obj_id, "type": "lens", "managed": False,
        "coreMigrationVersion": KBN, "typeMigrationVersion": "8.9.0",
        "attributes": {
            "title": title, "description": description,
            "visualizationType": viz_type, "state": state,
        },
        "references": [
            {"type": "index-pattern", "id": dv_id,
             "name": f"indexpattern-datasource-layer-{layer_id}"}
        ],
    }


def index_pattern(dv_id, title, name):
    return {
        "id": dv_id, "type": "index-pattern", "managed": False,
        "coreMigrationVersion": KBN, "typeMigrationVersion": "8.0.0",
        "attributes": {"title": title, "name": name, "timeFieldName": "@timestamp"},
        "references": [],
    }


def xy(layer_id, accessor, x_acc, series_type, split=None, legend=True, value_labels="hide"):
    layer = {
        "layerId": layer_id, "accessors": [accessor], "position": "top",
        "seriesType": series_type, "showGridlines": False, "layerType": "data",
        "xAccessor": x_acc,
    }
    if split:
        layer["splitAccessor"] = split
    return {
        "legend": {"isVisible": legend, "position": "right"},
        "valueLabels": value_labels, "fittingFunction": "None",
        "axisTitlesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "preferredSeriesType": series_type, "layers": [layer],
    }


def metric_viz(layer_id, acc, color, subtitle):
    return {
        "layerId": layer_id, "layerType": "data", "metricAccessor": acc,
        "color": color, "subtitle": subtitle, "showBar": False,
    }


# ───────────────────────── data views ─────────────────────────
objs.append(index_pattern(DV_ANOM, "ueba-anomalies-*", "UEBA Anomalies"))
objs.append(index_pattern(DV_ALERT, "ueba-alerts", "UEBA Alerts"))
objs.append(index_pattern(DV_MTTD, "ueba-mttd", "UEBA MTTD"))

fmt1 = {"id": "number", "params": {"decimals": 1}}

# ── 1. Timeline (area empilée) ──
objs.append(lens(
    "ueba-v3-timeline", "Timeline des anomalies comportementales", "lnsXY", "l1",
    {"x": c_date(label="Date"), "s": c_terms("ueba.user.keyword", 7, "y", "Utilisateur"),
     "y": c_count()},
    ["x", "s", "y"],
    xy("l1", "y", "x", "area_stacked", split="s"),
    DV_ANOM, KQL_USERS, "Évolution temporelle des fenêtres anormales (T1110.003)."))

# ── 2. KPI Total anomalies (rouge) ──
objs.append(lens(
    "ueba-v3-kpi-anomalies", "Total anomalies détectées", "lnsMetric", "l2",
    {"m": c_count("Total anomalies")}, ["m"],
    metric_viz("l2", "m", "#da1e28", "Fenêtres anormales (7 utilisateurs)"),
    DV_ANOM, KQL_USERS))

# ── 3. KPI Alertes critiques (orange) ──
objs.append(lens(
    "ueba-v3-kpi-alerts", "Alertes critiques (recall 100%)", "lnsMetric", "l3",
    {"m": c_count("Alertes")}, ["m"],
    metric_viz("l3", "m", "#ff832b", "Alertes corrélées — recall 14/14"),
    DV_ALERT))

# ── 4. Donut MITRE ATT&CK ──
objs.append(lens(
    "ueba-v3-mitre", "Techniques MITRE ATT&CK détectées", "lnsPie", "l4",
    {"g": c_terms("mitre_technique.keyword", 5, "m", "Technique MITRE"), "m": c_count()},
    ["g", "m"],
    {"shape": "donut", "layers": [{
        "layerId": "l4", "primaryGroups": ["g"], "metrics": ["m"], "numberDisplay": "value",
        "categoryDisplay": "default", "legendDisplay": "show", "legendPosition": "right",
        "nestedLegend": False, "layerType": "data"}]},
    DV_ANOM, KQL_USERS, "100% des détections -> T1110.003 Password Spraying."))

# ── 5. Top utilisateurs (bar horizontal) ──
objs.append(lens(
    "ueba-v3-topusers", "Top utilisateurs — Fenêtres anormales", "lnsXY", "l5",
    {"x": c_terms("ueba.user.keyword", 10, "y", "Utilisateur"), "y": c_count()},
    ["x", "y"],
    xy("l5", "y", "x", "bar_horizontal", legend=False, value_labels="show"),
    DV_ANOM, KQL_USERS, "Classement des utilisateurs par fenêtres anormales."))

# ── 6. Heatmap users × jours ──
objs.append(lens(
    "ueba-v3-heatmap", "Carte de chaleur — Activité anormale", "lnsHeatmap", "l6",
    {"x": c_date(interval="1d", label="Jour"),
     "y": c_terms("ueba.user.keyword", 10, "v", "Utilisateur"), "v": c_count()},
    ["x", "y", "v"],
    {"shape": "heatmap", "layerId": "l6", "layerType": "data",
     "legend": {"isVisible": True, "position": "right", "type": "heatmap_legend"},
     "gridConfig": {"type": "heatmap_grid", "isCellLabelVisible": True,
                    "isYAxisLabelVisible": True, "isXAxisLabelVisible": True,
                    "isYAxisTitleVisible": False, "isXAxisTitleVisible": False},
     "valueAccessor": "v", "xAccessor": "x", "yAccessor": "y"},
    DV_ANOM, KQL_USERS, "Intensité des anomalies par utilisateur et par jour."))

# ── 7. Tableau détail alertes ──
objs.append(lens(
    "ueba-v3-alerts-table", "Détail des alertes UEBA", "lnsDatatable", "l7",
    {"user": c_terms("user", 10, "risk", "Utilisateur"),
     "day": c_date(interval="1d", label="Jour"),
     "rl": c_terms("risk_level", 3, "risk", "Niveau"),
     "risk": c_metric("max", "risk_score", "Risk score", fmt=fmt1),
     "cas2": c_metric("max", "score_cas2", "Score CAS2", fmt=fmt1)},
    ["user", "day", "rl", "risk", "cas2"],
    {"layerId": "l7", "layerType": "data",
     "columns": [{"columnId": "user"}, {"columnId": "day"}, {"columnId": "rl"},
                 {"columnId": "risk"}, {"columnId": "cas2"}],
     "sorting": {"columnId": "risk", "direction": "desc"},
     "rowHeight": "single", "rowHeightLines": 1},
    DV_ALERT, description="Détail trié des 14 alertes corrélées."))

# ── 8. KPI MTTD moyen (bleu) ──
objs.append(lens(
    "ueba-v3-kpi-mttd", "MTTD moyen (minutes)", "lnsMetric", "l8",
    {"m": c_metric("average", "mttd_minutes", "MTTD moyen", fmt=fmt1)}, ["m"],
    metric_viz("l8", "m", "#0f62fe", "Mean Time To Detect — campagne T1110.003"),
    DV_MTTD))

# ── 9. Tableau MTTD par utilisateur ──
objs.append(lens(
    "ueba-v3-mttd-table", "MTTD par utilisateur", "lnsDatatable", "l9",
    {"user": c_terms("user", 10, "mttd", "Utilisateur"),
     "attack": c_metric("max", "attack_start", "Début attaque", data_type="date"),
     "first": c_metric("max", "first_detection", "1ère détection", data_type="date"),
     "mttd": c_metric("max", "mttd_minutes", "MTTD (min)", fmt=fmt1)},
    ["user", "attack", "first", "mttd"],
    {"layerId": "l9", "layerType": "data",
     "columns": [{"columnId": "user"}, {"columnId": "attack"},
                 {"columnId": "first"}, {"columnId": "mttd"}],
     "sorting": {"columnId": "mttd", "direction": "desc"},
     "rowHeight": "single", "rowHeightLines": 1},
    DV_MTTD, description="Délai de détection par utilisateur ciblé."))

# ── 10. Bar chart Risk Score par user ──
objs.append(lens(
    "ueba-v3-risk-bar", "Risk Score moyen par utilisateur", "lnsXY", "l10",
    {"x": c_terms("ueba.user.keyword", 10, "y", "Utilisateur"),
     "y": c_metric("average", "risk_score", "Risk score moyen", fmt=fmt1)},
    ["x", "y"],
    xy("l10", "y", "x", "bar", legend=False, value_labels="show"),
    DV_ANOM, KQL_USERS, "Score de risque moyen (0–100) par utilisateur."))

# ── 11. Pie niveaux d'alerte ──
objs.append(lens(
    "ueba-v3-risk-pie", "Distribution des niveaux d'alerte", "lnsPie", "l11",
    {"g": c_terms("risk_level.keyword", 5, "m", "Niveau d'alerte"), "m": c_count()},
    ["g", "m"],
    {"shape": "pie", "layers": [{
        "layerId": "l11", "primaryGroups": ["g"], "metrics": ["m"], "numberDisplay": "percent",
        "categoryDisplay": "default", "legendDisplay": "show", "legendPosition": "right",
        "nestedLegend": False, "layerType": "data"}]},
    DV_ANOM, KQL_USERS, "Répartition CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE."))

# ── 12. KPI utilisateurs CRITIQUES (rouge) ──
objs.append(lens(
    "ueba-v3-kpi-critical", "Utilisateurs niveau CRITIQUE", "lnsMetric", "l12",
    {"m": c_metric("unique_count", "ueba.user.keyword", "Users CRITIQUE")}, ["m"],
    metric_viz("l12", "m", "#a2191f", "Utilisateurs avec ≥1 fenêtre CRITIQUE"),
    DV_ANOM, KQL_CRIT))

# ───────────────────────── dashboard ─────────────────────────
panels = [
    ("ueba-v3-kpi-anomalies", 0, 0, 12, 8),
    ("ueba-v3-kpi-alerts", 12, 0, 12, 8),
    ("ueba-v3-kpi-mttd", 24, 0, 12, 8),
    ("ueba-v3-kpi-critical", 36, 0, 12, 8),
    ("ueba-v3-timeline", 0, 8, 48, 12),
    ("ueba-v3-topusers", 0, 20, 16, 14),
    ("ueba-v3-heatmap", 16, 20, 16, 14),
    ("ueba-v3-mitre", 32, 20, 16, 14),
    ("ueba-v3-risk-bar", 0, 34, 24, 14),
    ("ueba-v3-risk-pie", 24, 34, 24, 14),
    ("ueba-v3-mttd-table", 0, 48, 24, 14),
    ("ueba-v3-alerts-table", 24, 48, 24, 14),
]
panels_json, refs = [], []
for i, (vid, x, y, w, h) in enumerate(panels, start=1):
    name = f"panel_{i}"
    panels_json.append({
        "version": KBN, "type": "lens",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i), "embeddableConfig": {"enhancements": {}}, "panelRefName": name,
    })
    refs.append({"name": name, "type": "lens", "id": vid})

objs.append({
    "id": "ueba-soc-dashboard-v3", "type": "dashboard", "managed": False,
    "coreMigrationVersion": KBN, "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "UEBA — SOC Dashboard v3",
        "description": "Détection password spraying T1110.003 (13 & 16 mai 2026) — "
                       "MTTD, risk scoring et niveaux d'alerte SOC.",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                   "syncTooltips": False, "hidePanelTitles": False}),
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

out_path = "docs/kibana/ueba-dashboard-v3.ndjson"
with open(out_path, "w") as f:
    for o in objs:
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
    f.write(json.dumps({"exportedCount": len(objs), "missingRefCount": 0,
                        "missingReferences": []}) + "\n")
print(f"OK — {len(objs)} objets écrits dans {out_path}")
