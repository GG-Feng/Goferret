#!/usr/bin/env python3
"""验证集汇总：对 cases_validation/advisories.json 里的每条 advisory，按三层给出结果。

  检出   Goferret 的 report.json 是否报到了目标函数；类别是否与 advisory 一致
  复现   workflow 对目标函数各单元的结论（detected = 检测器报的类别；manual = 人工补的类别）
  一致   留给负责人核对（脚本只列出实验的一句话说明）
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
V, S = os.path.join(HERE, 'cases_validation'), os.path.join(HERE, 'scans')


def jload(p, d=None):
    return json.load(open(p, encoding='utf-8')) if os.path.exists(p) else d


rows = []
for a in jload(os.path.join(V, 'advisories.json')):
    slug = a['repo'].replace('/', '__')
    findings = (jload(os.path.join(S, slug, 'report.json')) or {}).get('findings', [])
    sel = jload(os.path.join(V, slug, 'selected.json')) or {'units': []}
    cats = a['category'] if isinstance(a['category'], list) else [a['category']]
    for t in a['targets']:
        det = sorted({f['missing_step_category'] for f in findings if f['function'] == t})
        units = []
        for u in sel['units']:
            if u['function'] != t:
                continue
            d = os.path.join(V, slug, u['unit_id'])
            v, sp = jload(os.path.join(d, 'verdict.json')) or {}, jload(os.path.join(d, 'spec.json')) or {}
            units.append(dict(category=u['category'], origin='manual' if u.get('manual') else 'detected',
                              verdict=v.get('verdict', '—'), rule=v.get('rule', '—'), what=(sp.get('what') or '')[:90]))
        rows.append(dict(ghsa=a['ghsa'], repo=a['repo'], target=t, advisory_category='/'.join(cats),
                         detected_categories='/'.join(det) or '—', category_match=bool(set(det) & set(cats)), units=units))

print('| advisory | 目标 | advisory 类别 | 检出类别 | 类别一致 | workflow 结论（单元类别:来源→结论/规则） |')
print('|---|---|---|---|---|---|')
for r in rows:
    us = '<br>'.join(f"{u['category']}:{u['origin']}→{u['verdict']}/{u['rule']}" for u in r['units']) or '—'
    print(f"| {r['ghsa']} | `{r['target']}` | {r['advisory_category']} | {r['detected_categories']} | {'是' if r['category_match'] else '否'} | {us} |")
json.dump(rows, open(os.path.join(V, 'validation_summary.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
