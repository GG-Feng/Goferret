"""渲染给维护者的报告草稿、每个单元的一键复现脚本，以及跨仓库汇总表。

报告正文只写「已复现」的条目；其余只在附录一行一条。不出现工具名、置信度、CVSS。
"""
import csv, glob, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
HINTS = json.load(open(os.path.join(HERE, 'fix_hints.json'), encoding='utf-8'))


def repro_sh(repo, commit, u, ev, test_name):
    pkg = ev['pkg_rel'] if ev['pkg_rel'] not in ('', '.') else '.'
    wd = '' if ev['mod_rel'] in ('', '.') else '/' + ev['mod_rel']
    return f"""#!/bin/sh
# 一键复现：{repo} @ {commit}
# 目标：{u['function']}
set -e
WORK=$(mktemp -d)
git clone -q https://github.com/{repo} "$WORK/src"
git -C "$WORK/src" checkout -q {commit}
cp "$(dirname "$0")/experiment_test.go" "$WORK/src{wd}/{ev['pkg_rel']}/repro_{u['unit_id']}_test.go"
docker run --rm -v "$WORK/src:/src" -w /src{wd} golang:1.25 go test ./{pkg} -run '^{test_name}$' -count=1 -v
"""


# 检测器记录的输入来源类型中，明确来自远程对端的几类；其余（文件读取、JSON 解码等）来源不定，需维护者按信任边界判断
REMOTE_SOURCES = {'http_request', 'http_body', 'network_accept', 'read_message'}
SOURCE_ZH = {'http_request': 'HTTP 请求', 'http_body': 'HTTP 响应/请求体', 'network_accept': '网络连接', 'read_message': '网络消息',
             'read': '读取', 'read_all': '整段读取', 'json_decode': 'JSON 解码', 'xml_decode': 'XML 解码', 'io_copy': '流复制',
             'buffered_read': '缓冲读取', 'scan': '逐行扫描', 'channel_recv': '通道接收'}


# 这几类主张（缺少鉴权/授权/来源校验）在同包单元测试里无法看到路由层或中间件的上游检查，只能证明函数本身不检查
AUTH_CATEGORIES = {'identity_verification', 'access_control', 'origin_validation'}


def _item(i, r, sel):
    u, ev, sp, v = r['unit'], r['ev'], r['spec'] or {}, r['verdict']
    cat = sp.get('category') if sp.get('category') in HINTS else u['category']  # 以实验实际证明的类别为准
    h = HINTS.get(cat, {'zh': cat, 'issue': '', 'fix': ''})
    lines = sorted(set(u['source_lines']) | set(u['sink_lines']))
    return [f"### {i}. `{ev['file']}` 中的 `{ev['qname']}`（第 {ev['start']}–{ev['end']} 行）", '',
            f"**问题**：{sp.get('what', '')}", '',
            f"缺少{h['zh']}：{h['issue']}。涉及第 {', '.join(map(str, lines))} 行；"
            f"输入来源：{'、'.join(SOURCE_ZH.get(s, s) for s in u.get('source_types', []))}。", '',
            '**复现**：', '', '```sh', f"sh cases/{sel['slug']}/{u['unit_id']}/repro.sh", '```', '',
            f"- 正常输入：{sp.get('benign', '')}", f"- 恶意输入：{sp.get('malicious', '')}", '',
            '预期输出中的关键行：', '', '```'] + v['marker_lines'] + ['```', '', f"**建议**：{h['fix']}", '']


def render_repo(repo, sel, results):
    """results: list of dict(unit, ev, spec, verdict)。返回 markdown 文本。"""
    commit = sel['commit']
    ok = [r for r in results if r['verdict']['verdict'] == '已复现']
    def cat_of(r):
        sp = r['spec'] or {}
        return sp.get('category') if sp.get('category') in HINTS else r['unit']['category']
    auth = [r for r in ok if cat_of(r) in AUTH_CATEGORIES]
    remote = [r for r in ok if r not in auth and set(r['unit'].get('source_types', [])) & REMOTE_SOURCES]
    local = [r for r in ok if r not in auth and r not in remote]
    rest = [r for r in results if r['verdict']['verdict'] != '已复现']
    L = [f'# {repo} 安全问题复现报告（草稿）', '',
         f'- 版本：`{commit}`',
         f'- 检查项：{len(results)} 个函数，其中 {len(ok)} 个已在隔离容器中复现（远程输入触发 {len(remote)}，本地输入触发 {len(local)}，需确认上游鉴权 {len(auth)}）',
         '- 每个问题附有一条可独立执行的复现命令（需要 Docker 和网络以获取依赖）', '']
    sections = [
        ('一、远程输入可触发的问题', remote, ''),
        ('二、由本地文件或内部数据触发的问题', local,
         '以下问题已在容器中复现，但触发输入来自本地文件、配置或内部数据。是否构成安全问题，取决于这些输入在实际部署中能否被不可信方控制，请按项目的信任边界判断。'),
        ('三、函数本身不做鉴权/授权检查的问题', auth,
         '以下实验证明了被测函数本身不检查调用方身份或权限。同包测试看不到路由层和中间件，如果鉴权在调用链上游完成，这些条目不构成问题，请按实际调用链判断。'),
    ]
    n = 0
    for title, items, note in sections:
        L += [f'## {title}（{len(items)}）', '']
        if note:
            L += [note, '']
        if not items:
            L += ['本轮没有。', '']
        for r in items:
            n += 1
            L += _item(n, r, sel)
    L += ['## 附录：其余检查项', '', '| 位置 | 结论 | 说明 |', '|---|---|---|']
    reasons = {'timeout': '实验超时', 'build_failed': '测试未能编译', 'markers_missing': '实验未产生有效观察',
               'malicious_not_reached': '恶意输入未到达目标代码', 'arms_indistinguishable': '两种输入结果无差别',
               'benign_also_bug': '正常输入也出现同样表现', 'no_bug_observed': '未观察到问题表现',
               'blocked_by_known_guard': '现有检查拦截了恶意输入', 'no_experiment': '未能构造实验', 'evidence_missing': '未能定位函数',
               'benign_not_reached': '正常输入也未到达目标代码（前置条件未建立）', 'package_unbuildable': '所在包在当前环境无法编译',
               'bug_if_not_evaluable': '判定条件无法对实测值求值', 'bug_if_holds_on_malicious_only': '恶意输入满足判定条件',
               'package_needs_infra': '所在包的测试骨架依赖数据库/外部服务，离线环境无法运行'}
    for r in rest:
        u, ev, v = r['unit'], r['ev'], r['verdict']
        loc = f"`{ev['file']}:{ev['qname']}`" if ev else f"`{u['function']}`"
        L.append(f"| {loc} | {v['verdict']} | {reasons.get(v['rule'], v['rule'])} |")
    return '\n'.join(L) + '\n'


def summary_csv(cases_root):
    rows = []
    for sp in sorted(glob.glob(os.path.join(cases_root, '*', 'selected.json'))):
        sel = json.load(open(sp, encoding='utf-8'))
        cnt = {'已复现': 0, '不成立': 0, '未能复现': 0}
        for u in sel['units']:
            vp = os.path.join(os.path.dirname(sp), u['unit_id'], 'verdict.json')
            if os.path.exists(vp):
                cnt[json.load(open(vp, encoding='utf-8'))['verdict']] += 1
        rows.append(dict(repo=sel['repo'], commit=sel['commit'][:10], units=len(sel['units']), **cnt))
    with open(os.path.join(cases_root, 'summary.csv'), 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, ['repo', 'commit', 'units', '已复现', '不成立', '未能复现']); w.writeheader(); w.writerows(rows)
    return rows
