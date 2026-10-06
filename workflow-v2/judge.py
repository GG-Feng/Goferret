"""规则判定：只看 run.log 里的固定标记和 spec.json 里冻结的 bug_if 条件，得出三种结论之一。

  已复现   两臂都到达目标行；bug_if 对 malicious 臂为真、对 benign 臂为假；两臂至少有一个数值/布尔 key 不同
  不成立   benign 臂到达、malicious 臂被守卫拦下（BLOCKED_AT 指向 evidence 中真实存在的守卫）
  未能复现 其余一切：构建失败、超时、缺标记、前置条件未建立、两臂无区分、条件不成立
"""
import re

VERDICTS = ('已复现', '不成立', '未能复现')
ARM_RE = re.compile(r'^\s*ARM=(benign|malicious)\s+(.*)$')
# 耗时、内存、时间戳一类每次都会变的 key，以及临时目录、随机数一类的值，不参与判定和稳定性比对
VOLATILE_KEY_RE = re.compile(r'(elapsed|duration|latency|_ms$|_ns$|_us$|_sec$|seconds|time|mem|alloc|rss|heap)', re.I)
VOLATILE_VAL_RE = re.compile(r'(/tmp/|/var/folders/|TestRepro_\w+\d{6,}|\d{9,})')


def stable_result(result):
    return {k: v for k, v in result.items() if not VOLATILE_KEY_RE.search(k) and not VOLATILE_VAL_RE.search(v)}


def parse_markers(output):
    arms, lines = {}, []
    for raw in output.splitlines():
        m = ARM_RE.match(raw)
        if not m:
            continue
        arm, rest = m.group(1), m.group(2).strip()
        a = arms.setdefault(arm, {'reached': None, 'blocked_at': None, 'result': {}, 'observed': None})
        lines.append(raw.strip())
        if rest.startswith('REACHED='):
            kv = dict(p.split('=', 1) for p in rest.split() if '=' in p)
            a['reached'], a['blocked_at'] = kv.get('REACHED'), kv.get('BLOCKED_AT')
        elif rest.startswith('RESULT'):
            a['result'] = stable_result(dict(p.split('=', 1) for p in rest[len('RESULT'):].split() if '=' in p))
        elif rest.startswith('OBSERVED='):
            a['observed'] = rest.split('=', 1)[1].strip()
    return arms, lines


def scalar(v):
    """字符串 → 数值/布尔；转不了返回 None（字符串标签不参与比较）"""
    s = str(v).strip().lower()
    if s in ('true', 'false'):
        return s == 'true'
    try:
        return float(s)
    except ValueError:
        return None


def eval_bug_if(pred, result):
    """返回 True/False；key 缺失或不可比较返回 None"""
    if not pred or not isinstance(pred, dict):
        return None
    lhs, rhs = scalar(result.get(pred.get('key'))), scalar(pred.get('value'))
    if lhs is None or rhs is None:
        return None
    op = pred.get('op')
    return {'>': lhs > rhs, '>=': lhs >= rhs, '<': lhs < rhs, '<=': lhs <= rhs, '==': lhs == rhs, '!=': lhs != rhs}.get(op)


def measurable_difference(a, b):
    """两臂的 RESULT 是否在某个数值/布尔 key 上不同（只在字符串标签上不同不算）"""
    for k in set(a) | set(b):
        x, y = scalar(a.get(k, '')), scalar(b.get(k, ''))
        if x is not None and y is not None and x != y:
            return True
    return False


STATUS_KEYS = ('status', 'status_code', 'http_status', 'code')


def rejected_status(result):
    """RESULT 里的 HTTP 状态码为 4xx/5xx：请求被拒，无论测试自己打了什么 REACHED。"""
    for k in STATUS_KEYS:
        v = scalar(result.get(k))
        if isinstance(v, float) and 400 <= v < 600:
            return int(v)
    return None


def line_of(loc):
    try:
        return int(str(loc).rsplit(':', 1)[1])
    except (ValueError, IndexError):
        return None


def judge(run, guard_lines, bug_if=None, sink_lines=()):
    """run: dict(rc, output, timed_out, build_failed)；guard_lines: 守卫 'file:line' 集合；bug_if: spec.json 里冻结的条件；
    sink_lines: evidence 里的目标（sink）行号。"""
    if run.get('timed_out'):
        return '未能复现', 'timeout', {}, []
    if run.get('build_failed'):
        return '未能复现', 'build_failed', {}, []
    arms, lines = parse_markers(run.get('output', ''))
    b, m = arms.get('benign'), arms.get('malicious')
    if not b or not m or b['reached'] is None or m['reached'] is None:
        return '未能复现', 'markers_missing', arms, lines
    first_sink = min(sink_lines) if sink_lines else None
    for a in (b, m):
        if rejected_status(a['result']) is not None:  # 状态码压过标记：4xx/5xx 的臂视为未到达
            a['reached'] = 'no'
        elif a['reached'] == 'no' and first_sink and a['blocked_at'] and a['blocked_at'] != 'none':
            ln = line_of(a['blocked_at'])
            if ln is not None and ln >= first_sink:  # "拦截点"在目标行或其后：目标行已执行，之后返回错误不算被守卫拦下
                a['reached'] = 'yes'
    if b['reached'] != 'yes':
        return '未能复现', 'benign_not_reached', arms, lines
    if m['reached'] == 'no':
        if m['blocked_at'] and m['blocked_at'] != 'none' and m['blocked_at'] in guard_lines:
            return '不成立', 'blocked_by_known_guard', arms, lines
        return '未能复现', 'malicious_not_reached', arms, lines
    if not measurable_difference(b['result'], m['result']):
        return '未能复现', 'arms_indistinguishable', arms, lines
    pm, pb = eval_bug_if(bug_if, m['result']), eval_bug_if(bug_if, b['result'])
    if pm is None or pb is None:
        return '未能复现', 'bug_if_not_evaluable', arms, lines
    if pm and not pb:
        return '已复现', 'bug_if_holds_on_malicious_only', arms, lines
    if pm and pb:
        return '未能复现', 'benign_also_bug', arms, lines
    return '未能复现', 'no_bug_observed', arms, lines
