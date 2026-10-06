"""最小 LLM 客户端：temperature 0，按输入哈希缓存。

只读 Goferret 的 .env（通过 llm_config.load_env），不改动 Goferret。
同样的 (model, system, user, max_tokens) 只会真正调用一次；之后直接返回缓存。
"""
import hashlib, json, os, re, sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(HERE, 'cache')
_cfg = None


def config(goferret_dir):
    global _cfg
    if _cfg is None:
        sys.path.insert(0, goferret_dir)
        import llm_config  # noqa: E402
        _cfg = llm_config.load_env()
    return _cfg


def chat(goferret_dir, system, user, max_tokens=8192):
    """返回 (content, meta)。meta 含 cached / resp_model / usage。"""
    c = config(goferret_dir)
    key = hashlib.sha256(json.dumps([c['LLM_MODEL'], system, user, max_tokens], ensure_ascii=False).encode()).hexdigest()
    os.makedirs(CACHE_DIR, exist_ok=True)
    cp = os.path.join(CACHE_DIR, key + '.json')
    if os.path.exists(cp):
        o = json.load(open(cp, encoding='utf-8'))
        return o['content'], dict(cached=True, resp_model=o.get('resp_model'), usage=o.get('usage'))
    payload = {
        'model': c['LLM_MODEL'],
        'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
        'temperature': 0,
        'max_tokens': max_tokens,
        'thinking': {'type': 'disabled'},
    }
    req = urllib.request.Request(
        c['LLM_BASE_URL'] + '/chat/completions', data=json.dumps(payload).encode(),
        headers={'Authorization': 'Bearer ' + c['LLM_API_KEY'], 'Content-Type': 'application/json'})
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                data = json.load(r)
            content = data['choices'][0]['message'].get('content') or ''
            o = dict(content=content, resp_model=data.get('model'), usage=data.get('usage'),
                     finish_reason=data['choices'][0].get('finish_reason'), key_inputs_sha256=key)
            json.dump(o, open(cp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
            return content, dict(cached=False, resp_model=o['resp_model'], usage=o['usage'])
        except urllib.error.HTTPError as e:
            last = f'HTTP {e.code}'
            if e.code != 429 and e.code < 500:
                break
        except Exception as e:  # 网络瞬断
            last = repr(e)
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(f'LLM 调用失败：{last}')


def parse_json(text):
    """去掉 ``` 围栏后解析 JSON；失败时取最外层花括号再试。"""
    t = text.strip()
    t = re.sub(r'^```\w*\n?', '', t)
    t = re.sub(r'\n?```$', '', t).strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        m = re.search(r'\{[\s\S]*\}', t)
        if m:
            return json.loads(m.group())
        raise
