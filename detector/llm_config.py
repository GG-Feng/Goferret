"""Shared LLM configuration.

Loads .env and resolves the active provider (LLM_PROVIDER) into unified
LLM_API_KEY / LLM_BASE_URL / LLM_MODEL so every script reads the same three
keys. Switch providers by editing LLM_PROVIDER in .env — no code change.

    LLM_PROVIDER=deepseek
    DEEPSEEK_API_KEY=sk-...
    DEEPSEEK_BASE_URL=https://api.deepseek.com
    DEEPSEEK_MODEL=deepseek-v4-pro

Each provider's BASE_URL is stored so that ``BASE_URL + '/chat/completions'``
is the correct endpoint (ARK's coding endpoint therefore includes the /v1
segment).
"""

import os
import sys

# provider name -> (api_key_var, base_url_var, model_var) in .env
PROVIDER_VARS = {
    'deepseek':   ('DEEPSEEK_API_KEY',   'DEEPSEEK_BASE_URL',   'DEEPSEEK_MODEL'),
    'zhipu':      ('ZHIPUAI_API_KEY',    'ZHIPU_BASE_URL',      'ZHIPU_MODEL'),
    'ark':        ('ARK_API_KEY',        'ARK_BASE_URL',        'ARK_MODEL'),
    'openai':     ('OPENAI_API_KEY',     'OPENAI_BASE_URL',     'OPENAI_MODEL'),
    'moonshot':   ('MOONSHOT_API_KEY',   'MOONSHOT_BASE_URL',   'MOONSHOT_MODEL'),
    'qwen':       ('DASHSCOPE_API_KEY',  'DASHSCOPE_BASE_URL',  'DASHSCOPE_MODEL'),
    'anthropic':  ('ANTHROPIC_API_KEY',  'ANTHROPIC_BASE_URL',  'ANTHROPIC_MODEL'),
    'google':     ('GOOGLE_API_KEY',     'GOOGLE_BASE_URL',     'GOOGLE_MODEL'),
    'openrouter': ('OPENROUTER_API_KEY', 'OPENROUTER_BASE_URL', 'OPENROUTER_MODEL'),
}

DEFAULT_PROVIDER = 'deepseek'


def load_env():
    """Parse .env into a dict and resolve the active LLM provider."""
    cfg = {}
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if not os.path.isfile(env_path):
        print("Error: .env file not found", file=sys.stderr)
        sys.exit(1)
    with open(env_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                cfg[k.strip()] = v.strip()

    resolve_llm(cfg)
    return cfg


def resolve_llm(cfg):
    """Resolve LLM_PROVIDER into unified LLM_API_KEY/LLM_BASE_URL/LLM_MODEL.

    Mutates cfg in place, adding the three unified keys. Unknown or missing
    LLM_PROVIDER falls back to DEFAULT_PROVIDER.
    """
    provider = cfg.get('LLM_PROVIDER', '').strip().lower() or DEFAULT_PROVIDER
    if provider not in PROVIDER_VARS:
        print(f"Warning: unknown LLM_PROVIDER={provider}, falling back to "
              f"{DEFAULT_PROVIDER}", file=sys.stderr)
        provider = DEFAULT_PROVIDER
    key_var, base_var, model_var = PROVIDER_VARS[provider]
    cfg['LLM_PROVIDER'] = provider
    cfg['LLM_API_KEY'] = cfg.get(key_var, '')
    cfg['LLM_BASE_URL'] = cfg.get(base_var, '')
    cfg['LLM_MODEL'] = cfg.get(model_var, '')
