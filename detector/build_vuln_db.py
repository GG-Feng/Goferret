"""
Build a vulnerability pattern database from extracted behavior chains.

Reads all behavior_chains/*.json, groups by (primary_domain, missing_step_category)
into pattern templates, and builds indices for efficient retrieval.

Usage:
    python build_vuln_db.py
    python build_vuln_db.py --input-dir behavior_chains --output vuln_db.json
"""

import json
import os
import sys
import argparse
from collections import defaultdict
from datetime import datetime


def load_behavior_chains(input_dir):
    """Load all valid behavior chain JSON files."""
    chains = []
    for f in sorted(os.listdir(input_dir)):
        if not f.endswith('.json'):
            continue
        path = os.path.join(input_dir, f)
        try:
            with open(path, encoding='utf-8') as fh:
                data = json.load(fh)
            if 'error' in data:
                continue
            if 'behavior_chain' not in data:
                continue
            chains.append(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    return chains


def extract_evidence_apis(chain):
    """Extract all API names from a behavior chain's evidence fields."""
    apis = set()
    for step in chain.get('behavior_chain', {}).get('steps', []):
        evidence = step.get('evidence', {})
        for api in evidence.get('apis', []):
            apis.add(api)
    return apis


def extract_evidence_functions(chain):
    """Extract all function names from evidence."""
    funcs = set()
    for step in chain.get('behavior_chain', {}).get('steps', []):
        evidence = step.get('evidence', {})
        for f in evidence.get('functions', []):
            funcs.add(f)
    return funcs


def find_missing_step(chain):
    """Find the missing step in a behavior chain."""
    for step in chain.get('behavior_chain', {}).get('steps', []):
        if step.get('is_missing_step'):
            return step
    return None


def build_templates(chains):
    """Group chains by (domain, category) and build templates."""
    groups = defaultdict(list)
    for chain in chains:
        domain = chain.get('primary_domain', 'Unknown')
        missing = find_missing_step(chain)
        if not missing:
            continue
        category = missing.get('missing_step_category', 'unknown')
        groups[(domain, category)].append(chain)

    templates = {}
    for (domain, category), group_chains in sorted(groups.items()):
        tpl_id = f"tpl_{len(templates) + 1:03d}"

        # Aggregate API indicators
        api_counter = defaultdict(int)
        for c in group_chains:
            for api in extract_evidence_apis(c):
                api_counter[api] += 1
        top_apis = [api for api, _ in sorted(api_counter.items(), key=lambda x: -x[1])[:10]]

        # Collect action sequences (strip MISSING: prefix for comparison)
        action_sequences = []
        for c in group_chains:
            actions = []
            for step in c['behavior_chain']['steps']:
                action = step['action']
                if step.get('is_missing_step'):
                    action = f"MISSING: {step.get('missing_step_category', '')}"
                actions.append(action)
            action_sequences.append(actions)

        # Missing step position stats
        missing_positions = []
        for c in group_chains:
            for i, step in enumerate(c['behavior_chain']['steps']):
                if step.get('is_missing_step'):
                    missing_positions.append(step['step_id'])
                    break

        # CWE coverage
        cwes = set()
        for c in group_chains:
            for cwe in c.get('vulnerability_pattern', {}).get('cwe_alignment', []):
                cwes.add(cwe)

        # Pattern names
        pattern_names = set()
        for c in group_chains:
            pn = c.get('vulnerability_pattern', {}).get('pattern_name', '')
            if pn:
                pattern_names.add(pn)

        # Chain type distribution
        type_counter = defaultdict(int)
        for c in group_chains:
            ct = c['behavior_chain'].get('chain_type', 'unknown')
            type_counter[ct] += 1
        dominant_type = max(type_counter, key=type_counter.get) if type_counter else 'unknown'

        # Top examples by confidence
        sorted_chains = sorted(group_chains, key=lambda c: c.get('extraction_confidence', 0), reverse=True)
        top_examples = [
            {
                'go_id': c.get('go_id', ''),
                'pattern_name': c.get('vulnerability_pattern', {}).get('pattern_name', ''),
                'module': c.get('module_path', ''),
                'confidence': c.get('extraction_confidence', 0),
            }
            for c in sorted_chains[:5]
        ]

        templates[tpl_id] = {
            'template_id': tpl_id,
            'domain': domain,
            'missing_step_category': category,
            'chain_type': dominant_type,
            'summary': _build_summary(domain, category, group_chains),
            'api_indicators': top_apis,
            'cwe_coverage': sorted(cwes, key=str),
            'pattern_names': sorted(pattern_names),
            'example_count': len(group_chains),
            'missing_position_range': {
                'min': min(missing_positions) if missing_positions else 0,
                'max': max(missing_positions) if missing_positions else 0,
            },
            'top_examples': top_examples,
        }

    return templates


def _build_summary(domain, category, chains):
    """Build a one-line summary for a template group."""
    descriptions = []
    for c in chains[:3]:
        missing = find_missing_step(c)
        if missing:
            descriptions.append(missing.get('description', '')[:100])
    if descriptions:
        return descriptions[0]
    return f"Vulnerabilities in {domain} missing {category}"


def build_indices(templates):
    """Build lookup indices from templates."""
    domain_index = defaultdict(list)
    category_index = defaultdict(list)
    api_index = defaultdict(list)
    pattern_name_index = defaultdict(list)

    for tpl_id, tpl in templates.items():
        domain_index[tpl['domain']].append(tpl_id)
        category_index[tpl['missing_step_category']].append(tpl_id)
        for api in tpl['api_indicators']:
            api_index[api].append(tpl_id)
        for pn in tpl['pattern_names']:
            pattern_name_index[pn].append(tpl_id)

    return {
        'domain_index': dict(domain_index),
        'category_index': dict(category_index),
        'api_index': dict(api_index),
        'pattern_name_index': dict(pattern_name_index),
    }


def main():
    parser = argparse.ArgumentParser(description="Build vulnerability pattern database")
    parser.add_argument("--input-dir", default="behavior_chains", help="Directory with behavior chain JSONs")
    parser.add_argument("--output", default="vuln_db.json", help="Output database file")
    args = parser.parse_args()

    print(f"Loading behavior chains from {args.input_dir}...")
    chains = load_behavior_chains(args.input_dir)
    print(f"  Loaded {len(chains)} valid behavior chains")

    print("Building templates...")
    templates = build_templates(chains)
    print(f"  Created {len(templates)} templates")

    print("Building indices...")
    indices = build_indices(templates)
    print(f"  Domain index: {len(indices['domain_index'])} domains")
    print(f"  Category index: {len(indices['category_index'])} categories")
    print(f"  API index: {len(indices['api_index'])} APIs")

    # Domain coverage stats
    domain_coverage = defaultdict(int)
    for c in chains:
        d = c.get('primary_domain', 'Unknown')
        domain_coverage[d] += 1

    # Category coverage stats
    category_coverage = defaultdict(int)
    for c in chains:
        missing = find_missing_step(c)
        if missing:
            category_coverage[missing.get('missing_step_category', 'unknown')] += 1

    db = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'total_records': len(chains),
            'total_templates': len(templates),
            'domain_coverage': dict(domain_coverage),
            'category_coverage': dict(category_coverage),
        },
        **indices,
        'templates': templates,
        'full_records': {c.get('go_id', ''): c for c in chains},
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    print(f"\nDatabase written to {os.path.abspath(args.output)}")
    print(f"  {len(chains)} records → {len(templates)} templates")
    for tpl_id, tpl in sorted(templates.items()):
        print(f"  {tpl_id}: {tpl['domain']} / {tpl['missing_step_category']} "
              f"({tpl['example_count']} examples, APIs: {', '.join(tpl['api_indicators'][:3])})")


if __name__ == "__main__":
    main()
