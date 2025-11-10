import json
import os

def load_rules(rules_path='analyzers/rules/strings.json'):
    if not os.path.exists(rules_path):
        raise FileNotFoundError(f"Rules file not found: {rules_path}")
    
    with open(rules_path, 'r', encoding='utf-8') as f:
        rules = json.load(f)
    return rules
