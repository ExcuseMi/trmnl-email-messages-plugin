# Run: python3 -m pytest plugin/test
# Saved settings live under a field's key, in the shape of its type and options. Changing a type or dropping an
# option value loses what people saved (2026-10-25: six yes/no selects became switches and came up empty).
import json
import pathlib

import yaml

HERE = pathlib.Path(__file__).resolve().parent
LIVE = json.loads((HERE / 'live_settings_fields.json').read_text())['fields']
# Retired on purpose, with the owner: key -> why
RETIRED = {'read_subject_regular': 'owner 2026-10-25: subjects the same size whether read or unread'}


def current_fields():
    settings = yaml.safe_load((HERE.parent / 'src' / 'settings.yml').read_text())
    return {f['keyname']: f for f in settings['custom_fields']}


def option_values(field):
    return {str(list(o.values())[0]) if isinstance(o, dict) else str(o) for o in field.get('options') or []}


def test_every_live_field_keeps_its_key_type_and_option_values():
    current = current_fields()
    for key, live in LIVE.items():
        if key in RETIRED:
            continue
        assert key in current, f'{key}: removed, saved values would be lost'
        assert current[key]['field_type'] == live['field_type'], f'{key}: type changed, saved values would be lost'
        missing = set(live['options']) - option_values(current[key])
        assert not missing, f'{key}: option values {missing} removed, installs that chose them lose the choice'
