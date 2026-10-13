#!/usr/bin/env python3
"""Host tests for ml_json_strip.c, checked against Python's json module.

    python tests/host/run_tests.py

Needs gcc (or set CC). Builds two tiny runners and fuzzes them with random,
deliberately awkward JSON: nested values, braces and quotes inside strings,
escapes, listed keys used as values, random whitespace, truncated input.
"""
import json, os, random, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', '..', 'components', 'tailtiny', 'src', 'ml_json_strip.c')
INC = os.path.join(HERE, '..', '..', 'components', 'tailtiny', 'include')
CC = os.environ.get('CC', 'gcc')
EXE = '.exe' if os.name == 'nt' else ''
KEYS = {"Hostinfo", "CapMap", "PacketFilter", "Drop"}   # must match strip_runner.c
TRICKY = ['a{b}c', 'q"uote', 'back\\slash', '"Hostinfo":1', '}{][,:', '\u00fcn\u00ef', 'Drop', '\n\t']


def build(name):
    out = os.path.join(HERE, name + EXE)
    subprocess.run([CC, '-O1', '-Wall', '-Wextra', '-I', INC, os.path.join(HERE, name + '.c'), SRC, '-o', out], check=True)
    return out


def rnd_key():
    return random.choice(sorted(KEYS) + ['Name', 'Key', 'Peers', 'x', 'HostinfoX', 'Cap', '']) if random.random() < 0.9 else random.choice(TRICKY)


def rnd(d=0):
    t = random.random()
    if d > 5 or t < 0.3:
        return random.choice([None, True, False, 0, -1.5e3, 42, random.choice(TRICKY), ''])
    if t < 0.65:
        return {rnd_key(): rnd(d + 1) for _ in range(random.randint(0, 6))}
    return [rnd(d + 1) for _ in range(random.randint(0, 5))]


def strip(v):
    if isinstance(v, dict):
        return {k: strip(x) for k, x in v.items() if k not in KEYS}
    if isinstance(v, list):
        return [strip(x) for x in v]
    return v


def dump(v):
    if random.random() < 0.5:
        return json.dumps(v, ensure_ascii=random.random() < 0.5, separators=(',', ':'))
    return json.dumps(v, ensure_ascii=False, indent=random.choice([None, 1, 2]))


def run(exe, text):
    inp, out = os.path.join(HERE, 'in.json'), os.path.join(HERE, 'out.bin')
    open(inp, 'w', encoding='utf-8').write(text)
    subprocess.run([exe, inp, out], check=True)
    return open(out, 'rb').read().decode('utf-8')


def main(n=3000):
    random.seed(1)
    strip_exe, iter_exe = build('strip_runner'), build('iter_runner')
    fails = 0
    for _ in range(n):
        v = rnd() if random.random() < 0.5 else {"Node": rnd(), "Peers": rnd(), random.choice(sorted(KEYS)): rnd()}
        try:
            ok = json.loads(run(strip_exe, dump(v))) == strip(v)
        except ValueError:
            ok = False
        fails += not ok
    print(f'strip: {n - fails}/{n} match Python')

    src = json.dumps({"Node": {"Key": "k", "Hostinfo": {"a": [1, {"b": "}{"}]}}, "Peers": [{"CapMap": {"x": None}, "E": ["1.2.3.4:5"]}] * 3, "Tail": "e\\\"q"})
    for cut in range(len(src) + 1):
        assert len(run(strip_exe, src[:cut])) <= cut
    print(f'strip: {len(src) + 1} truncated inputs, no crash, never longer than input')

    ifails = 0
    for _ in range(n):
        v = {('k%d' % j if random.random() < .7 else random.choice(TRICKY) + str(j)): rnd() for j in range(random.randint(0, 7))}
        raw = run(iter_exe, json.dumps(v, ensure_ascii=random.random() < .5, indent=random.choice([None, 1])))
        got = []
        for part in raw.split('\x02')[:-1]:
            k, val = part.split('\x01', 1)
            got.append((json.loads('"' + k + '"'), json.loads(val)))
        ifails += got != list(v.items())
    print(f'members: {n - ifails}/{n} match Python')
    for f in ('in.json', 'out.bin', 'strip_runner' + EXE, 'iter_runner' + EXE):
        try:
            os.remove(os.path.join(HERE, f))
        except OSError:
            pass
    return 1 if fails or ifails else 0


if __name__ == '__main__':
    sys.exit(main())
