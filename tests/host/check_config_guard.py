#!/usr/bin/env python3
"""Checks the config web UI's access checks and the AT command value checks.

    python tests/host/check_config_guard.py

1. Builds tests/host/config_guard_runner.c with gcc (or set CC) against
   ml_config_guard.c and ml_at_validate.c, and runs it on:
   - the Host header check (DNS rebinding): only the local IPv4 address,
     optionally with a port; no host names, also not hex-only ones such as
     "deadbeef.cafe", which passed upstream's first version;
   - HTTP Basic auth: right and wrong passwords, any user name, padding,
     bad base64, other schemes, an empty password;
   - the Content-Type check (CSRF): application/json only;
   - IPv4-mapped IPv6 local addresses (LWIP_IPV6 is on by default);
   - the APN, SIM PIN, host name and PPP credential checks, including the
     injections from the audit (x"\\r\\nAT+CFUN=0 as APN or control host).
2. Reads the source for the wiring the runner can't see: every HTTP handler
   starts with the access check (POST/DELETE with the JSON check), every
   string loaded from NVS is terminated, the page escapes what it puts into
   innerHTML and sends JSON on every POST, and each value is checked before
   it is put into AT+CPIN, AT+CGDCONT, AT+CGAUTH or AT+CDNSGIP.
   If node is installed, the page's script is also syntax-checked.

Exits 1 and lists each problem otherwise.
"""
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
COMP = os.path.join(HERE, '..', '..', 'components', 'tailtiny')
SRC = os.path.join(COMP, 'src')
CC = os.environ.get('CC', 'gcc')
EXE = '.exe' if os.name == 'nt' else ''

LOCAL_IP = (100 << 24) | (64 << 16) | 1     # 100.64.0.1, host byte order


def hx(s):
    if isinstance(s, str):
        s = s.encode('utf-8')
    return s.hex() if s else '-'


def basic(user_pass, scheme='Basic ', pad=True):
    if isinstance(user_pass, str):
        user_pass = user_pass.encode('utf-8')
    tok = base64.b64encode(user_pass).decode()
    return scheme + (tok if pad else tok.rstrip('='))


# ---------------------------------------------------------------------------
# 1. Runner cases: (runner line, expected output line, description)
# ---------------------------------------------------------------------------

def param(kind, s, expect, maxlen=0, what=None):
    return (f'param {kind} {hx(s)} {maxlen}', '1' if expect else '0',
            what or f'{kind}({s!r}, max {maxlen}) is {"accepted" if expect else "refused"}')


def cases():
    c = []
    # Baseline: anything inside a quoted AT argument
    c += [param('safe', '', True, 10), param('safe', "abc def!#$%&'()*+,-./:;<=>?@[]^_`{|}~", True, 64),
          param('safe', 'a"b', False, 10), param('safe', 'a\\22b', False, 10),
          param('safe', 'a\rAT+CFUN=0', False, 64), param('safe', 'a\nb', False, 10),
          param('safe', 'a\x1a', False, 10), param('safe', 'a\x1b', False, 10),
          param('safe', 'café', False, 10), param('safe', 'a\x7f', False, 10),
          param('safe', '12345', True, 5), param('safe', '123456', False, 5)]
    c.append(('null safe', '0', 'a NULL string is refused'))

    # APN (3GPP TS 23.003: LDH labels, max 100)
    for ok in ['', 'internet', 'america.bics', 'fast.t-mobile.com', 'iot.1nce.net', 'TM', 'a' * 63]:
        c.append(param('apn', ok, True))
    for bad in ['x"\r\nAT+CFUN=0', 'x"\rAT+CFUN=0\r', 'a;b', 'a b', 'a_b', '.internet', 'internet.',
                'a..b', '-a', 'a-.b', 'a' * 64]:
        c.append(param('apn', bad, False))
    long_apn = ''.join('.' if i % 10 == 9 else 'a' for i in range(101))
    c.append(param('apn', long_apn, False, what='an APN over 100 characters is refused'))
    c.append(param('apn', long_apn[:99] + 'a', True, what='an APN of 100 characters is accepted'))
    c += [param('apn', 'abcd', True, 4), param('apn', 'abcde', False, 4),
          param('apn', 'a' * 31, True, 31), param('apn', 'a' * 32, False, 31,
                                                  'an APN too long for the NVS field is refused, not cut')]
    c.append(('null apn', '0', 'a NULL APN is refused'))

    # SIM PIN: 4-8 digits
    for ok in ['1234', '12345678']:
        c.append(param('pin', ok, True))
    for bad in ['123', '123456789', '', '12a4', '1234"', '1234\r', ' 1234', '1234";+CFUN=0']:
        c.append(param('pin', bad, False))

    # Host names (control host, DERP hosts before AT+CDNSGIP)
    for ok in ['controlplane.tailscale.com', 'derp1f.tailscale.com', 'localhost', '1.2.3.4',
               'hs-1.example.org']:
        c.append(param('host', ok, True))
    for bad in ['', 'a"b', 'evil.com"\r\nAT+CFUN=0', 'a b.com', 'a_b.com', 'a;b', 'host:443',
                '2001:db8::1', '-a.com', 'a-.com', 'a..com', 'a.com.', 'https://a.com']:
        c.append(param('host', bad, False))
    big = list('a' * 299)
    for i in range(50, 299, 50):
        big[i] = '.'
    c.append(param('host', ''.join(big), False, what='a host name over 253 characters is refused'))
    c.append(param('host', 'abcdef', False, 5))
    c.append(param('host', 'a' * 63, True, 63, 'a 63-character control host fits the NVS field'))
    c.append(param('host', 'a' * 64, False, 63, 'a 64-character control host is refused, not cut'))
    c.append(param('host', 'a.' * 120 + 'bc', True, 242, 'a 242-character host fits AT+CDNSGIP'))
    c.append(param('host', 'a.' * 121 + 'b', False, 242, 'a 243-character host is refused for AT+CDNSGIP'))

    # PPP credentials: printable ASCII without '"' or '\'
    for ok in ['', 'sora', 'p@ss;w,rd with space']:
        c.append(param('cred', ok, True))
    for bad in ['pa"ss', 'pa\\ss', 'pa\r\nss', 'pa\tss', 'x","",""\r\nAT+CFUN=0']:
        c.append(param('cred', bad, False))
    c.append(param('cred', '0' * 31, True, 31))
    c.append(param('cred', '0' * 32, False, 31, 'a 32-character PPP value is refused for the 31-character field'))
    c.append(param('cred', 'x' * 64, True, what='a 64-character Kconfig PPP value is accepted'))
    c.append(param('cred', 'x' * 65, False, what='a 65-character PPP value is refused'))

    # Host header (DNS rebinding)
    def host(h, expect, ip=LOCAL_IP):
        return (f'hosthdr {hx(h)} {ip}', '1' if expect else '0',
                f'Host {h!r} is {"accepted" if expect else "refused"} for 100.64.0.1')
    for ok in ['100.64.0.1', '100.64.0.1:80', '100.64.0.1:8080', '100.64.0.1:65535', '100.64.0.1 ']:
        c.append(host(ok, True))
    for bad in ['100.64.0.2', 'deadbeef.cafe', 'cafe', '100.64.0.1.nip.io', 'evil.com', 'device.tail1234.ts.net',
                '100.64.0.1:', '100.64.0.1:65536', '100.64.0.1:123456', '100.64.0.1:80x', '100.64.0.01',
                '100.64.1', '100.64.0.1.', '0x64.0x40.0.1', '1681915905', '[::ffff:100.64.0.1]',
                '[::ffff:6440:1]', '', '100.64.0.256', '1000.64.0.1', '100.64.0.1 evil.com',
                '100.64.0.1@evil.com']:
        c.append(host(bad, False))
    c.append((f'hosthdr {hx("0.0.0.0")} 0', '0', 'no local address: nothing matches'))
    c.append((f'hosthdr {hx("192.168.1.20")} {(192 << 24) | (168 << 16) | (1 << 8) | 20}', '1',
              'a LAN address (ALLOW_LAN) matches itself'))

    # HTTP Basic auth
    pw = 's3cret-PW'

    def auth(h, expect, what, password=pw):
        return (f'auth {hx(h)} {hx(password)}', '1' if expect else '0', what)
    c += [
        auth(basic('admin:' + pw), True, 'the right password is accepted'),
        auth(basic('admin:' + pw, 'basic '), True, 'the scheme name is case-insensitive'),
        auth(basic('admin:' + pw, 'BASIC   ') + '  ', True, 'extra blanks around the token are fine'),
        auth(basic('admin:' + pw, pad=False), True, 'an unpadded token is accepted'),
        auth(basic('bob:' + pw), True, 'the user name is not checked'),
        auth(basic(':' + pw), True, 'an empty user name is fine'),
        auth(basic('admin:a:b'), True, 'the password is everything after the first colon', 'a:b'),
        auth(basic('admin:pässwörd'), True, 'a UTF-8 password works', 'pässwörd'),
        auth(basic('admin:s3cret-pw'), False, 'a wrong password is refused'),
        auth(basic('admin:s3cret-P'), False, 'a prefix of the password is refused'),
        auth(basic('admin:' + pw + 'x'), False, 'a longer password is refused'),
        auth(basic(b'admin:' + pw.encode() + b'\0'), False, 'a trailing NUL byte is refused'),
        auth(basic('admins3cret-PW'), False, 'a token without a colon is refused'),
        auth('Bearer ' + base64.b64encode(b'admin:' + pw.encode()).decode(), False, 'another scheme is refused'),
        auth('Basic', False, 'no token is refused'),
        auth('Basic ', False, 'an empty token is refused'),
        auth('Basic' + base64.b64encode(b'admin:' + pw.encode()).decode(), False, 'a scheme without a blank is refused'),
        auth('Basic YWRt!W4=', False, 'bad base64 is refused'),
        auth('Basic YW=Rt', False, 'padding in the middle is refused'),
        auth('Basic YWRtaW', False, 'a token of 4n+1 characters is refused'),
        auth('Basic YQ=', False, 'wrong padding is refused'),
        auth(basic('admin:' + pw) + ' junk', False, 'text after the token is refused'),
        auth(basic('admin:'), False, 'an empty password never matches', ''),
        auth(basic('admin:' + 'x' * 300), False, 'an oversized token is refused', 'x' * 300),
    ]

    # Content-Type (CSRF)
    for ok in ['application/json', 'application/json; charset=utf-8', 'Application/JSON', 'application/json ',
               'application/json;charset=UTF-8']:
        c.append((f'ctype {hx(ok)}', '1', f'Content-Type {ok!r} is accepted'))
    for bad in ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x',
                'application/jsonp', 'application/json-patch+json', '', 'text/plain; application/json',
                'application/jso']:
        c.append((f'ctype {hx(bad)}', '0', f'Content-Type {bad!r} is refused'))

    # IPv4-mapped IPv6 local addresses
    mapped = bytes(10) + b'\xff\xff' + bytes([100, 64, 0, 1])
    c.append((f'mapped {mapped.hex()}', f'1 {LOCAL_IP}', '::ffff:100.64.0.1 unwraps to 100.64.0.1'))
    c.append((f'mapped {(bytes(15) + b"1").hex()}', '0', '::1 is refused'))
    c.append(('mapped fd7a115ca1e000000000000000000001', '0', 'a native tailnet IPv6 address is refused'))
    c.append((f'mapped {(bytes(12) + bytes([100, 64, 0, 1])).hex()}', '0', '::100.64.0.1 (v4-compatible) is refused'))

    c.append(('zero', '1', 'ml_at_secure_zero() clears the buffer'))
    return c


def run_runner():
    problems = []
    cs = cases()
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, 'config_guard_runner' + EXE)
        subprocess.run([CC, '-O1', '-Wall', '-Wextra', '-Werror', '-std=c11', '-I', SRC,
                        os.path.join(HERE, 'config_guard_runner.c'),
                        os.path.join(SRC, 'ml_config_guard.c'), os.path.join(SRC, 'ml_at_validate.c'),
                        '-o', exe], check=True)
        stdin = ''.join(line + '\n' for line, _, _ in cs)
        out = subprocess.run([exe], input=stdin, capture_output=True, text=True, timeout=60)
    got = out.stdout.splitlines()
    if out.returncode != 0 or len(got) != len(cs):
        return [f'runner failed (exit {out.returncode}, {len(got)} of {len(cs)} answers): {out.stderr.strip()}']
    for (_, want, what), have in zip(cs, got):
        if have.strip() != want:
            problems.append(f'{what}: got {have.strip()!r}, want {want!r}')
    print(f'runner: {len(cs) - len(problems)}/{len(cs)} cases passed')
    return problems


# ---------------------------------------------------------------------------
# 2. Source wiring
# ---------------------------------------------------------------------------

def read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def strip_comments(text):
    """C source without comments; string literals are kept as they are."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch in '"\'':
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == '\\' else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith('/*', i):
            i = text.index('*/', i) + 2
            out.append(' ')
        elif text.startswith('//', i):
            i = text.find('\n', i)
            i = n if i < 0 else i
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def function_body(code, name):
    """Body of the C function @name (between its outer braces), or None."""
    m = re.search(r'\n[\w \*]*\b' + re.escape(name) + r'\s*\([^;{]*\)\s*\{', code)
    if not m:
        return None
    depth, i = 0, m.end() - 1
    for j in range(i, len(code)):
        if code[j] == '{':
            depth += 1
        elif code[j] == '}':
            depth -= 1
            if depth == 0:
                return code[i + 1:j]
    return None


def c_page(path):
    """The page as the browser gets it: CONFIG_PAGE_HTML's string literals joined."""
    code = strip_comments(read(path))
    code = code[code.index('CONFIG_PAGE_HTML'):]
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', code)
    esc = {'"': '"', '\\': '\\', "'": "'", 'n': '\n', 't': '\t'}
    return ''.join(re.sub(r'\\(.)', lambda m: esc.get(m.group(1), '\\' + m.group(1)), p) for p in parts)


def check_wiring():
    problems = []

    def expect(cond, what):
        if not cond:
            problems.append(what)

    httpd = strip_comments(read(os.path.join(SRC, 'ml_config_httpd.c')))

    # Every registered handler starts with the access check; POST and DELETE
    # also require JSON.
    table = re.findall(r'\.method\s*=\s*HTTP_(\w+)\s*,\s*\.handler\s*=\s*(\w+)', httpd)
    expect(len(table) >= 12, f'expected the 12 URI handlers in the table, found {len(table)}')
    for method, handler in table:
        body = function_body(httpd, handler)
        if body is None:
            problems.append(f'{handler}: definition not found')
            continue
        first = body.strip().split(';')[0]
        mutating = 'true' if method in ('POST', 'DELETE', 'PUT', 'PATCH') else 'false'
        expect(re.fullmatch(r'if \(!http_guard\(req, ' + mutating + r'\)\) return ESP_OK', first.strip()),
               f'{handler} ({method}) must start with http_guard(req, {mutating}), starts with: {first.strip()[:60]}')

    guard = function_body(httpd, 'http_guard') or ''
    order = ['local_addr_allowed', 'ml_config_host_is_local_ip', 'ml_config_basic_auth_ok',
             'ml_config_content_type_is_json']
    pos = [guard.find(x) for x in order]
    expect(all(p >= 0 for p in pos) and pos == sorted(pos),
           'http_guard checks interface, Host, auth, then Content-Type')
    local = function_body(httpd, 'local_addr_allowed') or ''
    expect('tailtiny_get_vpn_ip' in local and not re.search(r'0x64400000|0xFFC00000', local, re.I),
           'local_addr_allowed compares with the VPN address, not with 100.64.0.0/10')
    expect('LWIP_IPV6' in (function_body(httpd, 'request_local_ipv4') or '') and
           'ml_config_ipv4_from_mapped' in httpd, 'IPv4-mapped local addresses are unwrapped')

    # Every NVS string read is terminated right after it
    for m in re.finditer(r'nvs_get_blob\([^;]*\bNVS_KEY_(SETTINGS|WIFI|PEERS)\b\s*,\s*([^,]+),', httpd):
        key, buf = m.group(1), m.group(2).strip()
        if buf == 'NULL':
            continue
        if key == 'PEERS' and buf == 'tmp':
            continue          # the old format, copied into peer_list below
        want = {'SETTINGS': 'terminate_settings_strings', 'WIFI': 'terminate_wifi_list_strings',
                'PEERS': 'terminate_peer_labels'}[key]
        window = httpd[m.end():m.end() + 700]
        expect(want in window, f'nvs_get_blob(NVS_KEY_{key}, {buf}) is followed by {want}()')
    expect(re.search(r'nvs_get_str\(ctx->nvs, NVS_KEY_HTTP_PW', httpd), 'the generated password is kept in NVS')

    # The settings POST checks the AT/host fields before changing anything
    post = function_body(httpd, 'handler_post_settings') or ''
    first_copy = post.find('COPY_STR_FIELD(ctx->settings')
    for chk in ('check_cellular_apn', 'check_ppp_user', 'check_ppp_pass', 'check_ctrl_host'):
        i = post.find(chk)
        expect(0 <= i < first_copy, f'handler_post_settings calls {chk} before changing a field')
    expect('cellular_sim_pin' not in post.replace('"cellular_sim_pin" is ignored', ''),
           'handler_post_settings no longer stores a SIM PIN')
    expect('check_cellular_apn' in (function_body(httpd, 'ml_config_get_nvs_apn') or ''),
           'ml_config_get_nvs_apn refuses an invalid saved APN')
    ppp = function_body(httpd, 'ml_config_get_nvs_ppp') or ''
    expect('check_ppp_user' in ppp and 'check_ppp_pass' in ppp,
           'ml_config_get_nvs_ppp refuses invalid saved PPP credentials')
    expect('check_ctrl_host' in (function_body(httpd, 'ml_config_get_ctrl_host') or ''),
           'ml_config_get_ctrl_host refuses an invalid control host')
    expect('config_sanitize_settings' in (function_body(httpd, 'config_load_settings') or ''),
           'config_load_settings sanitises older settings')

    # The page: escaped innerHTML, JSON on every state-changing fetch, no SIM PIN
    page = c_page(os.path.join(SRC, 'ml_config_html.h'))
    script = page[page.index('<script>') + 8:page.index('</script>')]
    expect('function esc(' in script, 'the page defines esc()')
    for line in re.split(r'(?<=;)', script):
        if '<' not in line:
            continue        # not building HTML
        for expr in re.findall(r"'\+(.+?)\+'", line):
            expect(expr.startswith('esc(') or re.fullmatch(r'\(?i(\+1)?\)?', expr),
                   f'page puts {expr!r} into HTML without esc()')
    for m in re.finditer(r"fetch\('([^']+)',\{method:'(POST|DELETE|PUT)'([^}]*\})", script):
        expect("'Content-Type':'application/json'" in m.group(3),
               f"fetch {m.group(2)} {m.group(1)} sends Content-Type: application/json")
    expect('cellular_sim_pin' not in page, 'the page has no SIM PIN field')

    # Each value is checked where it goes into an AT command
    cell = strip_comments(read(os.path.join(SRC, 'ml_cellular.c')))
    sim = function_body(cell, 'sim_setup') or ''
    expect(0 <= sim.find('ml_at_valid_pin') < sim.find('AT+CPIN=\\"'), 'sim_setup checks the PIN before AT+CPIN=')
    dial = function_body(cell, 'ppp_setup_and_dial') or ''
    expect(0 <= dial.find('ml_at_valid_apn') < dial.find('AT+CGDCONT='), 'the APN is checked before AT+CGDCONT')
    expect(0 <= dial.find('ml_at_valid_credential') < dial.find('AT+CGAUTH='),
           'the PPP login is checked before AT+CGAUTH')
    expect(re.search(r'auth_len\s*>=\s*sizeof\(auth_cmd\)|\(size_t\)auth_len >= sizeof\(auth_cmd\)', dial),
           'an AT+CGAUTH that does not fit is refused, not cut')
    init = function_body(cell, 'ml_cellular_init') or ''
    first_uart = init.find('uart_init()')
    for chk in ('ml_at_valid_apn', 'ml_at_valid_pin', 'ml_at_valid_credential'):
        expect(0 <= init.find(chk) < first_uart, f'ml_cellular_init calls {chk} before touching the UART')

    sock = strip_comments(read(os.path.join(SRC, 'ml_at_socket.c')))
    gai = function_body(sock, 'ml_at_getaddrinfo') or ''
    m = re.search(r'if \(!ml_at_param_valid\(ML_AT_PARAM_HOSTNAME, hostname,[^{;]*\{[^}]*return EAI_NONAME;', gai)
    expect(m and m.start() < gai.find('AT+CDNSGIP='),
           'ml_at_getaddrinfo refuses an invalid host name before AT+CDNSGIP')

    cmake = read(os.path.join(COMP, 'CMakeLists.txt'))
    for f in ('src/ml_at_validate.c', 'src/ml_config_guard.c'):
        expect(f in cmake, f'{f} is in CMakeLists.txt')

    # Optional: the page's script parses
    node = shutil.which('node')
    if node:
        with tempfile.TemporaryDirectory() as tmp:
            js = os.path.join(tmp, 'page.js')
            with open(js, 'w', encoding='utf-8') as f:
                f.write(script)
            r = subprocess.run([node, '--check', js], capture_output=True, text=True)
            expect(r.returncode == 0, f'the page script parses: {r.stderr.strip()[:300]}')
    else:
        print('wiring: node not found, page script syntax not checked')

    print(f'wiring: {"no" if not problems else len(problems)} problem(s)')
    return problems


def main():
    problems = run_runner() + check_wiring()
    for p in problems:
        print('FAIL ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
