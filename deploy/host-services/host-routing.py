"""Owned IPv4 policy routes for the isolated host-service path."""
import ipaddress
import json

TABLE = 2480
INBOUND = '0x01000000'
OUTBOUND = '0x02000000'
MASK = '0x03000000'
KEEP = '0xfcffffff'


def rules():
    return [
        dict(priority=90, fwmark=INBOUND, fwmask=INBOUND, table=TABLE),
        dict(priority=91, fwmark=OUTBOUND, fwmask=OUTBOUND, table='main', suppress_prefixlen=0),
        dict(priority=92, fwmark=OUTBOUND, fwmask=OUTBOUND, table=TABLE),
    ]


def number(value):
    return int(str(value), 0)


def matches(row, expected):
    for key, value in expected.items():
        actual = row.get(key)
        if key in ('fwmark', 'fwmask'):
            if actual is None or number(actual) != number(value):
                return False
        elif key == 'table':
            if str(actual) != str(value) and (actual, value) != (254, 'main'):
                return False
        elif actual != value:
            return False
    # A rule with extra selectors is not ours.
    return all(key in expected or key in ('src', 'protocol') for key in row) and row.get('src', 'all') == 'all'


def rule_args(row):
    args = ['priority', str(row['priority']), 'fwmark', row['fwmark']+'/'+row['fwmask'],
            'lookup', str(row['table'])]
    if 'suppress_prefixlen' in row:
        args += ['suppress_prefixlength', str(row['suppress_prefixlen'])]
    return args


def check_available(policy, routes):
    if any(row.get('priority') in (90, 91, 92) or str(row.get('table')) == str(TABLE) for row in policy):
        raise ValueError('Host-service routing priorities 90-92/table 2480 already used')
    if any(str(row.get('table')) == str(TABLE) for row in routes):
        raise ValueError('Host-service routing table 2480 already used')


def route_plan(config):
    backend = ipaddress.IPv4Address(config['wan_backend'])
    network = ipaddress.IPv4Network(str(backend)+'/30', strict=False)
    if backend != network.network_address+2 or config['wan_host_interface'] != 'vpp-hostsvc':
        raise ValueError('Invalid host-service routing backend')
    host = str(ipaddress.IPv4Address(config['host']))
    return [
        ['unreachable', 'default', 'metric', '32767', 'table', str(TABLE)],
        ['default', 'via', str(network.network_address+1), 'dev', 'vpp-hostsvc',
         'onlink', 'src', host, 'metric', '100', 'table', str(TABLE)],
    ]


def owned_route(row, plan):
    if str(row.get('table')) != str(TABLE) or row.get('dst') != 'default':
        return False
    if row.get('type') == 'unreachable':
        return row.get('metric') == 32767
    route = plan[1]
    return (row.get('type', 'unicast') == 'unicast' and row.get('metric') == 100
            and row.get('gateway') == route[route.index('via')+1] and row.get('dev') == 'vpp-hostsvc'
            and row.get('prefsrc') == route[route.index('src')+1])


def install(config, execute, journal):
    plan = route_plan(config)
    policy = json.loads(execute('ip', '-j', '-4', 'rule', 'show'))
    routes = json.loads(execute('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
    if journal.exists():
        if json.loads(journal.read_text()) != plan:
            raise ValueError('Host-service routing journal configuration differs')
        for row in policy:
            if row.get('priority') in (90, 91, 92) or str(row.get('table')) == str(TABLE):
                if not any(matches(row, rule) for rule in rules()):
                    raise ValueError('Host-service routing policy was replaced')
        if any(str(row.get('table')) == str(TABLE) and not owned_route(row, plan) for row in routes):
            raise ValueError('Host-service routing table was replaced')
    else:
        check_available(policy, routes)
        # Record ownership before the first mutation, including partial startup.
        temporary = journal.with_suffix('.tmp')
        temporary.write_text(json.dumps(plan)+'\n')
        temporary.replace(journal)
    for route in plan:
        execute('ip', '-4', 'route', 'replace', *route)
    for rule in rules():
        if not any(matches(row, rule) for row in policy):
            execute('ip', '-4', 'rule', 'add', *rule_args(rule))


def remove(execute, journal):
    if not journal.exists():
        return
    plan = json.loads(journal.read_text())
    policy = json.loads(execute('ip', '-j', '-4', 'rule', 'show'))
    routes = json.loads(execute('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
    for rule in rules():
        if any(matches(row, rule) for row in policy):
            execute('ip', '-4', 'rule', 'del', *rule_args(rule))
    # Delete only our exact routes, never flush a shared table or global rules.
    for route in reversed(plan):
        metric = int(route[route.index('metric')+1])
        if any(owned_route(row, plan) and row.get('metric') == metric for row in routes):
            execute('ip', '-4', 'route', 'del', *route)
    journal.unlink()
