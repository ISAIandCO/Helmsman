"""Country catalogue. Saved preset IDs describe the applied route, never the UI country."""
RU_BASE = 'https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/'
GEOIP_BASE = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/'
COUNTRIES = {
    'ru': 'Россия', 'cn': 'Китай', 'ir': 'Иран', 'by': 'Беларусь',
    'tr': 'Турция', 'vn': 'Вьетнам', 'mm': 'Мьянма', 'tm': 'Туркменистан',
    'other': 'Другая страна',
}
SUFFIXES = {'ru': ['ru', 'su', 'xn--p1ai'], 'cn': ['cn', 'xn--fiqs8s', 'xn--fiqz9s'],
            'ir': ['ir', 'xn--mgba3a4f16a'], 'by': ['by', 'xn--90ais'], 'tr': ['tr'],
            'vn': ['vn'], 'mm': ['mm'], 'tm': ['tm']}
BUILTIN_LISTS = {
    'ru-blocked': ('Россия: домены из общественных списков', RU_BASE + 'rule-set-geosite/geosite-ru-blocked.srs'),
    'ru-ip-blocked': ('Россия: IP из общественных списков', RU_BASE + 'rule-set-geoip/geoip-ru-blocked.srs'),
    'ru-domains': ('Российские домены', RU_BASE + 'rule-set-geosite/geosite-category-ru.srs'),
    'ru-ips': ('Российские IP', RU_BASE + 'rule-set-geoip/geoip-ru.srs'),
    'cn-domains': ('Китай: домены', 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs'),
    'ir-domains': ('Иран: домены', 'https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs'),
}
for country in SUFFIXES:
    if country != 'ru':
        BUILTIN_LISTS[country + '-ips'] = (COUNTRIES[country] + ': IP', GEOIP_BASE + 'geoip-' + country + '.srs')

# Keep the original IDs and rules exactly as they were for existing installations.
PRESETS = {
    'full': 'Весь интернет через VPN', 'ru-selective': 'Россия: выборочно',
    'ru-except': 'Россия напрямую', 'manual': 'Мои правила',
}
for country in SUFFIXES:
    PRESETS[country + '-domains-only'] = COUNTRIES[country] + ': домены напрямую'
    if country != 'ru':
        PRESETS[country + '-except'] = COUNTRIES[country] + ': домены и IP напрямую'


def available_presets(country):
    return {key: name for key, name in PRESETS.items()
            if key in {'full', 'manual'} or key.startswith(country + '-')}


def preset_rules(preset):
    """Raw rules/final action; compile_config validates them through the normal path."""
    if preset == 'ru-selective':
        return [{'type': 'list', 'values': ['ru-blocked', 'ru-ip-blocked'], 'action': 'proxy'}], 'direct'
    if preset == 'ru-except':
        return [{'type': 'list', 'values': ['ru-domains', 'ru-ips'], 'action': 'direct'}], 'proxy'
    if preset in {'full', 'manual'}:
        return [], 'proxy'
    country = preset.split('-', 1)[0]
    rules = [{'type': 'domain_suffix', 'values': SUFFIXES[country], 'action': 'direct'}]
    tags = [country + '-domains'] if country in {'ru', 'cn', 'ir'} else []
    if preset.endswith('-except'):
        tags.append(country + '-ips')
    if tags:
        rules.append({'type': 'list', 'values': tags, 'action': 'direct'})
    return rules, 'proxy'


def required_lists(preset):
    return [tag for r in preset_rules(preset)[0] if r['type'] == 'list' for tag in r['values']]


def preset_description(preset):
    if preset == 'full':
        return 'Весь интернет через VPN; разрешённая LAN и пользовательские исключения — напрямую. Для первого подключения и широких блокировок.'
    if preset == 'manual':
        return 'Только пользовательские правила; маршрут остальных запросов задаётся в настройках. Для собственной схемы маршрутизации.'
    if preset == 'ru-selective':
        return 'Через VPN — домены и IP из российских списков блокировок; остальное напрямую. Для экономии трафика, без гарантии полноты списков.'
    if preset == 'ru-except':
        return 'Российские домены и IP из списков — напрямую; остальной интернет через VPN. Для местных сервисов и доступа к зарубежным ресурсам.'
    country = preset.split('-', 1)[0]
    if country in {'ru', 'cn', 'ir'}:
        domains = 'Национальные доменные зоны и местные домены из списка'
    else:
        domains = 'Только национальная доменная зона (местные сайты в .com и других зонах могут идти через VPN)'
    if preset.endswith('-except'):
        return domains + ' и IP страны — напрямую; остальное через VPN. Для местных сервисов; GeoIP может затронуть общие CDN.'
    return domains + ' — напрямую; остальное через VPN. Более узкое исключение без GeoIP, для доступа к местным сайтам.'
