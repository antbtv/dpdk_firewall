dpdk = dependency('libdpdk', required : true)
jansson = dependency('jansson', required : true)

test_inc = include_directories('../include')

# тест движка правил
test_rule_engine = executable('test_rule_engine',
  sources : [
    files('test_rule_engine.c'),
    files('../src/rule_engine.c'),
    files('../src/log.c'),
  ],
  include_directories : test_inc,
  dependencies : [dpdk, jansson],
)
test('rule_engine', test_rule_engine)

# тест DDoS-защиты
test_ddos = executable('test_ddos',
  sources : [
    files('test_ddos.c'),
    files('../src/ddos.c'),
    files('../src/log.c'),
  ],
  include_directories : test_inc,
  dependencies : [dpdk, jansson],
)
test('ddos', test_ddos)

# тест конфигурации — включает rule_engine.c, так как config_reload() вызывает rule_engine_reload_from_config()
test_config = executable('test_config',
  sources : [
    files('test_config.c'),
    files('../src/config.c'),
    files('../src/rule_engine.c'),
    files('../src/log.c'),
  ],
  include_directories : test_inc,
  dependencies : [dpdk, jansson],
)
test('config', test_config)
