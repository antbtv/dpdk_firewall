project('dpdk_firewall', 'c',
  version : '0.1.0',
  default_options : [
    'c_std=c11',
    'warning_level=2',
  ]
)

# Зависимости
dpdk = dependency('libdpdk', required : true)
jansson = dependency('jansson', required : true)

# Параметры сборки
max_rules = get_option('max_rules')
enable_debug = get_option('enable_debug')

# Глобальные аргументы компилятора
# _GNU_SOURCE необходим для POSIX-расширений, используемых проектом (strcasecmp,
# strnlen, sigaction, sigemptyset) и внутренними заголовками DPDK (rte_string_fns.h).
global_args = [
  '-DMAX_RULES=' + max_rules.to_string(),
  '-D_GNU_SOURCE',
]
if enable_debug
  global_args += ['-DDEBUG', '-DRTE_LOG_DP_LEVEL=RTE_LOG_DEBUG']
endif
add_project_arguments(global_args, language : 'c')

# Директории заголовочных файлов
inc = include_directories('include')

# Исходные файлы основного исполняемого файла брандмауэра
fw_sources = files(
  'src/main.c',
  'src/config.c',
  'src/port.c',
  'src/pipeline.c',
  'src/rule_engine.c',
  'src/ddos.c',
  'src/stats.c',
  'src/mgmt.c',
  'src/log.c',
)

executable('dpdk_firewall',
  sources : fw_sources,
  include_directories : inc,
  dependencies : [dpdk, jansson],
  install : true,
)

# Утилита командной строки (без зависимости от DPDK)
subdir('cli')

# Юнит-тесты
subdir('tests')
