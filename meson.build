project('dpdk_firewall', 'c',
  version : '0.1.0',
  default_options : [
    'c_std=c11',
    'warning_level=2',
  ]
)

# Dependencies
dpdk = dependency('libdpdk', required : true)
jansson = dependency('jansson', required : true)

# Build options
max_rules = get_option('max_rules')
enable_debug = get_option('enable_debug')

# Global compile args
global_args = [
  '-DMAX_RULES=' + max_rules.to_string(),
]
if enable_debug
  global_args += ['-DDEBUG', '-DRTE_LOG_DP_LEVEL=RTE_LOG_DEBUG']
endif
add_project_arguments(global_args, language : 'c')

# Include directories
inc = include_directories('include')

# Main firewall executable sources
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

# CLI tool (no DPDK dependency)
subdir('cli')

# Unit tests
subdir('tests')
