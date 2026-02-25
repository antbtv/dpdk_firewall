jansson = dependency('jansson', required : true)

cli_inc = include_directories('../include')

executable('fw_ctl',
  sources : files('fw_ctl.c'),
  include_directories : cli_inc,
  dependencies : [jansson],
  install : true,
)
