set breakpoint pending on
set pagination off
set backtrace past-main on

# Check if debug sources are loaded in our program, and we can break inside.

hbreak func
commands
  echo \n<backtrace 1 start>\n
  backtrace
  echo <backtrace 1 end>\n\n

  # Check if we can break inside PAL. On VM, backtracing currently stops inside PAL,
  # so this backtrace is expected to show PAL frames only.

  hbreak pal_common_console_write
  commands
    echo \n<backtrace 2 start>\n
    backtrace
    echo <backtrace 2 end>\n\n
    continue
  end

  continue
end

continue
