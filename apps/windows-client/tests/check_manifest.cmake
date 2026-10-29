# Inspect the resource in the linked PE, not only the source manifest.
execute_process(COMMAND "${MT_EXECUTABLE}" -nologo
  "-inputresource:${APPLICATION};#1" "-out:${OUTPUT_FILE}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Cannot extract application manifest: ${output}${error}")
endif()
file(READ "${OUTPUT_FILE}" manifest)
foreach(required "OrangeSpace.Client" "Microsoft.Windows.Common-Controls" "PerMonitorV2")
  string(FIND "${manifest}" "${required}" position)
  if(position EQUAL -1)
    message(FATAL_ERROR "Linked manifest is missing ${required}")
  endif()
endforeach()
if(NOT manifest MATCHES "requestedExecutionLevel[^>]*level=\"asInvoker\"")
  message(FATAL_ERROR "Linked manifest must retain asInvoker privileges")
endif()
message(STATUS "Linked PE manifest retains identity, common controls, DPI and asInvoker")
