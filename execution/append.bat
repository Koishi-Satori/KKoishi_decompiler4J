IF NOT DEFINED VM_OPTIONS GOTO empty_VM_OPTIONS
IF "%SEPARATOR%" == "" GOTO no_separator
SET VM_OPTIONS=%VM_OPTIONS%%SEPARATOR%%1
GOTO end

:no_separator
SET VM_OPTIONS=%VM_OPTIONS% %1
GOTO end

:empty_VM_OPTIONS
SET VM_OPTIONS=%1
GOTO end

:end