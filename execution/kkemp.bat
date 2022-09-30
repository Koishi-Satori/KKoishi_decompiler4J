@echo off
:: ------------------------------------------------------------------------------------
:: The start batch execution file of kkemp.
:: Author: KKoishi_
:: ------------------------------------------------------------------------------------

::Set the program name and locate the current directory.
set NAME=decompiler.kkoishi
set CUR=%cd%
set JRE=
:: ------------------------------------------------------------------------------------
:: Locate a JRE installation directory which will be used to run the Kkkemp jar file.
:: Try (in order): KKEMP_JDK, JDK_HOME, JAVA_HOME.
:: ------------------------------------------------------------------------------------
if exist "%KKEMP_JDK%" (set JRE=%KKEMP_JDK%)
if "%JRE%" == "" (
    if exist "%JAVA_HOME%" (
        set JRE=%JAVA_HOME%
    )
)
if "%JRE%" == "" (
    if exist "%JDK_HOME%" (
        set JRE=%JDK_HOME%
    )
)

:: ------------------------------------------------------------------------------------
:: Locate the java execution file, if not found, then end this process.
:: ------------------------------------------------------------------------------------
set JAVA_EXE=%JRE%\bin\java.exe
if not exist "%JAVA_EXE%" (
    echo ERROR: Can not start KKoishi_decompiler
    echo No JRE found, please make sure environment variable KKEMP_JDK, JAVA_HOME or JDK_HOME pointed to a valid JRE installation.
    echo And there must exist \bin\java.exe in JRE directory.
    exit /b
)

:: ---------------------------------------------------------------------
:: Collect JVM options and properties.
:: ---------------------------------------------------------------------
if not exist "%CUR%\data\%NAME%.vmoptions" (
    echo ERROR: Can not find jvm options file.
    exit /b
)
set VM_OPTIONS=
for /f  "eol=# usebackq delims=" %%i in ("%CUR%\data\%NAME%.vmoptions") do (
    call "%CUR%/append.bat" "%%i"
)

:: ------------------------------------------------------------------------------------
:: RUN!
:: ------------------------------------------------------------------------------------
"%JAVA_EXE%" %VM_OPTIONS% -jar "%CUR%\%NAME%.jar"
