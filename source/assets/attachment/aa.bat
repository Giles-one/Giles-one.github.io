@echo off
setlocal

rem 检查参数数量是否为1
if "%~1"=="" (
    echo 用法: %0 文件路径
    exit /b
)

rem 获取文件名部分
for %%F in ("%~1") do (
    echo 文件名: %%~nF
)
echo %~n1%~x1

endlocal