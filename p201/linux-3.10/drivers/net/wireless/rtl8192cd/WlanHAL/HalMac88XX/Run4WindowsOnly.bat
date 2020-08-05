  echo  Enter IC Type (EX: 8822b/8821c/8822c/8814b/all)
  set /P IC_TYPE=

insert_halmac_in_reg_def.exe
MP_Precomp.exe
clone88xx.exe

set CURRENT_FOLDER_ADDR=%~DP0%

if "%IC_TYPE%"=="8822b" (
	set FILE_STR=win8822b
) else if "%IC_TYPE%"=="8822B" (
	set FILE_STR=win8822b
) else if "%IC_TYPE%"=="8821c" (
	set FILE_STR=win8821c
) else if "%IC_TYPE%"=="8821C" (
	set FILE_STR=win8821c
) else if "%IC_TYPE%"=="8197f" (
	set FILE_STR=win8197f
) else if "%IC_TYPE%"=="8197F" (
	set FILE_STR=win8197f
) else if "%IC_TYPE%"=="8814b" (
	set FILE_STR=win8814b
) else if "%IC_TYPE%"=="8814B" (
	set FILE_STR=win8814b
) else if "%IC_TYPE%"=="8822c" (
	set FILE_STR=win8822c
) else if "%IC_TYPE%"=="8822C" (
	set FILE_STR=win8822c
) else if "%IC_TYPE%"=="8812F" (
	set FILE_STR=win8812f
) else  (
	goto end
)
goto keepfile

:keepfile
mkdir %CURRENT_FOLDER_ADDR%temp
copy %CURRENT_FOLDER_ADDR%halmac_88xx\*%FILE_STR%*.* %CURRENT_FOLDER_ADDR%temp
move %CURRENT_FOLDER_ADDR%halmac_88xx\halmac_%IC_TYPE% %CURRENT_FOLDER_ADDR%temp\halmac_%IC_TYPE%
rd %CURRENT_FOLDER_ADDR%halmac_88xx\ /s /q
mkdir %CURRENT_FOLDER_ADDR%halmac_88xx
copy %CURRENT_FOLDER_ADDR%temp\*.* %CURRENT_FOLDER_ADDR%halmac_88xx
move %CURRENT_FOLDER_ADDR%temp\halmac_%IC_TYPE% %CURRENT_FOLDER_ADDR%halmac_88xx\halmac_%IC_TYPE% 
rmdir %CURRENT_FOLDER_ADDR%temp /s/q
goto end

:end