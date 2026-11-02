; При удалении Leftik VPN снимаем kill switch, иначе интернет останется заблокированным
!macro customUnInstall
  ReadEnvStr $0 PROGRAMDATA
  IfFileExists "$0\LeftikVPN\restore-firewall.cmd" 0 leftik_legacy
    nsExec::Exec `cmd.exe /d /c "$0\LeftikVPN\restore-firewall.cmd"`
  leftik_legacy:
  IfFileExists "$0\LeftikVPN\restore-firewall.ps1" 0 leftik_done
    nsExec::Exec `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$0\LeftikVPN\restore-firewall.ps1"`
  leftik_done:
  RMDir /r "$0\LeftikVPN"
  nsExec::Exec `powershell.exe -NoProfile -Command "Get-Process sing-box -ErrorAction SilentlyContinue | Where-Object { $$_.Path -like '$INSTDIR\*' } | Stop-Process -Force"`
!macroend
