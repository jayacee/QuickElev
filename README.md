# QuickElev
Spawns a command line with "NT AUTHORITY\SYSTEM" privileges - fast and lightweight alternative to PsExec

## How Does It Work?
This tool cycles through every ```NT AUTHORITY\SYSTEM``` process and tries to duplicate their token. If a successful duplication occurs, the tool calls ```ImpersonateLoggedOnUser``` then ```CreateProcessWithTokenW```.

## Protection Levels
Certain process protection levels may prevent the token or process from being opened with the required permissions.

These were the tested protection levels, based on the protection levels that did permit this token duplication:
- ✅ PsProtectedSignerWinTcb-Light
- ❌ PsProtectedSignerAntimalware-Light
- ❌ PsProtectedSignerWindows-Light

Surprisingly, ```PsProtectedSignerWindows-Light``` does not protect its token enough to prevent this. By opening processes of this protection level with the ```PROCESS_QUERY_LIMITED_INFORMATION``` privilege, its token can then be opened with ```TOKEN_QUERY | TOKEN_DUPLICATE``` privileges.

## Download
[Releases](releases/)
