Set shell = CreateObject("WScript.Shell")
shell.Run "cmd.exe /c echo benign test && exit", 0, True
