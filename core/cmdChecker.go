package core

import (
	"strings"
)

// 检查命令执行
func checkDE(cmdline string) bool {
	//fmt.Println("cmdline:::",cmdline)
	isDownloadAndEXEC := false
	lenCmdline := len(cmdline)
	if lenCmdline > 20 && lenCmdline < 300 {
		index := strings.Index(cmdline, "|")
		if index > 0 {
			if (strings.Contains(cmdline, "sh ") || strings.Contains(cmdline, "bash ")) && (strings.Contains(cmdline, "curl ") || strings.Contains(cmdline, "wget ")) {
				targetString := ""
				if lenCmdline-index > 10 {
					targetString = cmdline[index : index+10]
				} else {
					targetString = cmdline[index:]
				}
				if strings.Contains(targetString, "python") || strings.Contains(targetString, "sh") || strings.Contains(targetString, "perl") {
					isDownloadAndEXEC = true
				}
			}
		}
	}

	return isDownloadAndEXEC
}

//现在很少有原生的直接执行命令的了，意义真不大，还是卡下载执行反弹链意义更大

func checkCmdline(uid string, pCmd string) bool {
	needCheck := false

	lenCmdline := len(pCmd)
	if lenCmdline > 200 {
		return false
	}

	if strings.HasPrefix(pCmd, "sh ") || strings.HasPrefix(pCmd, "bash ") {
		if strings.Contains(pCmd, "|") || strings.Contains(pCmd, ";") || strings.Contains(pCmd, "&&") {
			if count, ok := RceCheckMap["readSystem"]; ok == false || count < 2 {
				if strings.Contains(pCmd, "ifconfig") || strings.Contains(pCmd, "/etc/passwd") || strings.Contains(pCmd, "hostname") || strings.Contains(pCmd, "netstat") { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["readSystem"]; ok == false {
						RceCheckMap["readSystem"] = 1
					} else {
						RceCheckMap["readSystem"] += 1
					}
				}
			} else if count, ok := RceCheckMap["readFile"]; ok == false || count < 8 {
				if strings.Contains(pCmd, "cat ") || strings.Contains(pCmd, "ls ") || strings.Contains(pCmd, "find ") { //search on system
					needCheck = true
					if _, ok := RceCheckMap["readFile"]; ok == false {
						RceCheckMap["readFile"] = 1
					} else {
						RceCheckMap["readFile"] += 1
					}
					if RceCheckMap["readFile"] > 6 {
						RceCheckMap["readFile_count"] = 1
					}
				}
			} else if count, ok := RceCheckMap["readID"]; ok == false || count < 2 {
				if strings.Contains(pCmd, "whoami") || strings.Contains(pCmd, "who") { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["readID"]; ok == false {
						RceCheckMap["readID"] = 1
					} else {
						RceCheckMap["readID"] += 1
					}
				}
			} else if count, ok := RceCheckMap["download"]; ok == false || count < 2 {
				if strings.Contains(pCmd, "wget ") || strings.Contains(pCmd, "scp ") || (strings.Contains(pCmd, "curl ") && strings.Contains(pCmd, " -o")) { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["download"]; ok == false {
						RceCheckMap["download"] = 1
					} else {
						RceCheckMap["download"] += 1
					}
				}
			} else if count, ok := RceCheckMap["probe"]; ok == false || count < 2 {
				if strings.Contains(pCmd, "ping ") || strings.Contains(pCmd, "telnet ") { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["probe"]; ok == false {
						RceCheckMap["probe"] = 1
					} else {
						RceCheckMap["probe"] += 1
					}
				}
			}
		} else {
			pCmd = strings.Replace(pCmd, "sh -c ", "", 1)
			debug_print("pCmd:2", pCmd)
			if count, ok := RceCheckMap["readSystem"]; ok == false || count < 2 {
				if strings.Contains(pCmd, "ifconfig") || strings.Contains(pCmd, "/etc/passwd") || strings.HasPrefix(pCmd, "hostname") || strings.HasPrefix(pCmd, "netstat") { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["readSystem"]; ok == false {
						RceCheckMap["readSystem"] = 1
					} else {
						RceCheckMap["readSystem"] += 1
					}
				}
			} else if count, ok := RceCheckMap["readFile"]; ok == false || count < 8 {
				if strings.HasPrefix(pCmd, "cat ") || strings.HasPrefix(pCmd, "ls ") || strings.HasPrefix(pCmd, "find ") { //search on system
					needCheck = true
					if _, ok := RceCheckMap["readFile"]; ok == false {
						RceCheckMap["readFile"] = 1
					} else {
						RceCheckMap["readFile"] += 1
					}
					if RceCheckMap["readFile"] > 6 {
						RceCheckMap["readFile_count"] = 1
					}
				}
			} else if count, ok := RceCheckMap["readID"]; ok == false || count < 2 {
				if strings.HasPrefix(pCmd, "whoami") || strings.HasPrefix(pCmd, "who") { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["readID"]; ok == false {
						RceCheckMap["readID"] = 1
					} else {
						RceCheckMap["readID"] += 1
					}
				}
			} else if count, ok := RceCheckMap["download"]; ok == false || count < 2 {
				if strings.HasPrefix(pCmd, "wget ") || strings.HasPrefix(pCmd, "scp ") || (strings.HasPrefix(pCmd, "curl ") && strings.Contains(pCmd, " -o")) { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["download"]; ok == false {
						RceCheckMap["download"] = 1
					} else {
						RceCheckMap["download"] += 1
					}
				}
			} else if count, ok := RceCheckMap["probe"]; ok == false || count < 2 {
				if strings.HasPrefix(pCmd, "ping ") || strings.HasPrefix(pCmd, "telnet ") { //id pwd hostname
					needCheck = true
					if _, ok := RceCheckMap["probe"]; ok == false {
						RceCheckMap["probe"] = 1
					} else {
						RceCheckMap["probe"] += 1
					}
				}
			}
		}
	}

	return needCheck
}
