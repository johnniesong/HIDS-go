package core

import (
	"crypto/tls"
	"fmt"
	pnet "github.com/shirou/gopsutil/net"
	_ "github.com/shirou/gopsutil/process"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var IsOwnAssetAndNotIsolateMap map[string]bool

// 获取lsof信息，传入grep目标：target，preResult代表使用之前的lsof结果，大幅度减少性能消耗，calcDipCount代表计算dip出现次数，大于一定次数，代表无害，减少性能消耗
func getCheckRshellInfoByLsof(target string, preResult string) ([][]string, string) {
	result := make([][]string, 0, 3)
	ssRes := ""
	needFilter := false
	if preResult != "" {
		ssRes = preResult
		needFilter = true
	} else {
		t1 := time.Now()
		ssRes, _ = execComm("lsof -n -P -i|grep ESTABL|grep \" " + target + " \"")
		//live_print("lsof -n -P -i|grep ESTABL|grep \" "+target+" \"")
		t2 := time.Now()
		//fmt.Println(t2.Sub(t1).Seconds())
		timeCost := t2.Sub(t1).Seconds()
		SumLsofTimeCostLock.Lock()
		SumLsofTimeCost += timeCost
		SumLsofTimeCostLock.Unlock()
		fmt.Println("CALL SSCheck!!!!!", timeCost, SumLsofTimeCost)
	}
	if len(ssRes) > 3 {
		ssList := strings.Split(strings.TrimSpace(ssRes), "\n")
		for _, ssInfo := range ssList {
			if len(ssInfo) > 10 {
				if needFilter {
					if strings.Contains(ssInfo, " "+target+" ") == false {
						continue
					}
				}
				//debug_print("ssInfo:",ssInfo)
				ssItemList := make([]string, 0, 10)
				tmpArray := make([]string, 0, 5)
				for _, item := range strings.Split(strings.TrimSpace(ssInfo), " ") {
					if len(item) > 0 {
						ssItemList = append(ssItemList, item)
					}
				}
				//for index, item1 := range (ssItemList) {
				//	debug_print(strconv.Itoa(index), item1)
				//}
				exec := strings.TrimSpace(ssItemList[0])
				pid := strings.TrimSpace(ssItemList[1])
				uidName := strings.TrimSpace(ssItemList[2])
				SipSportDipDport := strings.TrimSpace(ssItemList[8])
				if strings.Contains(SipSportDipDport, "->") {
					tmpSipSportDipDport := strings.Split(SipSportDipDport, "->")
					sip_sport := strings.TrimSpace(tmpSipSportDipDport[0])
					dip_dport := strings.TrimSpace(tmpSipSportDipDport[1])
					sip := strings.Split(sip_sport, ":")[0]
					sPort := strings.Split(sip_sport, ":")[1]
					dip := strings.Split(dip_dport, ":")[0]
					dPort := strings.Split(dip_dport, ":")[1]
					tmpArray = append(tmpArray, exec)
					tmpArray = append(tmpArray, SipSportDipDport)
					tmpArray = append(tmpArray, sip)
					tmpArray = append(tmpArray, dip)
					tmpArray = append(tmpArray, ssInfo)
					tmpArray = append(tmpArray, pid)
					tmpArray = append(tmpArray, uidName)
					tmpArray = append(tmpArray, dPort)
					tmpArray = append(tmpArray, sPort)
					debug_print("getCheckRshellInfoByLsof:", exec, SipSportDipDport, sip, dip, pid, uidName, dPort, sPort)
				} else {
					sip_sport := strings.TrimSpace(SipSportDipDport)
					dip_dport := strings.TrimSpace("*:*")
					splitResult := strings.Split(sip_sport, ":")
					sip, sPort := "", ""
					sip = splitResult[0]
					if len(sip) < 7 {
						sip = "--NULL--"
					}
					if len(splitResult) < 2 {
						sPort = "-1"
					} else {
						sPort = splitResult[1]
					}
					dip := strings.Split(dip_dport, ":")[0]
					dPort := strings.Split(dip_dport, ":")[1]
					tmpArray = append(tmpArray, exec)
					tmpArray = append(tmpArray, SipSportDipDport)
					tmpArray = append(tmpArray, sip)
					tmpArray = append(tmpArray, dip)
					tmpArray = append(tmpArray, "")
					tmpArray = append(tmpArray, pid)
					tmpArray = append(tmpArray, uidName)
					tmpArray = append(tmpArray, dPort)
					tmpArray = append(tmpArray, sPort)

					debug_print("getCheckRshellInfoByLsof:", exec, SipSportDipDport, sip, dip, pid, uidName, dPort, sPort)
				}
				result = append(result, tmpArray)
			}
		}
	}
	return result, ssRes
}

// 反弹shell的核心检查逻辑，获取lsof信息，然后检查，涉及到目的ip过滤。	启用严格模式，避免一部分性能消耗，但是先内网建立隧道的方式就无法检测了
func checkProcessListenPort_V2_lsof_V2(pid int32, dangerUID bool, cwd string) (bool, string, string) {
	//for k,v:=range(IsOwnAssetAndNotIsolateMap){
	//	debug_print("IsOwnAssetAndNotIsolateMap",k,strconv.FormatBool(v))
	//}
	//for k,v:=range(IPSMap){
	//	debug_print("IPSMap",k,strconv.FormatBool(v))
	//}
	time.Sleep(3 * time.Second)

	rawResult, totalResult := getCheckRshellInfoByLsof("", "")
	dipMap := getDipCountDict(rawResult)

	//for k,v:=range dipMap{
	//	fmt.Println(k,v)
	//}

	rawResult = filterResultBySportDip(rawResult, dipMap, false)

	totalResult = ""
	for _, item := range rawResult {
		info := item[4]
		totalResult += info + "\n"
	}

	live_print("len totalResult", len(totalResult))
	if len(totalResult) > 0 {
		result, _ := getCheckRshellInfoByLsof(strconv.Itoa(int(pid)), totalResult)
		if len(result) > 0 {
			for _, items := range result {
				//fmt.Println("items",items)
				//exec:=items[0]
				SipSportDipDport := items[1]
				sip := items[2]
				dip := items[3]
				lsofInfo := items[4]

				checkResult, checkResultInfo, warningObviousLevel := checkRshellBySSinfoResult(sip, dip, SipSportDipDport, totalResult, dangerUID, lsofInfo, cwd, pid)
				live_print("WarningObviousLevel:", warningObviousLevel)
				if checkResult {
					dipDport := strings.Split(SipSportDipDport, "->")[1]
					if checkIsHttpService(dipDport) == false {
						return checkResult, checkResultInfo, SipSportDipDport
					}
				}
			}
		} else {
			live_print(strconv.Itoa(int(pid)) + " result NULL")
		}
	}

	if HasCheckedLsofInPeriod == false {
		live_print("start checkLsofInPeriod by checkProcessListenPort_V2_lsof_V2")
		checkLsof(rawResult, totalResult, true, cwd)
		HasCheckedLsofInPeriod = true
		live_print("finish checkLsofInPeriod by checkProcessListenPort_V2_lsof_V2")
	}
	return false, "", ""
}

func getWarningObviousLevel(countOfBash int, countOfSh int, countOfExec int, countOfProcess int, dangerUID bool) int {
	level := 0

	if dangerUID {
		countOfExec -= 1
		countOfProcess -= 1
	}

	if countOfProcess <= 8 && (countOfBash >= 3 || countOfSh >= 3 || countOfBash+countOfSh >= 4) {
		level += 1
		if dangerUID {
			level += 1
		}
	}

	if countOfProcess <= 8 && float64(countOfSh+countOfBash)/float64(countOfProcess) >= 0.70 {
		level += 1
	}

	if countOfExec >= 1 && dangerUID {
		level += 1
	}
	return level
}

// 先判断文件类型（是一个很重要的信息），文本，还是可执行，可执行的话，在行数很少，1-2的时候，特殊处理，对于execItems[0]=="socat" || execItems[0]=="ncat" ||execItems[0]=="nc" 这句话来说是一个行为上的上级判断？
// 或者说当在行数很少，1-2的时候，直接用execItems[0]=="socat" || execItems[0]=="ncat" ||execItems[0]=="nc"的逻辑，countOfExec+=2 countOfProcess+=1？ 可以一试！
// 检查ELF后门
func checkIsELFRshell(proName string, ppid int32, pExe string) bool {
	score := 0

	_, err := strconv.Atoi(proName)
	if err == nil {
		score += 1
	}

	if ppid == 1 {
		score += 1
	}

	if strings.Contains(pExe, proName) == false {
		score += 1
	}

	if strings.Contains(pExe, "deleted") || strings.Contains(pExe, "memfd") {
		score += 1
	}

	live_print("checkIsELFRshell score: ", score)

	if score >= 3 {
		return true
	} else {
		return false
	}
}

func checkIsDangerAnonymousProcess(procName_ string, pid int32) bool {
	_, err := strconv.Atoi(procName_)
	if err != nil {
		return false
	}

	proName, pPid, _, pCwd, pExe, _ := getProcessInfo(pid)
	return _checkIsDangerAnonymousProcess(proName, pPid, pCwd, pExe)
}

func _checkIsDangerAnonymousProcess(proName string, pPid int32, pCwd string, pExe string) bool {
	score := 0
	live_print("getProcessInfo1", proName, pPid, pCwd, pExe)
	if pPid == 1 {
		score += 1
	}

	_, err := strconv.Atoi(proName)
	if err == nil {
		score += 2
	}

	if strings.Contains(pExe, proName) == false {
		score += 2
	}

	if len(pCwd) < 3 {
		score += 1
	}

	fileType := getFileTypeInfo(pExe)
	if fileType == SO {
		score += 2
	}

	live_print("checkIsDangerAnonymousProcess score: ", score)

	if score > 4 {
		return true
	} else {
		return false
	}
}

// 反弹shell的核心检查逻辑
func checkRshellBySSinfoResult(sip string, dip string, SipSportDipDport string, totalResult string, dangerUID bool, lsofInfo string, cwd string, pid int32) (bool, string, int) {
	execResult, _ := getCheckRshellInfoByLsof(SipSportDipDport, totalResult)
	live_print("checkRshellBySSinfoResult SipSportDipDport", SipSportDipDport)
	countOfBash := 0
	countOfSh := 0
	countOfExec := 0
	countOfProcess := 0
	lsofInfo2 := " lsofInfo: "
	whiteFlag := 0

	isNormalBin := false

	if len(execResult) > 0 {
		for _, execItems := range execResult {
			//for _,item:=range execItems{
			//	fmt.Println(item)
			//}
			if strings.Contains(execItems[0], "tmon") || strings.Contains(execItems[0], "agent") || strings.Contains(execItems[0], "wonder-agent") {
				whiteFlag = 1
				break
			}
			if execItems[0] == "bash" {
				countOfBash += 1
			} else if len(execItems[0]) <= 4 && strings.HasSuffix(execItems[0], "sh") {
				countOfSh += 1
			} else if execItems[0] == "perl" || execItems[0] == "java" || strings.HasPrefix(execItems[0], "php") || strings.HasPrefix(execItems[0], "python") {
				countOfExec += 1
				isNormalBin = true
			} else if execItems[0] == "curl" || execItems[0] == "make" || strings.HasPrefix(execItems[0], "pip") {
				countOfExec -= 2
			}
			Cpid, err := strconv.Atoi(execItems[5])
			if err != nil {
				fmt.Println("ERROR: pid,err:=strconv.Atoi(execItems[5])")
			} else {
				if checkIsDangerAnonymousProcess(execItems[0], int32(Cpid)) || (execItems[0] == "socat" || execItems[0] == "ncat" || execItems[0] == "nc") {
					countOfExec += 2
					countOfProcess += 1
				}
			}
			countOfProcess += 1
			lsofInfo2 += "\n" + execItems[4]
		}
		//这个相当于对len(execResult)!=1 && (execItems[0]=="socat" || execItems[0]=="ncat" ||execItems[0]=="nc") 这里的补充，所以不能重复判断
		if len(execResult) == 1 && isNormalBin == false {
			for _, execItems := range execResult {
				Cpid, err := strconv.Atoi(execItems[5])
				connectionInfo, _, _ := getProcessConnectionsInfoANDUid(int32(Cpid))
				connCount := getRemoteTCPConnctionCount(connectionInfo)
				//live_print("len(connectionInfo)",Cpid,connCount,len(connectionInfo),connectionInfo)
				if connCount > 2 { //目前没见过开多个链接的反弹程序
					live_print(Cpid, " connCount>2 PASS")
					continue
				}

				exist, _ := fileExists(cwd + "/" + execItems[0])
				if cwd == "" || exist == false {
					if err != nil {
						fmt.Println("ERROR: pid,err:=strconv.Atoi(execItems[5])")
					} else {
						proName, pPid_, _, pCwd, pExe_, _ := getProcessInfo(int32(Cpid))
						live_print("getProcessInfo2", proName, pPid_, pCwd, pExe_)
						if checkIsELFRshell(proName, pPid_, pExe_) {
							countOfExec += 2
							countOfProcess += 2
						}
						cwd = pCwd
					}
				}

				filePaths := getFilePathByName(execItems[0], cwd)
				for _, filePath := range filePaths {
					fileType := getFileTypeInfo(filePath)
					if fileType == TEXT {

					} else if fileType == EXEC || fileType == SO {
						countOfExec += 2
						countOfProcess += 2
						break
					} else {

					}
				}
			}
		}

		if dangerUID {
			countOfExec += 1
			countOfProcess += 1
		}
		fmt.Println("len execResult:", len(execResult))
		fmt.Println("execResult:", execResult)
		fmt.Println("check!!!!", whiteFlag, countOfBash, countOfSh, countOfExec, countOfSh+countOfBash+countOfExec, countOfProcess, dangerUID)
		if whiteFlag == 0 && (countOfBash > 0 || countOfSh > 0 || countOfExec > 0) && (countOfExec >= 0) && (countOfSh+countOfBash+countOfExec > 1) && (countOfSh+countOfBash+countOfExec <= countOfProcess) { //在里面判断，不是公司资产就报警
			checkInfo := fmt.Sprintf("%d %d %d %d %d %d %t", whiteFlag, countOfBash, countOfSh, countOfExec, countOfSh+countOfBash+countOfExec, countOfProcess, dangerUID)
			//return true,lsofInfo+lsofInfo2
			fmt.Println("check success 1")
			if strings.HasPrefix(dip, "*") == true { //* XXXXX 肯定不是公司资产，甚至不是ip。。。
				debug_print("f 1", dip)
				return true, lsofInfo2 + "\n!!!!checkInfo:" + checkInfo, getWarningObviousLevel(countOfBash, countOfSh, countOfExec, countOfProcess, dangerUID)
			}

			if CheckIsOwnAsset(dip, "0") == false {
				if isPrivateIP(net.ParseIP(sip)) == false && CheckIsOwnAsset(dip, "1") == true && CheckIsOwnAsset(sip, "1") == true { //sip不是私网，且sip dip都是隔离网段机器，不告警
					debug_print("Both sip and dip are isolate, not warning")
				} else {
					debug_print("f 2", dip)
					return true, lsofInfo2 + "\n!!!!checkInfo:" + checkInfo, getWarningObviousLevel(countOfBash, countOfSh, countOfExec, countOfProcess, dangerUID)
				}
			}
		} else {
			fmt.Println("check failed")
		}
	}
	return false, "", 0
}

// 周期性清理rcecache中缓存
func CleanRceCheck() {
	for {
		time.Sleep(10 * time.Minute)
		CleanRceCheckMap = true
	}
}

// checkps 的逻辑之一
func findBeforeAfterOfIPString(target string, ip string, searchArea int) string {
	lenTarget := len(target)
	lenIP := len(ip)
	index := strings.Index(target, ip)
	before := ""
	after := ""
	if index != -1 {
		if index < searchArea {
			before = target[0:index]
		} else {
			before = target[index-searchArea : index]
		}
		if index+lenIP+searchArea < lenTarget {
			after = target[index+lenIP : index+lenIP+searchArea]
		} else {
			after = target[index+lenIP : lenTarget]
		}
		return before + after
	} else {
		return ""
	}
}

func getInfoByConnectionInfo(connectionInfo pnet.ConnectionStat) (string, string, string, string, string, bool) {
	sip := connectionInfo.Laddr.IP
	dip := connectionInfo.Raddr.IP
	sport := strconv.Itoa(int(connectionInfo.Laddr.Port))
	dport := strconv.Itoa(int(connectionInfo.Raddr.Port))
	ESTAB := connectionInfo.Status
	tmpType := connectionInfo.Type
	connType := ""
	if tmpType == 1 {
		connType = "TCP"
	} else if tmpType == 2 {
		connType = "UDP"
	} else {
		connType = "NONE"
	}
	isESTAB := false
	if ESTAB == "ESTABLISHED" {
		isESTAB = true
	}

	return sip, dip, sport, dport, connType, isESTAB

}

func getRemoteTCPConnctionCount(connectionInfos []pnet.ConnectionStat) int {
	count := 0
	for _, connectionInfo := range connectionInfos {
		_, dip, _, dport, _, isESTAB := getInfoByConnectionInfo(connectionInfo)
		if isESTAB && len(dip) >= 7 && dport != "0" {
			count += 1
		}
	}
	return count

}

func checkIsDangerConnectionInfo(connectionInfos []pnet.ConnectionStat) (bool, string) {
	for _, connectionInfo := range connectionInfos {
		sip, dip, sport, _, _, _ := getInfoByConnectionInfo(connectionInfo)

		if filterResultForCheckDangerPS(dip, sport) == false {
			debug_print("pass by filterResultForCheckDangerPS")
			continue
		}

		if isPrivateIP(net.ParseIP(sip)) == false && CheckIsOwnAsset(dip, "1") == true && CheckIsOwnAsset(sip, "1") == true { //sip不是私网，且sip dip都是隔离网段机器，不告警
			debug_print("Both sip and dip are isolate, not warning")
			continue
		}

		if isPrivateIP(net.ParseIP(dip)) == false && dip != "0.0.0.0" && CheckIsOwnAsset(dip, "0") == false {
			return true, dip
		}
	}
	return false, ""
}

func CheckDangerPS() {
	for {
		time.Sleep(5 * time.Minute)
		//time.Sleep(5 * time.Second)
		live_print("start CheckDangerPS")
		res, _ := execComm("ps -eo pid,ppid,start")
		if len(res) > 0 {
			lines := strings.Split(strings.TrimSpace(res), "\n")
			for _, info := range lines {
				//fmt.Println("1:",info)
				itemList := make([]string, 0, 60)
				tmpInfo := strings.Split(info, " ")
				for _, item := range tmpInfo {
					if len(item) > 0 {
						itemList = append(itemList, item)
					}
				}
				hash := itemList[0] + "|--|" + itemList[2]

				//fmt.Println("itemList:",itemList)

				_, found := CheckedProcessMap[hash]

				if found == false && itemList[1] == "1" && strings.Contains(itemList[2], ":") {
					pid := itemList[0]

					intPid, _ := strconv.Atoi(pid)

					pName, pPid, pCmd, pCwd, pExe, _ := getProcessInfo(int32(intPid))
					connectionInfo, uids, _ := getProcessConnectionsInfoANDUid(int32(intPid))
					isDangerAnonymousProcess := _checkIsDangerAnonymousProcess(pName, pPid, pCwd, pExe)
					isDangerConnectionInfo, dip := checkIsDangerConnectionInfo(connectionInfo)

					if isDangerConnectionInfo && isDangerAnonymousProcess {
						bugInfo := fmt.Sprintln(pName, pPid, pCmd, pCwd, pExe, connectionInfo, uids, isDangerAnonymousProcess, isDangerConnectionInfo, dip, hash)
						log := SYSCALL{}
						log.Uid = strconv.Itoa(int(uids[0]))
						log.Pid = pid
						log.Exe = pExe
						log.PPid = strconv.Itoa(int(pPid))
						log.Euid = ""
						log.Gid = ""
						log.Egid = ""
						log.A0 = pName
						log.Argc = ""
						log.Auid = ""
						log.Cwd = pCwd
						log.Comm = pCmd
						bug := initBugDetail("REVERSE_SHELL")
						bug.Content = ""
						live_print("warning: REVERSE_SHELL by checkDangerPS")
						bug.Chains = bugInfo
						bug.AnalyseTime = time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05")
						bug.Description = bugList[bug.Type]
						bug.Others = "TYPE:REVERSE_SHELL by checkDangerPS bugInfo:" + bugInfo

						live_print("warning info:", pName, pPid, pCmd, pCwd, pExe, connectionInfo, uids, isDangerAnonymousProcess, isDangerConnectionInfo, dip, hash)

						go func(logType string, bugDetail interface{}, auditLog interface{}) { //做二次检查之后，在决定是否告警
							time.Sleep(20 * time.Second)
							if HasAbnormalConnectByDip(dip, 5) {
								live_print(bug.Others)
								MessageToServer(bug.Type, bug, log)
							}
						}(bug.Type, bug, log)
					}
				} else {
					CheckedProcessMap[hash] = true
				}
			}
		}
	}
}

func CheckPs() { //检查已经存在的，对于lsof是个互补，lsof是及时性检查，这个是5分钟检查一次，攻击者很可能在5分钟内断开连接，那就检测不到了，这里检测的是个ip，域名还没考虑到。。。
	for {
		time.Sleep(5 * time.Minute)
		//time.Sleep(5 * time.Second)
		result := make([][]string, 0, 3)
		res, _ := execComm("ps -ef")
		if len(res) > 3 {
			lines := strings.Split(strings.TrimSpace(res), "\n")
			for _, info := range lines {
				//fmt.Println("1:",info)
				tmpArray := make([]string, 0, 5)
				itemList := make([]string, 0, 12)
				tmpInfo := strings.Split(info, " ")
				for _, item := range tmpInfo {
					if len(item) > 0 {
						itemList = append(itemList, item)
					}
				}
				//for i,v :=range itemList{
				//	fmt.Println(i,v)
				//}

				cmdline := strings.Join(itemList[7:], " ")
				if _, found := UidMap[itemList[0]]; found == true {
					cached := AbnormalCmdline[cmdline]
					shortCmdline := ""
					needCheck := false
					if len(cmdline) > 40 {
						shortCmdline = cmdline[:40]
					} else {
						shortCmdline = cmdline
					}
					if len(cmdline) > 20 && len(cmdline) < 300 && cached != true && strings.Count(cmdline, ".") > 2 && (strings.Contains(shortCmdline, "bash ") || strings.Contains(shortCmdline, "sh ") || strings.Contains(shortCmdline, "perl ") || strings.Contains(shortCmdline, "python ")) {
						if strings.Contains(shortCmdline, " scp ") == false && strings.Contains(shortCmdline, " ssh ") == false && strings.Contains(shortCmdline, "@") == false {
							if strings.Contains(shortCmdline, " curl ") == true && strings.Contains(shortCmdline, "sh") == false && strings.Contains(shortCmdline, "|") == false {
								needCheck = false
							} else {
								needCheck = true
							}
							if strings.Contains(shortCmdline, " wget ") == true && strings.Contains(shortCmdline, "sh") == false && strings.Contains(shortCmdline, "|") == false {
								needCheck = false
							} else {
								needCheck = true
							}
						}
					}
					if needCheck {
						ip := RegIP.FindString(cmdline)
						//tmpCmdline:=strings.Replace(cmdline,ip,"",1)
						beforeAfter := findBeforeAfterOfIPString(cmdline, ip, 20)
						if beforeAfter != "" {
							port := RegPort.FindString(beforeAfter)
							if ip != "" && port != "" && isPrivateIP(net.ParseIP(ip)) == false && ip != "0.0.0.0" && CheckIsOwnAsset(ip, "0") == false {
								fmt.Println("!!!!!!!!!!!!!!!!!!", ip, port)
								tmpArray = append(tmpArray, ip)
								tmpArray = append(tmpArray, port)
								tmpArray = append(tmpArray, cmdline)
								tmpArray = append(tmpArray, itemList[0]) //user
								tmpArray = append(tmpArray, info)
								result = append(result, tmpArray)

								AbnormalCmdline[cmdline] = true
								log := SYSCALL{}
								log.Uid = itemList[0]
								log.Pid = itemList[1]
								log.Exe = cmdline
								log.PPid = ""
								log.Euid = ""
								log.Gid = ""
								log.Egid = ""
								log.A0 = ""
								log.Argc = ""
								log.Auid = ""
								log.Cwd = ""
								log.Comm = info
								bug := initBugDetail("POSSIBLE_RCE")
								bug.Content = ""
								live_print("warning: CheckPs RCE by danger uid")
								bug.Chains = info
								bug.Others = "TYPE:CheckPs, RCE by danger uid:" + itemList[0] + " rceInfo:" + info

								go func(logType string, bugDetail interface{}, auditLog interface{}) { //做二次检查之后，在决定是否告警
									time.Sleep(20 * time.Second)
									if HasAbnormalConnectByDip(ip, 5) {
										live_print(bug.Others)
										MessageToServer(bug.Type, bug, log)
									}
								}(bug.Type, bug, log)
							}
						}
					}
					if cached == true {
						fmt.Println("CheckPs cached Abnormal cmdline:", cmdline)
					}
				}
			}
			fmt.Println(result)
		}
	}
}

func checkIsMustCheckForRShell(user string) bool {
	if _, found := UidMap[user]; found == true {
		return true
	} else {
		return false
	}

}

func getDipCountDict(rawResult [][]string) map[string]int {
	httpAccessCount = 0
	DipMap := map[string]int{}
	for _, items := range rawResult {
		dip := items[3]
		dPort := items[7]
		count := 1
		if dPort == "80" || dPort == "443" {
			httpAccessCount += 1
		}
		if _, ok := DipMap[dip]; ok {
			DipMap[dip] += count
		} else {
			DipMap[dip] = count
		}
	}
	return DipMap
}

func filterResultForCheckDangerPS(dip string, sPort string) bool {
	if ListenPortMap[sPort] {
		debug_print("filter by ListenPortMap", sPort)
		return false
	}

	dipIsSelfIP := false
	if _, found := IPSMap[dip]; found == true {
		dipIsSelfIP = true
	}

	if dipIsSelfIP || isPrivateIP(net.ParseIP(dip)) { //目的ip是自己或者私网，就pass
		debug_print("filter 3", dip)
		return false
	}
	return true
}

func filterResultBySportDip(rawResult [][]string, dipMap map[string]int, isLsof_P bool) [][]string {
	newResult := make([][]string, 0)
	for _, items := range rawResult {
		SipSportDipDport := items[1]
		dip := items[3]
		sPort := items[8]
		dPort := items[7]
		if ListenPortMap[sPort] {
			debug_print("filter by ListenPortMap", sPort)
			continue
		}

		if isLsof_P && (dPort == "80" || dPort == "443") {
			debug_print("filter by isLsof_P, not check 80 443", dPort)
			continue
		}

		if httpAccessCount > HTTP_ACCESS_COUNT_LIMIT && (dPort == "80" || dPort == "443") {
			debug_print("filter by httpAccessCount", dPort)
			continue
		}

		if count, _ := dipMap[dip]; count > 5 {
			debug_print("filter 0", dip, count)
			continue
		}

		if len(dip) < 5 || strings.Contains(SipSportDipDport, "*:") {
			debug_print("filter 2", dip)
			continue
		}

		dipIsSelfIP := false
		if _, found := IPSMap[dip]; found == true {
			dipIsSelfIP = true
		}
		if dipIsSelfIP || isPrivateIP(net.ParseIP(dip)) { //目的ip是自己或者私网，就pass
			debug_print("filter 3", dip)
			continue
		}

		if CheckIsOwnAsset(dip, "0") == true { //是自己的资产就不检查了
			debug_print("filter 4", dip)
			continue
		}
		//live_print("filterResultByDip Append:",dip)
		newResult = append(newResult, items)
	}
	return newResult
}

func getFileChangeInRecentNdayCount(filePath string) int {
	count := 0
	if checkFileIsRecent3(filePath) {
		count += 1
	}
	return count
}

func checkLsof(preRawResult [][]string, preTotalResult string, mustCheck bool, cwd string) {
	if IsLsofCheckPeriodOpen && (mustCheck || HasAbnormalConnect()) {
		rawResult := make([][]string, 0)
		needCheckDipMap := map[string]bool{}
		checkedDipCache := map[string]bool{}
		totalResult := ""
		outCount := 0
		if len(preTotalResult) > 0 {
			rawResult, totalResult = preRawResult, preTotalResult
		} else {
			rawResult, totalResult = getCheckRshellInfoByLsof("", "")
		}
		debug_print("rawResult!!!!!!!!!!!!!!!!!!!!!!")
		//for _,item:=range(rawResult){
		//	fmt.Println(item)
		//}

		dipMap := getDipCountDict(rawResult)
		live_print("before len rawResult", len(rawResult))
		rawResult = filterResultBySportDip(rawResult, dipMap, true)

		totalResult = ""
		for _, item := range rawResult {
			info := item[4]
			totalResult += info + "\n"
			needCheckDipMap[item[5]] = true
		}
		live_print("after len rawResult", len(rawResult))
		debug_print(totalResult)

		//for _,item:=range(rawResult){
		//	fmt.Println(item)
		//}

		debug_print("rawResult finish !!!!!!!!!!!!!!!!!!!!!!")
		if len(totalResult) > 0 {
			for targetPid, _ := range needCheckDipMap {
				//targetDip:=rawItems[3]
				//if count, _ := dipMap[targetDip]; count > 4 {
				//	live_print("filter 0",targetDip)
				//	continue
				//}
				result, _ := getCheckRshellInfoByLsof(targetPid, totalResult)

				debug_print("after getCheckRshellInfoByLsof len rawResult", len(result))

				if len(result) > 0 {
					for _, items := range result {
						//fmt.Println("items",items)
						//exec:=items[0]
						SipSportDipDport := items[1]
						sip := items[2]
						dip := items[3]
						lsofInfo := items[4]
						uidName := items[6]
						//fmt.Println("dip 1:",dip)

						if isPrivateIP(net.ParseIP(sip)) == false && CheckIsOwnAsset(dip, "1") == true && CheckIsOwnAsset(sip, "1") == true { //sip不是私网，且sip dip都是隔离网段机器，不告警
							debug_print("Both sip and dip are isolate, not warning")
							continue
						}

						dangerUID := false
						if _, found := UidMap[uidName]; found == true {
							dangerUID = true
						}
						//fmt.Println("dip 2:",dip)
						pid, _ := strconv.Atoi(targetPid)
						checkResult, checkResultInfo, warningObviousLevel := checkRshellBySSinfoResult(sip, dip, SipSportDipDport, totalResult, dangerUID, lsofInfo, cwd, int32(pid))
						live_print("WarningObviousLevel:", warningObviousLevel)
						if checkResult {
							dipDport := strings.Split(SipSportDipDport, "->")[1]
							if checkIsHttpService(dipDport) == false {
								pid, _ := strconv.Atoi(targetPid)
								proName, pPid_, pCmd_, pCwd, pExe_, _ := getProcessInfo(int32(pid))
								if strings.Contains(pExe_, "hidsgo") {
									continue
								}

								log := SYSCALL{}
								log.Uid = uidName
								log.Pid = targetPid
								log.Exe = pExe_
								log.PPid = strconv.Itoa(int(pPid_))
								log.Euid = ""
								log.Gid = ""
								log.Egid = ""
								log.A0 = proName
								log.Argc = ""
								log.Auid = ""
								log.Cwd = pCwd
								log.Comm = pCmd_
								bug := initBugDetail("REVERSE_SHELL")
								bug.Content = checkResultInfo
								live_print("warning: REVERSE_SHELL by checkLsof_P")
								bug.Chains = checkResultInfo
								bug.Others = ""
								bug.SipSportDipDport = SipSportDipDport

								bug.AnalyseTime = time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05")
								bug.Description = bugList[bug.Type]

								if checkedDipCache[dip] {
									debug_print("In checkedDipCache: PASS", dip)
									continue
								} else {
									checkedDipCache[dip] = true
								}

								//这块可能要分三类，1是文件上传 2文件本身有问题。文件上传适用于3天内，文件本身有问题也分两种 1 直接的命令执行如system eval 2 如im这类的，tp这类的
								//这里因为误报率问题，hold不住 文件本身的问题，只能去hold上传，直接的反弹还是实时检查去hold吧

								go func(logType string, bugDetail interface{}, auditLog interface{}) { //做二次检查之后，在决定是否告警
									live_print("HasAbnormalConnectByTarget", bug.SipSportDipDport)
									time.Sleep(20 * time.Second)
									if result := HasAbnormalConnectByTarget(bug.SipSportDipDport, 5); result {
										live_print("In HasAbnormalConnectByTarget")
										fileNameContentNodeList, recent3Count := getTop3FileContentByCWD(pCwd)
										if len(fileNameContentNodeList) > 0 {
											if (warningObviousLevel < 2 && recent3Count > 0) || warningObviousLevel > 1 {
												for _, item := range fileNameContentNodeList {
													result := "-----------------" + item.filePath + "----------------\n" + item.content
													bug.Others += result
													log.Exe += " || " + item.filename
													log.A0 += " || " + item.filename
												}
												fmt.Println(bug.Others)
												if _, found := lsof_PBUGCache.Get(log.Exe); found == false {
													lsof_PBUGCache.Set(log.Exe, true, 3*time.Hour)
													MessageToServer(bug.Type, bug, log)
												} else {
													live_print("Found BUG in lsof_PBUGCache")
												}
											}
										} else {
											live_print("Len fileNameContentNodeList = 0")
										}
									}
								}(bug.Type, bug, log)
								outCount += 1
								if outCount > 20 {
									return
								}
							}
						}
					}
				}
			}
		}
	} else {
		live_print("IsLsofCheckPeriodOpen:", IsLsofCheckPeriodOpen)
	}
}

func CheckLsof_P() {
	CheckLsofCheckPeriodOpen() //最开始检查一次能否开启CheckLsof_P
	if TEST_LSOF_P == false {
		time.Sleep(10 * time.Minute)
	} else {
		time.Sleep(10 * time.Second)
	}

	for {
		if TEST_LSOF_P == false {
			time.Sleep(10 * time.Minute)
		} else {
			time.Sleep(10 * time.Second)
		}
		CheckLsofCheckPeriodOpen() //以后周期性检查，可以重开
		if HasCheckedLsofInPeriod == false {
			rawResult := make([][]string, 0)
			live_print("Start CheckLsof_P!!!!!!!!!!!!!!!!!!!!!")

			checkLsof(rawResult, "", false, "")
		} else {
			live_print("Not Start CheckLsof_P!!!!!!!!!!!!!!!!!!!!!")
		}

		HasCheckedLsofInPeriod = false
	}
}

type fileNameContentNode struct {
	filename string
	content  string
	filePath string
}

func getTop3FileContentByCWD(cwd string) ([]fileNameContentNode, int) {
	fileNameContentNodeList := make([]fileNameContentNode, 0, 4)
	fmt.Println("CWD:", cwd)
	fileList, recent3Count := getFileListByCwd(cwd)
	if len(fileList) > 0 {
		for _, item := range fileList {
			content := ""
			filePath := cwd + "/" + item
			fi, err := os.Stat(filePath)
			if err != nil {
				continue
			}
			fmt.Println("filePath:", filePath)
			size := fi.Size()
			if size > 5485760 {
				content = "Big file can not read."
			} else {
				if strings.HasSuffix(item, "jar") || strings.ContainsAny(item, ".") == false {
					content = "Is binary file"
				} else {
					content, _ = readFile(filePath)
				}
				if len(content) > 2000 {
					content = content[:2000]
				}
			}
			fmt.Println("content:", content)
			fileNameContentNodeList = append(fileNameContentNodeList, fileNameContentNode{filename: item, content: content, filePath: filePath})
		}
	}
	return fileNameContentNodeList, recent3Count
}

func checkIsHttpService(target string) bool {
	dport := strings.Split(target, ":")[1]
	prefix := ""
	if dport == "443" {
		prefix = "https://"
	} else if dport == "80" {
		prefix = "http://"
	} else {
		prefix = "http://"
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(prefix + target)
	if err != nil {
		fmt.Println("checkIsHttpService Send Request Error: ", target, err)
		//if strings.Contains(err.Error(),"EOF"){
		//	return true
		//}else if strings.Contains(err.Error(),"tls"){
		//	return true
		//}
		return false
	}
	defer resp.Body.Close()
	//fmt.Println(resp.Proto)
	if strings.Contains(resp.Proto, "HTTP/") {
		return true
	} else {
		return false
	}

	return false

}
