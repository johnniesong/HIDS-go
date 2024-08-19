package core

import (
	"fmt"
	_ "github.com/patrickmn/go-cache"
	"strconv"
	"strings"
	"time"
	//"math/rand"
)

type BugDetail struct {
	Type             string // 漏洞名
	Pids             string // 记录pid追踪记录
	Chains           string // 记录当前进程的所有父进程链
	Description      string
	AnalyseTime      string // 分析结束的时间
	Content          string
	Others           string // 记录一些debug的信息
	SSCheckPid       int32
	SipSportDipDport string
}

func initBugDetail(Type string) BugDetail {
	var Bug BugDetail
	Bug.AnalyseTime = time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05")
	Bug.Type = Type
	Bug.Description = bugList[Bug.Type]

	return Bug
}

func checkProcess(pid int32, pPid int32, pCmd string, pCwd string, pExe string, bug *BugDetail, gas int, uid string, mustCheck bool, cHash string) (bool, error) {
	//time.Sleep(time.Duration(rand.Intn(1000)) * time.Microsecond)
	gas -= 1
	if gas <= 0 {
		debug_print("Error: no gas !!!!!")
		debug_print("Process Check: ", pid, pPid, "|||", pCmd, "|||", pExe, "|||", gas, uid, UidMap[uid])
		return false, nil
	}
	pidStr := fmt.Sprintf("s_%d", pid)

	// 应对进程结束导致无法获取进程信息ppid的情况，直接从auditd日志里取。递归的时候再从进程里取ppid //通过auditd也完全可以，现在是通过命令找进程去完成的，ppid，pcmd都坑能没有是空，
	proName, pPid_, pCmd_, pCwd_, pExe_, err := getProcessInfo(pid)

	if pPid == -1 { //没取到，或者死了
		pPid = pPid_
	}

	if pCmd == "" { //audit里没有，实时去的时候有，或者进程死掉
		pCmd = pCmd_
	}

	if pExe == "" { //audit里没有，实时去的时候有，或者进程死掉
		pExe = pExe_
	}

	if pCwd == "" { //audit里没有，实时去的时候有，或者进程死掉
		pCwd = pCwd_
	}

	// 还是没有取到 pPid 相关信息，认为是process相关信息获取失败//失败原因
	if pPid <= 0 {
		if PRINT_DEBUG {
			fmt.Println("Error Process Info:", pid, proName, pPid, pCmd, err)
		}
		return false, err
	}

	// 不检查白名单内的进程
	if ProcessNameWhiteList[proName] {
		return false, nil
	}

	// 检查父进程是否在白名单内
	pproName, _, _, _, _, err := getProcessInfo(pPid)
	if err == nil {
		if ProcessNameWhiteList[pproName] {
			return false, nil
		}
	}

	// 先尝试从缓存中读取//这个cache拿到了，代表什么，只有是漏洞的进程id才会缓存进去
	if bugType, found := processCache.Get(pidStr); found {
		//if bugType.(string) != "" {
		bug.Chains, _ = getProcessChain(pid)
		bug.Type = bugType.(string)
		return true, nil
		//} else {
		//	//fmt.Println("%d cached: no bugs", pid)
		//	return false, nil
		//}
	}

	bug.Pids = fmt.Sprintf("%s => %d %s(%s)", bug.Pids, pid, proName, pCmd)
	debug_print("Process Check: ", pid, proName, "|||", pCmd, "|||", pPid, "|||", pExe, "|||", gas, uid, UidMap[uid])

	//无论有没有缓存，都要检查是否为web容器
	if rceVulList[pproName] || rceVulList[proName] || strings.HasPrefix(pproName, "python") || strings.HasPrefix(pproName, "php-fpm") || strings.HasPrefix(proName, "python") || strings.HasPrefix(proName, "java") {
		if strings.Contains(pCmd, "/sh") || strings.Contains(pCmd, "/bash") {
			live_print("!!in rce proname: ", proName, " pproName:", pproName, " pid:", strconv.Itoa(int(pid)), " cmd:", pCmd, " exe: ", pExe)
			//这里先针对菜刀做一个简陋版本，硬匹配
			if strings.Contains(pCmd, "cd \"") && strings.Contains(pCmd, ";echo [S];") {
				live_print("warning: caidao")
				bug.Chains, _ = getProcessChain(pid)
				bug.Type = "POSSIBLE_RCE"
				bug.Others = "TYPE:caidao" + " proname:" + proName + " pproName:" + pproName
				return true, nil
			} else if strings.Contains(pCmd, "python") && strings.Contains(pCmd, "import pty") && strings.Contains(pCmd, "pty.spawn(") {
				live_print("warning: caidao2")
				bug.Chains, _ = getProcessChain(pid)
				bug.Type = "POSSIBLE_RCE"
				bug.Others = "TYPE:caidao2" + " proname:" + proName + " pproName:" + pproName
				return true, nil
			}
		}

	}

	//
	dangerUID := false
	needCheck := false
	if _, found := UidMap[uid]; found == true {
		dangerUID = true
		debug_print("pCmd:", pCmd)
		needCheck = checkCmdline(uid, pCmd)

		isDownloadAndEXEC := checkDE(pCmd)
		if isDownloadAndEXEC {
			live_print("warning: checkDE by danger uid")
			bug.Chains, _ = getProcessChain(pid)
			bug.Type = "POSSIBLE_RCE"
			bug.Others = "TYPE:checkDE by danger uid:" + uid + " cmdline:" + pCmd + " pproName:" + pproName
			//这里不返回而是继续检查，如果RSHELL命中，则用RSHELL的告警。否则，用这条告警。
		}
	}

	if needCheck == true {
		live_print("needCheck pCmd:", pCmd)
		fmt.Println("RceCheckMap:")
		rceInfo := ""
		for k, v := range RceCheckMap {
			fmt.Println(k, strconv.Itoa(v))
			rceInfo += k + ":" + strconv.Itoa(v) + ","
		}
		rceCount := len(RceCheckMap)
		if rceCount >= 4 {
			RceCheckMap = map[string]int{}
			live_print("warning: RCE by danger uid")
			bug.Chains, _ = getProcessChain(pid)
			bug.Type = "POSSIBLE_RCE"
			bug.Others = "TYPE:RCE by danger uid:" + uid + " rceInfo:" + rceInfo + " pproName:" + pproName
			return true, nil
		}
	}

	LsofCheckOpenLock.RLock()
	lsofIsOpen := IsLsofCheckOpen
	LsofCheckOpenLock.RUnlock()
	hash := ""
	if lsofIsOpen {
		needCheckRShell := false
		// 检查是否为反弹shell
		if mustCheck {
			needCheckRShell = true //|| strings.HasPrefix(procMaps, "php-fpm")
		} else if procMaps := pExe; strings.Contains(procMaps, "/bin/bash") || strings.Contains(procMaps, "/bin/sh") || strings.Contains(procMaps, "/bin/perl") || strings.Contains(procMaps, "/bin/ncat") || strings.Contains(procMaps, "/socat") {
			needCheckRShell = true
		} else {
			debug_print(strconv.Itoa(int(pid)), " not in Rshell checklist:")
		}
		realpCmd := strings.TrimSpace(pCmd)
		if mustCheck != true && len(realpCmd) > 200 && (strings.Contains(realpCmd, " curl ") || strings.Contains(realpCmd, " wget ")) {
			needCheckRShell = false
		}
		//else if procMaps,_ := readProcMaps(pid); strings.Contains(procMaps, "/bin/bash") || strings.Contains(procMaps, "/bin/perl") || strings.Contains(procMaps, "/bin/ncat"){
		//	needCheckRShell=true
		//}
		if needCheckRShell {

			tmpPCmd := RegA.ReplaceAll([]byte(pCmd), []byte("REPL_A"))
			tmpPCmd2 := string(tmpPCmd[:])

			tmpPCmd = RegB.ReplaceAll([]byte(tmpPCmd2), []byte("0"))
			tmpPCmd3 := string(tmpPCmd[:])

			tmpPCmd = RegC.ReplaceAll([]byte(tmpPCmd3), []byte("a"))
			tmpPCmd4 := string(tmpPCmd[:])

			if len(proName) > 0 {
				hash = proName + "|" + tmpPCmd4
			} else {
				hash = pExe + "|" + tmpPCmd4
			}
			if mustCheck {
				hash = strings.TrimSpace(hash) + "|---|" + cHash
			} else {
				hash = strings.TrimSpace(hash) + "|---|"
			}
			debug_print("HASH:", pCmd, "<-->", hash)
			_, found := ssCheckCache.Get(hash)
			//if found==false && len(realpCmd)>10 && len(realpCmd)<70{
			//	ssCheckCacheMap:=ssCheckCache.Items()gggg
			//	for k:=range ssCheckCacheMap{
			//		//fmt.Println("ssCheckCacheMap:",k,"|||||",hash)
			//		if  absInt(len(k)-len(hash))<10 {
			//			if IsSimilarByLevenshtein(k,hash,0.93){
			//				found=true
			//				debug_print("Similar in ssCache:",k,"||||",hash)
			//				break
			//			}
			//		}
			//	}
			//}

			if found == false {
				time.Sleep(3 * time.Second)
				if HasAbnormalConnect() { //检查之前用netlink预先检查一遍,是否有异常链接

					//isDownloadAndEXEC:= checkDE(pCmd)
					//if isDownloadAndEXEC{
					//	live_print("warning: checkDE by danger uid")
					//	bug.Chains, _ = getProcessChain(pid)
					//	bug.Type = "POSSIBLE_RCE"
					//	bug.Others = "TYPE:checkDE by danger uid:" + uid + " cmdline:"+ pCmd+" pproName:"+pproName
					//	//这里不返回而是继续检查，如果RSHELL命中，则用RSHELL的告警。否则，用这条告警。
					//}

					live_print("Lsof Process Check: ", pid, proName, "|||", pCmd, "|||pPid :", pPid, "|||", pExe, "|||", gas, uid, UidMap[uid], " mustcheck:", mustCheck)
					if result, ssInfos, SipSportDipDport := checkProcessListenPort_V2_lsof_V2(pid, dangerUID, pCwd); result {
						bug.SSCheckPid = pid
						bug.SipSportDipDport = SipSportDipDport
						bug.Chains, _ = getProcessChain(pid)
						bug.Type = "REVERSE_SHELL"
						bug.Others = fmt.Sprintf("[Fds]: \n%s", ssInfos)
						return true, nil
					} else {
						debug_print(strconv.Itoa(int(pid)), " checkProcessListenPort_V2_lsof_V2 check failed")
					}
					//if result, ssInfos,SipSportDipDport := checkProcessListenPort_V2_lsof_V2(pid+1,dangerUID); result {
					//	bug.SSCheckPid=pid+1
					//	bug.SipSportDipDport=SipSportDipDport
					//	bug.Chains, _ = getProcessChain(pid)
					//	bug.Type = "REVERSE_SHELL"
					//	bug.Others = fmt.Sprintf("[Fds]: \n%s", ssInfos)
					//	return true, nil
					//}else {
					//	debug_print(strconv.Itoa(int(pid))," no socket info:",ssInfos)
					//}
				}

				if len(realpCmd) > 60 {
					ssCheckCache.Set(hash, true, 10*24*time.Hour)
					debug_print("Add to SScache 10*24:", hash)
				} else if len(realpCmd) > 40 {
					ssCheckCache.Set(hash, true, 8*24*time.Hour)
					debug_print("Add to SScache 8*24:", hash)
				} else if len(realpCmd) > 20 {
					ssCheckCache.Set(hash, true, 6*24*time.Hour)
					debug_print("Add to SScache 6*24:", hash)
				} else if len(realpCmd) > 10 {
					ssCheckCache.Set(hash, true, 2*24*time.Hour)
					debug_print("Add to SScache 2*24:", hash)
				} else {
					debug_print("NOT Add to SScache 20:", hash)
				}
			} else {
				debug_print("found in ssCache:", hash)
			}
		}
	}

	if pPid > 5 { //1 2 根进程，没意义，不用检查
		// 没检测到漏洞的process加个缓存，防止重复检查
		// 但是会存在一个问题，rce和reverse_shell的时候必须要检查父进程，如果加了缓存就会存在漏报的问题
		// 所以最后结论是：不能给没检测出来的进程加缓存
		//processCache.Set(pidStr, "", CacheUntargetProcessTime * time.Second)、、
		mustCheck = checkIsMustCheckForRShell(uid)

		return checkProcess(pPid, -1, "", "", "", bug, gas, uid, mustCheck, hash)
	}

	return false, nil
}

func checkCommand(log SYSCALL, bug *BugDetail) {
	pid, _ := strconv.Atoi(log.Pid)
	pPid, _ := strconv.Atoi(log.PPid)
	uid := log.Uid

	// 递检查进程
	checkProcess(int32(pid), int32(pPid), getCmd(log), log.Cwd, log.Exe, bug, GAS, uid, false, "")

}
