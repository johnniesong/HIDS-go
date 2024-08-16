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
	Type         string // 漏洞名
	Pids         string // 记录pid追踪记录
	Chains       string // 记录当前进程的所有父进程链
	Description  string
	AnalyseTime  string // 分析结束的时间
	Content      string
	Others       string // 记录一些debug的信息
	SSCheckPid   string
	SSCheckSPort string
	SSCheckDPort string
}

func initBugDetail(Type string) BugDetail {
	var Bug BugDetail
	Bug.AnalyseTime = time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05")
	Bug.Type = Type
	Bug.Description = bugList[Bug.Type]

	return Bug
}

func checkProcess(pid int32, pPid int32, pCmd string, pExe string, bug *BugDetail, gas int) (bool, error) {
	//time.Sleep(time.Duration(rand.Intn(1000)) * time.Microsecond)
	gas -= 1
	if gas < 0 {
		fmt.Println("Error: no gas !!!!!")
		return false, nil
	}
	pidStr := fmt.Sprintf("s_%d", pid)

	// 应对进程结束导致无法获取进程信息ppid的情况，直接从auditd日志里取。递归的时候再从进程里取ppid
	proName, pPid_, pCmd_, _, pExe_, err := getProcessInfo(pid)

	if pPid == -1 { //没取到，或者死了
		pPid = pPid_
	}

	if pCmd == "" { //audit里没有，实时去的时候有，或者进程死掉
		pCmd = pCmd_
	}

	if pExe == "" { //audit里没有，实时去的时候有，或者进程死掉
		pExe = pExe_
	}

	// 还是没有取到 pPid 相关信息，认为是process相关信息获取失败
	if pPid <= 0 {
		fmt.Println("Error Process Info:", pid, proName, pPid, pCmd, err)
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

	// 先尝试从缓存中读取//只有是漏洞的进程id才会缓存进去
	if bugType, found := processCache.Get(pidStr); found {
		//if bugType.(string) != "" {
		bug.Chains, _ = getProcessChain(pid)
		bug.Type = bugType.(string)
		return true, nil
	}

	bug.Pids = fmt.Sprintf("%s => %d %s(%s)", bug.Pids, pid, proName, pCmd)
	fmt.Println("Process Check: ", pid, proName, "|||", pCmd, "|||", pPid, "|||", pExe, "|||", gas)

	//无论有没有缓存，都要检查是否为web容器
	if rceVulList[pproName] || rceVulList[proName] || strings.HasPrefix(pproName, "python") || strings.HasPrefix(pproName, "php-fpm") || strings.HasPrefix(proName, "python") || strings.HasPrefix(proName, "php-fpm") {
		if strings.Contains(pCmd, "/sh ") || strings.Contains(pCmd, "/bash ") {
			debug_print("!!in rce proname: ", proName, " pproName:", pproName, " pid:", strconv.Itoa(int(pid)), " cmd:", pCmd, " exe: ", pExe)

			//这里先针对菜刀做一个简陋版本，硬匹配
			if strings.Contains(pCmd, "cd \"") && strings.Contains(pCmd, ";echo [S];") {
				debug_print("warning: caidao")
				bug.Chains, _ = getProcessChain(pid)
				bug.Type = "POSSIBLE_RCE"
				bug.Others = "TYPE:caidao" + " proname:" + proName + " pproName:" + pproName
				return true, nil
			}
		}

	}

	needCheckRShell := false
	// 检查是否为反弹shell
	if procMaps := pExe; strings.Contains(procMaps, "/bin/bash") || strings.Contains(procMaps, "/bin/perl") || strings.Contains(procMaps, "/bin/ncat") {
		needCheckRShell = true
	} else if procMaps, _ := readProcMaps(pid); strings.Contains(procMaps, "/bin/bash") || strings.Contains(procMaps, "/bin/perl") || strings.Contains(procMaps, "/bin/ncat") {
		needCheckRShell = true
	} else {
		debug_print(strconv.Itoa(int(pid)), " not in Rshell checklist:", procMaps)
	}
	if needCheckRShell {
		hash := ""
		if len(proName) > 0 {
			hash = proName + "|" + pCmd
		} else {
			hash = pExe + "|" + pCmd
		}
		_, found := ssCheckCache.Get(hash)
		if found == false {
			if result, ssInfos := checkProcessListenPort_V2(pid); result {
				bug.SSCheckPid = strconv.Itoa(int(pid))
				bug.Chains, _ = getProcessChain(pid)
				bug.Type = "REVERSE_SHELL"
				bug.Others = fmt.Sprintf("[Fds]: \n%s", ssInfos)
				return true, nil
			} else {
				debug_print(strconv.Itoa(int(pid)), " no socket info:", ssInfos)
			}
			if len(pCmd) > 60 {
				ssCheckCache.Set(hash, true, 3*60*time.Minute)
				debug_print("Add to SScache 60:", hash)
			} else if len(pCmd) > 40 {
				ssCheckCache.Set(hash, true, 3*40*time.Minute)
				debug_print("Add to SScache 40:", hash)
			} else if len(pCmd) > 20 {
				ssCheckCache.Set(hash, true, 3*30*time.Minute)
				debug_print("Add to SScache 30:", hash)
			} else if len(pCmd) > 10 {
				ssCheckCache.Set(hash, true, 3*20*time.Minute)
				debug_print("Add to SScache 20:", hash)
			}
		} else {
			debug_print("found in ssCache:", hash)
		}
	}

	if pPid != 1 && pPid != 2 { // 1 2 根进程，没意义，不用检查
		// 没检测到漏洞的process加个缓存，防止重复检查
		// 但是会存在一个问题，rce和reverse_shell的时候必须要检查父进程，如果加了缓存就会存在漏报的问题
		// 所以最后结论是：不能给没检测出来的进程加缓存
		//processCache.Set(pidStr, "", CacheUntargetProcessTime * time.Second)、、
		return checkProcess(pPid, -1, "", "", bug, gas)
	}
	return false, nil
}

func checkCommand(log SYSCALL, bug *BugDetail) {
	pid, _ := strconv.Atoi(log.Pid)
	pPid, _ := strconv.Atoi(log.PPid)

	// 递检查进程
	checkProcess(int32(pid), int32(pPid), getCmd(log), log.Exe, bug, GAS)
}
