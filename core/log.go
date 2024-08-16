package core

import (
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"strings"
	"time"
)

var json = jsoniter.ConfigFastest

type SYSCALL struct {
	Uid         string `json:"uid"`
	Gid         string `json:"gid"`
	Result      string `json:"res"`
	Success     string `json:"success"`
	A0          string `json:"a0"`
	A1          string `json:"a1"`
	A2          string `json:"a2"`
	A3          string `json:"a3"`
	A4          string `json:"a4"`
	A5          string `json:"a5"`
	A6          string `json:"a6"`
	A7          string `json:"a7"`
	Argc        string `json:"argc"`
	Auid        string `json:"auid"`
	Comm        string `json:"comm"`
	Cwd         string `json:"cwd"`
	Egid        string `json:"egid"`
	Euid        string `json:"euid"`
	Exe         string `json:"exe"`
	Exit        string `json:"exit"`
	Fsgid       string `json:"fsgid"`
	Fsuid       string `json:"fsuid"`
	Key         string `json:"key"`
	Mode        string `json:"mode"`
	ProcessName string `json:"name"`
	Nametype    string `json:"nametype"`
	Ogid        string `json:"ogid"`
	Ouid        string `json:"ouid"`
	Pid         string `json:"pid"`
	PPid        string `json:"ppid"`
	Sgid        string `json:"sgid"`
	Suid        string `json:"suid"`
	Syscall     string `json:"syscall"`
	Tty         string `json:"tty"`
	ProcessTime string `json:"timestamp"`
}

func getCmd(log SYSCALL) string {
	cmd := log.A0

	if !strings.HasPrefix(log.A1, "0x") {
		cmd += " " + log.A1
	}
	if !strings.HasPrefix(log.A2, "0x") {
		cmd += " " + log.A2
	}
	if !strings.HasPrefix(log.A3, "0x") {
		cmd += " " + log.A3
	}
	if !strings.HasPrefix(log.A4, "0x") {
		cmd += " " + log.A4
	}
	if !strings.HasPrefix(log.A5, "0x") {
		cmd += " " + log.A5
	}
	if !strings.HasPrefix(log.A6, "0x") {
		cmd += " " + log.A6
	}
	if !strings.HasPrefix(log.A7, "0x") {
		cmd += " " + log.A7
	}

	return cmd
}

func Entry(data []byte, hids_pid string) BugDetail {
	var log SYSCALL
	var bug BugDetail

	// 解析json格式的数据到struct
	var err = json.Unmarshal(data, &log)
	if err != nil {
		fmt.Println("Parse Json Error: ", err, "\nContent: ", string(data))
		return bug
	}

	if log.Pid == hids_pid || log.PPid == hids_pid || log.Pid == "" || log.PPid == "" {
		//debug_print("hids_pid :"+hids_pid+" pass")
		return bug
	}

	debug_print("Entry -> ", log.Pid, log.PPid, log.Exe, " ||| ", getCmd(log), "--")
	InsertToEntryMap(log.Exe)
	// 目前只检测execve
	// 根据log.Cwd 和 log.Exe 去除现有的监控软件目录
	if log.Syscall != "execve" || EntryWhiteListCache.Get(log.Exe) || PreExeCwdWhitelist[log.Exe] || PreExeCwdWhitelist[log.Cwd] {
		//debug_print("PASS -> ", log.Pid, log.PPid, log.Exe, " ||| ", getCmd(log), "--")
		return bug
	}

	// 先根据ppid的缓存检查下，如果ppid有缓存(且没有命中漏洞)，那么直接设置bug.Type进行下一步，不再重新检查了
	// @question: 非常严重的问题，如果web容器被频繁访问，刚好又存在命令执行，如果加了缓存就会丢数据。(被缓存为不存在漏洞)
	// @answer: 正常的访问是不会触发cache的，因为正常访问不会有命令执行
	isCached := false
	if bugType, found := prepPidCache.Get(log.PPid); found && bugType.(string) == "" {
		// 只对没有检查出漏洞的设置cache
		debug_print("pid In Cache: " + log.PPid)
		isCached = true
	} else {
		checkCommand(log, &bug)
	}

	if bug.Type != "" {
		bug.AnalyseTime = time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05")
		bug.Description = bugList[bug.Type]
		if bug.Type == "REVERSE_SHELL" {
			go func(logType string, bugDetail interface{}, auditLog interface{}) { //做二次检查之后，在决定是否告警
				time.Sleep(2 * time.Second)
				SSByPid(bug.SSCheckPid)
				MessageToServer(bug.Type, bug, log)
			}(bug.Type, bug, log)
		} else {
			MessageToServer(bug.Type, bug, log)
		}
	}

	// 无论结果是什么，只要不是从缓存里读的，都把结果设置下缓存
	if !isCached {
		//debug_print(" Cache: pid: "+log.PPid)
		prepPidCache.Set(log.PPid, bug.Type, 1*time.Minute)
	}

	return bug
}
