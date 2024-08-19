package main

import (
	"HIDS-go/core"
	"encoding/binary"
	"fmt"
	"github.com/pkg/profile"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	ConstHeader         = "l\\"
	ConstHeaderLength   = 2
	ConstSaveDataLength = 2
	ConstPreLength      = ConstHeaderLength + ConstSaveDataLength
)

// 解包
func unpack(buffer []byte, readerChannel chan []byte) []byte {
	length := len(buffer)

	var i int
	for i = 0; i < length; i = i + 1 {
		// 如果长度太短，暂不处理（积累更多数据）
		if length < i+ConstPreLength {
			break
		}

		if string(buffer[i:i+ConstHeaderLength]) == ConstHeader {

			messageLength := int(binary.LittleEndian.Uint16(buffer[i+ConstHeaderLength : i+ConstPreLength]))
			jsonLength := messageLength - ConstPreLength

			//fmt.Println("xx:", length, i, messageLength)

			// 不足一条数据时，暂不处理
			if length < i+messageLength {
				break
			}

			// 传送消息体出去
			readerChannel <- buffer[i+ConstPreLength : i+ConstPreLength+jsonLength]

			i += messageLength - 1
		}
	}
	// 如果刚好处理完，就返回空，否则返回没有处理完的内容,
	if i == length {
		return make([]byte, 0)
	} else {
		//fmt.Println("un handles:", buffer[i:], string(buffer[i:]))
		return buffer[i:]
	}
}

// 从管道中读取数据
func reader(readerChannel chan []byte) {
	for {
		select {
		case data := <-readerChannel:
			//fmt.Println("Client got:", len(data), string(data))
			core.Entry(data[0:len(data)-1], hids_pid)
		}
	}
}

// 连接logmon给予的unix套接字，获取auditd数据
func connect_logmon() (net.Conn, error) {
	for {
		c, err := net.Dial("unix", "@audit_socketout")
		if err != nil {
			if core.IS_DEBUG == true {
				time.Sleep(1 * time.Second)
			} else {
				time.Sleep(100 * time.Second)
			}
			fmt.Println("No socket data, try connect")
		} else {
			return c, err
		}

	}

}

var hids_pid = strconv.Itoa(os.Getpid())

func main() {
	fmt.Println(core.VERSION)
	if core.TEST_CPU_COST == true {
		defer profile.Start(profile.ProfilePath(".")).Stop()
	}
	if core.TEST_MEM_COST == true {
		defer profile.Start(profile.MemProfile, profile.ProfilePath(".")).Stop()
	}

	receive_size := 1024 * 1
	readerChannelSize := 1024
	core.AbnormalCmdline = map[string]bool{}
	core.CheckedProcessMap = map[string]bool{}
	core.UidMap, core.FullUidMap = core.CacheUidMapByPasswd()
	core.UidMap = core.CacheUidMapByPS(core.UidMap)
	core.ListenPortMap = core.CacheListenPort()
	core.EntryMap_tmp = map[string]int{}
	core.IsOwnAssetAndNotIsolateMap = map[string]bool{}
	core.RceCheckMap = map[string]int{}
	//core.DipMap=map[string]int{}
	core.EntryWhiteListCache = core.RWCache{&sync.RWMutex{}, map[string]bool{}}
	//在头一小时预制一些cache项
	core.EntryWhiteListCache.Set("/bin/date", true)
	core.EntryWhiteListCache.Set("/usr/bin/wc", true)
	core.EntryWhiteListCache.Set("/bin/ps", true)
	core.EntryWhiteListCache.Set("/usr/bin/cut", true)
	core.EntryWhiteListCache.Set("/usr/bin/md5sum", true)
	core.EntryWhiteListCache.Set("/usr/bin/grep", true)
	core.EntryWhiteListCache.Set("/usr/bin/wc", true)
	core.EntryWhiteListCache.Set("/usr/bin/ls", true)
	core.EntryWhiteListCache.Set("/usr/bin/gawk", true)
	core.EntryWhiteListCache.Set("/usr/bin/ls", true)
	core.EntryWhiteListCache.Set("/usr/sbin/ss", true)
	core.EntryWhiteListCache.Set("/usr/sbin/lsof", true)
	// 存活性检查
	//runtime.GOMAXPROCS(3) // 最多使用2个核
	go core.AliveCheck()                     //存活检查，打点回传
	go core.CPUCheck()                       //CPU消耗检查，打点回传
	go core.CleanLog()                       //清理日志
	go core.CheckResourceAndCloseLsofCheck() //检查是否能够开启lsof检查，性能消耗问题，大约5%的机器开不了
	go core.CleanRceCheck()                  //清理RCE检查的cache
	go core.CheckPs()                        //通过ps命令检查进程启动命令是否安全
	go core.CheckDangerPS()                  //通过ps命令检查进程是否安全
	go core.CheckLsof_P()                    //周期性对全部异常外连进行检查

	go core.GenEntryMap() //周期性加白系统中高频率应用
	//声明一个临时缓冲区，用来存储被截断的数据
	tmpBuffer := make([]byte, receive_size/2)

	//声明一个管道用于接收解包的数据
	readerChannel := make(chan []byte, readerChannelSize)
	go reader(readerChannel)

START:
	c, _ := connect_logmon()

	for {
		buf := make([]byte, receive_size)
		n, err := c.Read(buf[:])
		if err != nil {
			fmt.Println(c.RemoteAddr().String(), " connection error: ", err)
			if core.IS_DEBUG == true {
				time.Sleep(1 * time.Second)
			} else {
				time.Sleep(100 * time.Second)
			}
			goto START
		}
		//拼上了,解决沾包
		tmpBuffer = unpack(append(tmpBuffer, buf[:n]...), readerChannel)

		//fmt.Println("Client got:", string(buf))
	}

	fmt.Println("Stop")

}
